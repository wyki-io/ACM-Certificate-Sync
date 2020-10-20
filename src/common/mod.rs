use anyhow::anyhow;
use openssl::{nid::Nid, x509::X509};
use std::fmt;

/// Represents a TLS certificate packaged with its key and CA chain
///
/// # Fields
///
/// * `domains` - A list of domains related to this certificate
/// * `key` - The certificate private key
/// * `chain` - The certificate CA chain
/// * `domains` - Subject Alternatives Names
#[derive(Debug, Default)]
pub struct TLS {
    pub cert: String,
    pub key: String,
    pub chain: Vec<String>,
    pub domains: Vec<String>,
}

impl fmt::Display for TLS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.domains.join(", "))
    }
}

impl TLS {
    pub fn new(cert: String, key: String, chain: Vec<String>, domains: Vec<String>) -> Self {
        Self {
            cert,
            key,
            chain,
            domains,
        }
    }

    /// Considers the `cert` parameter to be a x509 PEM encoded certificate and
    /// resolves the related domains with openssl
    ///
    /// # Arguments
    ///
    /// * `cert` - The x509 PEM encoded certificate
    /// * `key` - The certificate key
    /// * `chain` - The certificate CA chain
    ///
    /// # Errors
    ///
    /// This method may return an error if it is unable to parse the cert as a
    /// x509 PEM certificate
    ///
    pub fn from_pem(cert: String, key: String, chain: Vec<String>) -> anyhow::Result<Self> {
        let x509 = X509::from_pem(cert.as_bytes())?;
        let mut domains: Vec<String> = Vec::new();
        // domains.push(x509.subject_name().entries_by_nid(Nid::COMMONNAME).next().unwrap().data().as_utf8());
        let common_name = TLS::get_common_name_from_x509(&x509)?;
        domains.push(common_name);
        match x509.subject_alt_names() {
            Some(alt_names) => {
                alt_names.iter().for_each(|name| {
                    if let Some(domain) = name.dnsname() {
                        domains.push(String::from(domain));
                    };
                });
            }
            _ => (),
        };
        Ok(TLS::new(cert, key, chain, domains))
    }

    /// Tries to extract certs from String into a Vec of cert
    pub fn into_vec(certs: String) -> anyhow::Result<Vec<String>> {
        let mut ret: Vec<String> = vec![];
        let mut loop_count = 0;
        let mut last = 0;
        for (index, _matched) in certs.match_indices("-----BEGIN CERTIFICATE-----") {
            if loop_count == 0 {
                loop_count += 1;
                last = index;
                continue;
            }
            ret.push(String::from(&certs[last..index]));
            last = index;
        }
        ret.push(String::from(&certs[last..]));
        Ok(ret)
    }

    /// Extract the COMMON_NAME entry from a x509 certificate
    fn get_common_name_from_x509(x509: &X509) -> anyhow::Result<String> {
        Ok(String::from(
            std::str::from_utf8(
                x509
                    .subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .ok_or(anyhow!(format!("Unable to get X509 entry COMMON_NAME")))?
                    .data()
                    .as_utf8()?
                    .as_bytes()
            )?
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::TLS;
    use indoc::indoc;

    #[test]
    fn parse_cert_pem() -> anyhow::Result<()> {
        let cert_pem = indoc!(
            "
            -----BEGIN CERTIFICATE-----
            MIIEszCCApsCFHeEcnKQaAxMFhiVcMiafYNXC0SmMA0GCSqGSIb3DQEBCwUAMBYx
            FDASBgNVBAMMC2V4YW1wbGUub3JnMB4XDTIwMTAxOTE4NTQwMFoXDTIxMTAxOTE4
            NTQwMFowFjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwggIiMA0GCSqGSIb3DQEBAQUA
            A4ICDwAwggIKAoICAQC9D3efsRwrqUz17mgXjDI3TsDcmAR5k+WnfnI5K4CZvHLx
            R8ueBJj5tTp3bxKv9BBAFY3JDyvyKvS1WEFq60+rAxOfz5t4NxeUlU8fF0nUFr1f
            mzwLg+0ivbrg6vKPGMMaOQmOrSAzNV+O5B2Zh2QrA2Bq/ApWPQL5OaTsfasCIn9/
            2/INuhQt7UcpnrD5I21Qcbn/koeZmuH26eOWMXVPbPqwgFRZZ4Z3fpoPPba78I42
            Xp95Xk/TLo8x2FS2dm7qXwDAjaI6txHejHCm0U/xL7kgbzYutXXyNXLfP8n32AUD
            f1oIxFYKydOaQ2nPtxF79J0UOU07ZdnWOX0kQ1hINf03O6Jy187LCbhqffAQuybN
            sKGFJFxJGdVxv1Rb+3WoGCsyY2h/V1949o1BZM5UuNJwKW6S0/v1beM7xEAMP3KE
            luBXmBybHnXcjQb2h/3PRdfvjyotpiB9y+72v8YKnADGmyyog/dvHtrkxrHxmabr
            iJiCPwyYTfO8Rj1DK0AOgAPqgA2wfl/YyfryyskHi7HPXsK3Tw09n6cOTSdJ9Hem
            G8jayw1dwZDRAhjEKN/kjVOZOPyhjv298RS4djxSO9J9R4Cl/D+LgOtjsNSVJsK1
            NiRCaPgnqx/RuLO02WaAIglp8rtZtYMDwFHrXjohNmTdcx+2T6UYXpgcz4KSWwID
            AQABMA0GCSqGSIb3DQEBCwUAA4ICAQB9GB56u6Wij85K/wpDqcKB83UIKc4Po91W
            At6x3BQMCHiCE8qQ/bn/PXE6VCk/74duKwIjVMKXHJuyNwhNMiDow9Tu9WbXDByY
            ZcWpCftoMiP5/SmPwIdk2xgsDcJruTV/iXCF25bpq8nvT7OmHKhmMa4IHnQ3wdzf
            CZSdkisHjbMMGG2z12kLoooDjcvrzGjDOPR1YCG5cwewyeOBpgeBHKHVNnU/W9kz
            KPMEcM0mXbYLTHlxYNjkaNKvQ3JUlR7a0aHWaLEcJVmJvLAu9vEXUnLcDhtMjK1K
            bGv9PAc+8ATS4IqRAw5bBOmMtJ9Zf6gjs/wAcQYfQrHIMVrgGMaUIcMyG/RbRav+
            7ZfHyi8c4SwcBV/1Q+YUM/BAtcZ6sTiNSz/iynIJETRan7/F/mUKrLAcFarUU+tC
            5C/7UR7gUWn6rMS4Y02cGsalsCg1Ycu1ykhTQyfNiXR6EZrIWvkc22u4giNROWzC
            Mu5UqTqGzcIq2bxbfNT1P6F7ly80Sl8Zp4Cymmj18OY720SAq0a5OXUqRU6Wtnru
            OmknsLLODqcycNZqFeItqStaoKVb45VEJkIW9911vZlTLM5suy85oqpWJsyJnCxh
            hyb9SOUlKyDo+dUtAFsOQTfjzYjYlhTd4kFTQXco9KybFwIBwQ1c324LOOR/xqPU
            qMO0ZEBWgA==
            -----END CERTIFICATE-----
            "
        );
        let tls = TLS::from_pem(
            String::from(cert_pem),
            String::from(""),
            vec![String::from("")],
        )?;
        assert_eq!(1, tls.domains.len());
        // Ugly cast, need workaround
        assert_eq!(true, tls.domains.contains(&"example.org".to_owned()));
        // Need to check with alt names
        Ok(())
    }

    #[test]
    fn split_multiple_certs_into_vec() {
        let first_cert = indoc!(
            "
            -----BEGIN CERTIFICATE-----
            MIIJVjCCCD6gAwIBAgIQAqGZwYqQRZwCAAAAAHPMbDANBgkqhkiG9w0BAQsFADBC
            ...
            MP6Cub32KGa5uYGUBvB4l8B88zFHTsAUBvmgr8LgFTQGgPP6gXKj2ySb
            -----END CERTIFICATE-----
            "
        );
        let second_cert = indoc!(
            "
            -----BEGIN CERTIFICATE-----
            MIIJVjCCCD6gAwIBAgIQAqGZwYqQRZwCAAAAAHPMbDANBgkqhkiG9w0BAQsFADBC
            ...
            MP6Cub32KGa5uYGUBvB4l8B88zFHTsAUBvmgr8LgFTQGgPP6gXKj2ySb
            -----END CERTIFICATE-----
            "
        );
        let mut concat_certs = String::from(first_cert);
        concat_certs.push_str(second_cert);
        let certs = TLS::into_vec(concat_certs).unwrap();
        assert_eq!(String::from(first_cert), *certs.get(0).unwrap());
        assert_eq!(String::from(second_cert), *certs.get(1).unwrap());
    }
}
