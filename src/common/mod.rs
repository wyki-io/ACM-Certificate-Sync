use openssl::x509::X509;

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
        let domains = match x509.subject_alt_names() {
            Some(alt_names) => {
                let mut domains = Vec::with_capacity(alt_names.len());
                alt_names.iter().for_each(|name| {
                    match name.dnsname() {
                        Some(domain) => domains.push(String::from(domain)),
                        _ => (),
                    };
                });
                domains
            }
            _ => vec![],
        };
        Ok(TLS::new(cert, key, chain, domains))
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
            MIIJVjCCCD6gAwIBAgIQAqGZwYqQRZwCAAAAAHPMbDANBgkqhkiG9w0BAQsFADBC
            MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMw
            EQYDVQQDEwpHVFMgQ0EgMU8xMB4XDTIwMDcxNTA4MjkxNloXDTIwMTAwNzA4Mjkx
            NlowZjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
            DU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFTATBgNVBAMMDCou
            Z29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOKBMK+yIazADk2I
            y94Zn9IlCu6RefcurqTfUeYwzuiHnvE/9EPQrWiNGF+XgwBKk3RSWuHKoiO/d5Cq
            s/tVh8+jggbtMIIG6TAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUH
            AwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQURe/AgC2QdGH87CXXiS8/i21XDuww
            HwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswaAYIKwYBBQUHAQEEXDBa
            MCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxbzFjb3JlMCsG
            CCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2cvZ3NyMi9HVFMxTzEuY3J0MIIEqAYD
            VR0RBIIEnzCCBJuCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lkLmNvbYIWKi5hcHBl
            bmdpbmUuZ29vZ2xlLmNvbYIJKi5iZG4uZGV2ghIqLmNsb3VkLmdvb2dsZS5jb22C
            GCouY3Jvd2Rzb3VyY2UuZ29vZ2xlLmNvbYIGKi5nLmNvgg4qLmdjcC5ndnQyLmNv
            bYIRKi5nY3BjZG4uZ3Z0MS5jb22CCiouZ2dwaHQuY26CDiouZ2tlY25hcHBzLmNu
            ghYqLmdvb2dsZS1hbmFseXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUu
            Y2yCDiouZ29vZ2xlLmNvLmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28u
            dWuCDyouZ29vZ2xlLmNvbS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5j
            b20uYnKCDyouZ29vZ2xlLmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2ds
            ZS5jb20udHKCDyouZ29vZ2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xl
            LmVzggsqLmdvb2dsZS5mcoILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdv
            b2dsZS5ubIILKi5nb29nbGUucGyCCyouZ29vZ2xlLnB0ghIqLmdvb2dsZWFkYXBp
            cy5jb22CDyouZ29vZ2xlYXBpcy5jboIRKi5nb29nbGVjbmFwcHMuY26CFCouZ29v
            Z2xlY29tbWVyY2UuY29tghEqLmdvb2dsZXZpZGVvLmNvbYIMKi5nc3RhdGljLmNu
            gg0qLmdzdGF0aWMuY29tghIqLmdzdGF0aWNjbmFwcHMuY26CCiouZ3Z0MS5jb22C
            CiouZ3Z0Mi5jb22CFCoubWV0cmljLmdzdGF0aWMuY29tggwqLnVyY2hpbi5jb22C
            ECoudXJsLmdvb2dsZS5jb22CEyoud2Vhci5na2VjbmFwcHMuY26CFioueW91dHVi
            ZS1ub2Nvb2tpZS5jb22CDSoueW91dHViZS5jb22CFioueW91dHViZWVkdWNhdGlv
            bi5jb22CESoueW91dHViZWtpZHMuY29tggcqLnl0LmJlggsqLnl0aW1nLmNvbYIa
            YW5kcm9pZC5jbGllbnRzLmdvb2dsZS5jb22CC2FuZHJvaWQuY29tghtkZXZlbG9w
            ZXIuYW5kcm9pZC5nb29nbGUuY26CHGRldmVsb3BlcnMuYW5kcm9pZC5nb29nbGUu
            Y26CBGcuY2+CCGdncGh0LmNuggxna2VjbmFwcHMuY26CBmdvby5nbIIUZ29vZ2xl
            LWFuYWx5dGljcy5jb22CCmdvb2dsZS5jb22CD2dvb2dsZWNuYXBwcy5jboISZ29v
            Z2xlY29tbWVyY2UuY29tghhzb3VyY2UuYW5kcm9pZC5nb29nbGUuY26CCnVyY2hp
            bi5jb22CCnd3dy5nb28uZ2yCCHlvdXR1LmJlggt5b3V0dWJlLmNvbYIUeW91dHVi
            ZWVkdWNhdGlvbi5jb22CD3lvdXR1YmVraWRzLmNvbYIFeXQuYmUwIQYDVR0gBBow
            GDAIBgZngQwBAgIwDAYKKwYBBAHWeQIFAzAzBgNVHR8ELDAqMCigJqAkhiJodHRw
            Oi8vY3JsLnBraS5nb29nL0dUUzFPMWNvcmUuY3JsMIIBBAYKKwYBBAHWeQIEAgSB
            9QSB8gDwAHcA5xLysDd+GmL7jskMYYTx6ns3y1YdESZb8+DzS/JBVG4AAAFzUc6h
            QwAABAMASDBGAiEAlsUu2NprTTur/KX90fdYN/3Rp+UuuZIa5UJ8wzqRUboCIQDg
            K2gL9j/Xc7KAwfEMNd4lvGuglCP4BXgZtA6XCKnb0gB1AAe3XBvlfWj/8bDGHSMV
            x7rmV3xXlLdq7rxhOhpp06IcAAABc1HOozgAAAQDAEYwRAIgQSSH2O7aHNWS3PVQ
            /R1rkkAH2R36HxDFIdIksoVeCPoCIFKHYcqxojmuVtn/hBJZ+BqAOc/Xjgu0YauK
            SWUZQxdDMA0GCSqGSIb3DQEBCwUAA4IBAQDLMhvkMISI0O+xmjDBkcobpzwMrQ5t
            tf4C/16RnKdUj5BqzrtCBi8FKFapfBTumMGpfaZAdrhzritSKutuUADbpOA8FXlE
            zYGskKhfTMDl1M85cCVkEKQIyb4ib2N8NkXmxrccYe5RATgMi3zMWGTN1XA5hRpp
            e5ofR/2e+rfYBy974/hpvZhJpKjiPXJyri0p/h0m5IgNJfJSYfWas95OgKKRXYIW
            7X9kq7xu+pmkrbGMVtF4eXgBrL72NEQc0fh0L5mAUxInaqjgoaABfNijS3V7MPlg
            MP6Cub32KGa5uYGUBvB4l8B88zFHTsAUBvmgr8LgFTQGgPP6gXKj2ySb
            -----END CERTIFICATE-----
            "
        );
        let tls = TLS::from_pem(
            String::from(cert_pem),
            String::from(""),
            vec![String::from("")],
        )?;
        assert_eq!(72, tls.domains.len());
        // Ugly cast, need workaround
        assert_eq!(true, tls.domains.contains(&"*.google.com".to_owned()));
        Ok(())
    }
}
