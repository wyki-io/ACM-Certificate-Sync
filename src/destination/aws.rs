extern crate hyper;
extern crate rusoto_acm;
extern crate rusoto_core;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;

use hyper::client::{Client, HttpConnector};
use hyper::Uri;
use hyper_proxy::{Intercept, Proxy, ProxyConnector};
use hyper_tls::HttpsConnector;
use rusoto_acm::{
    Acm, AcmClient, CertificateSummary, ImportCertificateRequest, ImportCertificateResponse,
    ListCertificatesRequest, Tag,
};
use rusoto_core::request::HttpClient;
use rusoto_core::Region;
use rusoto_credential::ChainProvider;
use rusoto_elbv2::{AddListenerCertificatesInput, Certificate, Elb, ElbClient};

use serde::{Deserialize, Serialize};

use super::TLS;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct AwsRootConfig {
    aws: AcmAlbConfig,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
struct AcmAlbConfig {
    region: Region,
    credentials: Option<AcmAlbCredentials>,
    load_balancers: Option<Vec<String>>,
    dry_run: bool
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct AcmAlbCredentials {
    access_key: String,
    secret_key: String,
}

pub struct AcmAlbDestination {
    config: AcmAlbConfig,
    acm_client: AcmClient,
    elb_client: ElbClient,
    tag_managed_by: Tag,
}

#[async_trait]
impl super::Destination for AcmAlbDestination {
    fn name(&self) -> String {
        String::from("AWS ACM-ALB ")
    }

    async fn publish(&self, tls: TLS) -> anyhow::Result<()> {
        debug!("TLS domains : {:?}", tls);
        match self.send_to_acm(tls).await {
            Ok(cert_arn) => {
                debug!("ACM Cert ARN : {}", cert_arn);
                if let Some(ref listeners_arns) = self.config.load_balancers {
                    if let Err(e) = self.link_to_alb_listeners(cert_arn, listeners_arns).await {
                        error!("Unable to add certificate to ALB : {}", e);
                    };
                }
            }
            Err(e) => error!("Unable to send certificate to ACM : {}", e),
        }
        Ok(())
    }
}

impl AcmAlbDestination {
    pub fn new(config_str: &str) -> anyhow::Result<Self> {
        let config = parse_config(config_str)?;
        if let Some(creds) = config.credentials.as_ref() {
            debug!(
                "Using credentials from config, access_key : {}, secret_key : {}",
                creds.access_key, creds.secret_key
            );
            std::env::set_var("AWS_ACCESS_KEY_ID", creds.access_key.clone());
            std::env::set_var("AWS_SECRET_ACCESS_KEY", creds.secret_key.clone());
        }
        let credentials_provider = ChainProvider::new();
        let acm_client = AcmClient::new_with(
            Self::create_client()?,
            credentials_provider.clone(),
            config.region.clone(),
        );
        let elb_client = ElbClient::new_with(
            Self::create_client()?,
            credentials_provider,
            config.region.clone(),
        );
        let mut tag_managed_by = Tag::default();
        tag_managed_by.key = String::from("ManagedBy");
        tag_managed_by.value = Some(String::from("cert-sync"));
        Ok(AcmAlbDestination {
            config,
            acm_client,
            elb_client,
            tag_managed_by,
        })
    }

    fn create_client() -> anyhow::Result<HttpClient<ProxyConnector<HttpsConnector<HttpConnector>>>>
    {
        let http_proxy = std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .ok();
        let https_proxy = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .ok()
            .or_else(|| http_proxy.clone());
        let _no_proxy = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .ok();
        let mut proxies: Vec<Proxy> = Vec::new();
        if let Some(prox) = http_proxy {
            proxies.push(Proxy::new(
                Intercept::Http,
                prox.parse::<Uri>().expect("Malformed HTTP_PROXY env var"),
            ));
        }
        if let Some(prox) = https_proxy {
            proxies.push(Proxy::new(
                Intercept::Https,
                prox.parse::<Uri>().expect("Malformed HTTPS_PROXY env var"),
            ));
        }
        let https_connector = HttpsConnector::new();
        let proxy_connector = match !proxies.is_empty() {
            true => {
                let mut proxy_connector =
                    ProxyConnector::from_proxy(https_connector, proxies.pop().unwrap())?;
                while !proxies.is_empty() {
                    proxy_connector.add_proxy(proxies.pop().unwrap());
                }
                proxy_connector
            }
            false => ProxyConnector::new(https_connector)?,
        };
        let mut hyper_builder = Client::builder();

        // disabling due to connection closed issue
        hyper_builder.pool_max_idle_per_host(0);
        Ok(rusoto_core::HttpClient::from_builder(
            hyper_builder,
            proxy_connector,
        ))
    }

    async fn send_to_acm(&self, tls: TLS) -> anyhow::Result<String> {
        let domain = tls.domains.clone();
        let existing_cert = self.retrieve_existing_cert(&tls).await?;
        let new_cert = self.publish_certificate(tls, existing_cert).await?;
        match new_cert.certificate_arn {
            Some(arn) => Ok(arn),
            None => Err(anyhow!(format!(
                "Unable to create ACM certificate for cert with domains {}",
                domain.iter().fold(String::new(), |acc, x| acc + x)
            ))),
        }
    }

    async fn retrieve_existing_cert(
        &self,
        tls: &TLS,
    ) -> anyhow::Result<Option<CertificateSummary>> {
        let mut first_iter = true;
        let mut next_token = Some(String::from(""));
        while next_token.is_some() {
            let mut request = ListCertificatesRequest::default();
            if !first_iter && next_token.is_some() {
                request.next_token = next_token
            }
            let certs_res = self.acm_client.list_certificates(request).await?;
            if let Some(cert) = certs_res.certificate_summary_list.and_then(|certs| {
                certs
                    .into_iter()
                    .filter(|cert| cert.domain_name.is_some())
                    .find(|cert| tls.domains.contains(cert.domain_name.as_ref().unwrap()))
            }) {
                return Ok(Some(cert));
            }
            first_iter = false;
            next_token = certs_res.next_token;
        }
        Ok(None)
    }

    async fn publish_certificate(
        &self,
        new_cert: TLS,
        existing_cert: Option<CertificateSummary>,
    ) -> anyhow::Result<ImportCertificateResponse> {
        // Create the request
        let mut cert_req = ImportCertificateRequest::default();
        cert_req.certificate = Bytes::from(new_cert.cert);
        cert_req.private_key = Bytes::from(new_cert.key);
        if !new_cert.chain.is_empty() {
            cert_req.certificate_chain = Some(Bytes::from(new_cert.chain.join("\n")));
        }

        let main_domain = new_cert.domains.get(0).ok_or(
            anyhow!("Certificate does not contain any domain name, not uploading to ACM")
        )?;
        let mut tag_name = Tag::default();
        tag_name.key = String::from("Name");
        tag_name.value = Some(main_domain.clone());

        let mut tag_domain = Tag::default();
        tag_domain.key = String::from("Domain");
        tag_domain.value = Some(main_domain.clone());

        match existing_cert {
            Some(cert_summary) => {
                info!(
                    "Use existing certificate ARN {}",
                    cert_summary.certificate_arn.as_ref().unwrap()
                );
                cert_req.certificate_arn = cert_summary.certificate_arn;
            }
            None => {
                info!(
                    "Create new certificate for domain {}",
                    tag_domain.value.as_ref().unwrap()
                );
                cert_req.tags = Some(vec![tag_name, tag_domain, self.tag_managed_by.clone()]);
            }
        }

        // Send the cert
        if self.config.dry_run {
            Err(anyhow!("Dry-run enabled, not sending request to AWS"))
        } else {
            let cert_res = self.acm_client.import_certificate(cert_req).await?;
            Ok(cert_res)
        }
    }

    async fn link_to_alb_listeners(
        &self,
        cert_arn: String,
        listeners_arn: &[String],
    ) -> anyhow::Result<()> {
        let mut certificate = Certificate::default();
        certificate.certificate_arn = Some(cert_arn);
        let certificates = vec![certificate];
        if self.config.dry_run {
            return Ok(())
        }
        for listener_arn in listeners_arn {
            let mut request = AddListenerCertificatesInput::default();
            request.listener_arn = listener_arn.clone();
            request.certificates = certificates.clone();
            self.elb_client.add_listener_certificates(request).await?;
        }
        Ok(())
    }
}

/// Get config from file
fn parse_config(config_str: &str) -> anyhow::Result<AcmAlbConfig> {
    let config_from_file: AwsRootConfig = serde_yaml::from_str(config_str)?;
    let config = config_from_file.aws;

    debug!("Config : {:?}", config);
    // Set region from env if it exists
    // if let Some(env_region) = option_env!("AWS_REGION") {
    //     if let Ok(region) = Region::from_str(env_region) {
    //         config.region = region
    //     }
    // }

    // // Set credentials from env if it exists
    // set_credentials_from_env(&mut config)?;
    Ok(config)
}

// fn set_credentials_from_env(config: &mut AcmAlbConfig) -> anyhow::Result<()> {
//     if let Some(env_cred_access) = option_env!("AWS_CREDENTIALS_ACCESS_KEY") {
//         match config.credentials {
//             Some(&mut creds) => (),
//             None => config.credentials = AcmAlbCredentials {}
//         }
//         if let Some(env_cred_secret) = option_env!("AWS_CREDENTIALS_SECRET_KEY") {
//         }
//     }
//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::parse_config;
    use indoc::indoc;
    use rusoto_core::Region;

    #[test]
    fn parse_config_full_test() -> anyhow::Result<()> {
        let config_str = String::from(indoc!(
            "
            aws:
              region:
                - eu-west-3
              credentials:
                access_key: access_key
                secret_key: secret_key
              load_balancers:
                - a
                - b
            "
        ));
        let config = parse_config(&config_str)?;
        assert_eq!(config.region, Region::EuWest3);
        let credentials = config.credentials.unwrap();
        assert_eq!(credentials.access_key, "access_key");
        assert_eq!(credentials.secret_key, "secret_key");
        let load_balancers = config.load_balancers.unwrap();
        assert_eq!(load_balancers, vec!["a", "b"]);
        Ok(())
    }

    #[test]
    fn parse_config_minimal_test() -> anyhow::Result<()> {
        let config_str = String::from(indoc!(
            "
            aws:
              region:
                - eu-west-3
            "
        ));
        let config = parse_config(&config_str)?;
        assert_eq!(config.region, Region::EuWest3);
        assert_eq!(config.credentials, None);
        assert_eq!(config.load_balancers, None);
        Ok(())
    }
}
