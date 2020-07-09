// extern crate bytes;
extern crate rusoto_acm;
extern crate rusoto_core;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;

use rusoto_acm::{
    Acm, AcmClient, CertificateSummary, ImportCertificateRequest, ImportCertificateResponse,
    ListCertificatesRequest, Tag,
};
use rusoto_core::Region;
use rusoto_elbv2::{
    AddListenerCertificatesInput, Certificate, DescribeLoadBalancersInput, Elb, ElbClient,
};

use super::TLS;
// use std::io::Bytes;
pub struct AcmAlbProvider {
    region: Region,
}

#[async_trait]
impl super::Provider for AcmAlbProvider {
    fn name(&self) -> String {
        String::from("AWS")
    }

    async fn publish(&self, tls: TLS) -> anyhow::Result<()> {
        let cert_arn = self.send_to_acm(tls).await?;
        let listeners_arn = vec![String::from("listener_arn")];
        self.link_to_alb_listeners(cert_arn, listeners_arn).await?;
        todo!()
    }
}

impl AcmAlbProvider {
    pub fn new(region: Region) -> Self {
        AcmAlbProvider { region }
    }

    async fn send_to_acm(&self, tls: TLS) -> anyhow::Result<String> {
        let domain = tls.domain.clone();
        // May be a good idea to set it in self
        let client = AcmClient::new(self.region.clone());
        let existing_cert = self.retrieve_existing_cert(&tls).await?;
        let new_cert = self.publish_certificate(tls, existing_cert).await?;
        match new_cert.certificate_arn {
            Some(arn) => Ok(arn),
            None => Err(anyhow!(format!(
                "Unable to create ACM certificate for domain {}",
                domain
            ))),
        }
    }

    async fn retrieve_existing_cert(
        &self,
        tls: &TLS,
    ) -> anyhow::Result<Option<CertificateSummary>> {
        // May be a good idea to set it in self
        let client = AcmClient::new(self.region.clone());
        let mut first_iter = true;
        let mut next_token = Some(String::from(""));
        while next_token.is_some() {
            let mut request = ListCertificatesRequest::default();
            if !first_iter && next_token.is_some() {
                request.next_token = next_token
            }
            let certs_res = client.list_certificates(request).await?;
            if let Some(cert) = certs_res.certificate_summary_list.and_then(|certs| {
                certs
                    .into_iter()
                    .filter(|cert| cert.domain_name.is_some())
                    .find(|cert| tls.domain == *cert.domain_name.as_ref().unwrap())
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
        let mut domain_tag = Tag::default();
        domain_tag.key = String::from("Domain");
        domain_tag.value = Some(new_cert.domain);
        cert_req.tags = Some(vec![domain_tag]);
        if let Some(chain) = new_cert.chain {
            cert_req.certificate_chain = Some(Bytes::from(chain));
        }
        if let Some(arn) = existing_cert {
            cert_req.certificate_arn = arn.certificate_arn;
        }

        // Send the cert
        let client = AcmClient::new(self.region.clone());
        let cert_res = client.import_certificate(cert_req).await?;
        Ok(cert_res)
    }

    async fn link_to_alb_listeners(
        &self,
        cert_arn: String,
        listeners_arn: Vec<String>,
    ) -> anyhow::Result<()> {
        // May be a good idea to set it in self
        let client = ElbClient::new(self.region.clone());
        let mut certificate = Certificate::default();
        certificate.certificate_arn = Some(cert_arn);
        let certificates = vec![certificate];
        for listener_arn in listeners_arn {
            let mut request = AddListenerCertificatesInput::default();
            request.listener_arn = listener_arn;
            request.certificates = certificates.clone();
            client.add_listener_certificates(request).await?;
        }
        Ok(())
    }
}
