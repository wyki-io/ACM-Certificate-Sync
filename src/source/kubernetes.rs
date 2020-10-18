use super::Provider;
use super::TLS;

use anyhow::anyhow;
use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::{
    api::{Api, ListParams, WatchEvent},
    runtime::Informer,
    Client,
};
use std::str;
use std::collections::BTreeMap;
use std::convert::TryFrom;

pub struct SecretSource {
    informer: Informer<Secret>,
}

#[async_trait]
impl super::Source for SecretSource {
    fn name(&self) -> String {
        String::from("Kubernetes Secret Source")
    }

    async fn receive<'a, T: Provider + Send + Sync>(
        &'a self,
        destination: &'a T,
    ) -> anyhow::Result<()> {
        let mut secrets = self.informer.poll().await?.boxed();
        while let Some(secret) = secrets.try_next().await? {
            println!("Hello");
            if let Some(cert) = self.filter_certificate(secret)? {
                println!("There");
                info!("Will persist cert {}", cert);
                println!("General");
                destination.publish(cert).await?;
                println!("Kenobi");
            }
        }
        Ok(())
    }
}

impl SecretSource {
    pub async fn new(_config: &str) -> anyhow::Result<Self> {
        let client = Client::try_default().await?;
        let secrets: Api<Secret> = Api::all(client);
        let lp = ListParams::default();
        let informer = Informer::new(secrets).params(lp);
        Ok(SecretSource { informer })
    }

    fn filter_certificate(&self, ev: WatchEvent<Secret>) -> anyhow::Result<Option<TLS>> {
        // dbg!("In handle_secret");
        match ev {
            WatchEvent::Added(secret) | WatchEvent::Modified(secret) => {
                let certificate_secret = self.match_certificate(secret);
                let data = self.extract_data(certificate_secret);
                match data {
                    Some(data) => {
                        let tls = TLS::try_from(data)?;
                        Ok(Some(tls))
                    }
                    None => {
                        // error!(
                        //     "{}:{} Empty data field in Kubernetes Secret",
                        //     certificate_secret.metadata.unwrap_or_default().namespace.unwrap_or_default(),
                        //     secret.metadata.unwrap_or_default().name.unwrap_or_default(),
                        // );
                        Ok(None)
                    }
                }
            }
            _ => Ok(None),
        }
    }

    fn match_certificate(&self, secret: Secret) -> Option<Secret> {
        let expected_type = String::from("kubernetes.io/tls");
        let empty_type = String::from("");
        let secret_type = secret.type_.as_ref().unwrap_or(&empty_type);
        if secret_type.eq(&expected_type) {
            // debug!(
            //     "{}:{} pick certificate",
            //     secret.metadata.unwrap_or_default().namespace.unwrap_or_default(),
            //     secret.metadata.unwrap_or_default().name.unwrap_or_default(),
            // );
            Some(secret)
        } else {
            // debug!(
            //     "{}:{} ignore secret",
            //     secret.metadata.unwrap_or_default().namespace.unwrap_or_default(),
            //     secret.metadata.unwrap_or_default().name.unwrap_or_default()
            // );
            None
        }
    }

    fn extract_data(&self, secret: Option<Secret>) -> Option<BTreeMap<String, ByteString>> {
        match secret {
            Some(secret) => secret.data,
            None => None,
        }
    }
}

impl TryFrom<BTreeMap<String, ByteString>> for TLS {
    type Error = anyhow::Error;

    fn try_from(value: BTreeMap<String, ByteString>) -> Result<Self, Self::Error> {
        let cert = match value.get("tls.crt") {
            Some(x) => String::from_utf8(x.0.clone())?,
            None => return Err(anyhow!("Unable to get cert from secret")),
        };
        let key = match value.get("tls.key") {
            Some(x) => String::from_utf8(x.0.clone())?,
            None => return Err(anyhow!("Unable to get key from secret")),
        };
        let mut certs = TLS::into_vec(cert)?;
        let tls = TLS::from_pem(
            certs.drain(0..1).collect(),
            key,
            certs
        )?;
        Ok(tls)
    }
}
