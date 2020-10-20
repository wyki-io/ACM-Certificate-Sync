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
        match self.event_loop(destination).await {
            Err(e) => error!("Error while receiving TLS : {}", e),
            _ => ()
        }
        Ok(())
    }
}

impl SecretSource {
    pub async fn new(_config: &str) -> anyhow::Result<Self> {
        let client = Client::try_default().await?;
        let secrets: Api<Secret> = Api::all(client);
        let lp = ListParams::default()
            .fields("type=kubernetes.io/tls");
        let informer = Informer::new(secrets).params(lp);
        Ok(SecretSource { informer })
    }

    async fn event_loop<'a, T: Provider + Send + Sync>(
        &'a self,
        destination: &'a T,
    ) -> anyhow::Result<()> {
        let mut secrets = self.informer.poll().await?.boxed();
        while let Some(secret) = secrets.try_next().await? {
            if let Some(cert) = self.filter_certificate(secret)? {
                info!("Will try to synchronize cert with domains {}", cert.domains.join(", "));
                // destination.publish(cert).await?;
            }
        }
        Ok(())
    }

    fn filter_certificate(&self, ev: WatchEvent<Secret>) -> anyhow::Result<Option<TLS>> {
        match ev {
            WatchEvent::Added(secret) | WatchEvent::Modified(secret) => {
                let secret_name = SecretSource::get_name_from_secret(&secret);
                let secret_namespace = SecretSource::get_namespace_from_secret(&secret);
                info!("Pick certificate {}:{}", secret_namespace, secret_name);
                match secret.data {
                    Some(data) => {
                        let tls = TLS::try_from(data)?;
                        info!("Received cert from secret {}:{}", secret_namespace, secret_name);
                        Ok(Some(tls))
                    }
                    None => {
                        warn!("No data found in secret {}:{}", secret_namespace, secret_name);
                        Ok(None)
                    }
                }
            }
            _ => Ok(None),
        }
    }

    fn get_name_from_secret(secret: &Secret) -> String {
        match secret.metadata {
            Some(ref meta) => match meta.name {
                Some(ref name) => name.clone(),
                None => String::from("")
            },
            None => String::from("")
        }
    }

    fn get_namespace_from_secret(secret: &Secret) -> String {
        match secret.metadata {
            Some(ref meta) => match meta.namespace {
                Some(ref namespace) => namespace.clone(),
                None => String::from("")
            },
            None => String::from("")
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
