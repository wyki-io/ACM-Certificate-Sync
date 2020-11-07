use super::Destination;
use super::TLS;

use anyhow::anyhow;
use async_trait::async_trait;
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::{
    api::{Api, ListParams},
    Client,
};
use kube_runtime::utils::try_flatten_applied;
use kube_runtime::watcher;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::str;

use tokio::time::{delay_for, Duration};

pub struct SecretSource {
    api: Api<Secret>,
    list_params: ListParams,
}

#[async_trait]
impl super::Source for SecretSource {
    fn name(&self) -> String {
        String::from("Kubernetes Secret Source")
    }

    async fn receive<'a, T: Destination + Send + Sync>(
        &'a self,
        destination: &'a T,
    ) -> anyhow::Result<()> {
        loop {
            let watcher = watcher(self.api.clone(), self.list_params.clone());
            try_flatten_applied(watcher)
                .try_for_each(|secret| async move {
                    if let Err(e) = self.handle_certificate(destination, secret).await {
                        error!("Error while receiving TLS : {}", e);
                    }
                    // Delay to avoid throttling on destination side
                    delay_for(Duration::from_secs(1)).await;
                    Ok(())
                })
                .await?;
        }
    }
}

impl SecretSource {
    pub async fn new(_config: &str) -> anyhow::Result<Self> {
        let client = Client::try_default().await?;
        let api: Api<Secret> = Api::all(client);
        let list_params = ListParams::default().fields("type=kubernetes.io/tls");
        Ok(SecretSource { api, list_params })
    }

    async fn handle_certificate<'a, T: Destination + Send + Sync>(
        &'a self,
        destination: &'a T,
        secret: Secret,
    ) -> anyhow::Result<()> {
        if let Some(tls) = self.convert_to_tls(secret)? {
            info!(
                "Will try to synchronize cert with domains {}",
                tls.domains.join(", ")
            );
            destination.publish(tls).await?;
        }
        Ok(())
    }

    fn convert_to_tls(&self, secret: Secret) -> anyhow::Result<Option<TLS>> {
        let secret_name = SecretSource::get_name_from_secret(&secret);
        let secret_namespace = SecretSource::get_namespace_from_secret(&secret);
        info!("Pick certificate {}:{}", secret_namespace, secret_name);
        match secret.data {
            Some(data) => {
                let tls = TLS::try_from(data)?;
                info!(
                    "Received cert from secret {}:{}",
                    secret_namespace, secret_name
                );
                Ok(Some(tls))
            }
            None => {
                warn!(
                    "No data found in secret {}:{}",
                    secret_namespace, secret_name
                );
                Ok(None)
            }
        }
    }

    fn get_name_from_secret(secret: &Secret) -> String {
        match secret.metadata.name {
            Some(ref name) => name.clone(),
            None => String::from(""),
        }
    }

    fn get_namespace_from_secret(secret: &Secret) -> String {
        match secret.metadata.namespace {
            Some(ref namespace) => namespace.clone(),
            None => String::from(""),
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
        let mut certs = TLS::split_to_vec(cert)?;
        let tls = TLS::from_pem(certs.drain(0..1).collect(), key, certs)?;
        Ok(tls)
    }
}
