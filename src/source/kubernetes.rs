use super::TLS;

use async_trait::async_trait;
use anyhow::anyhow;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::{
    api::{Api, ListParams, WatchEvent},
    runtime::Informer,
    Client,
};
use futures::{StreamExt, TryStreamExt};
use std::collections::BTreeMap;
use std::convert::TryFrom;
pub struct SecretSource {}

#[async_trait]
impl super::Source for SecretSource {
    fn name(&self) -> String {
        String::from("Kubernetes Secret Source")
    }
    async fn receive(&self) -> anyhow::Result<Vec<TLS>> {
        let client = Client::try_default().await?;
        let secrets: Api<Secret> = Api::all(client);
        let lp = ListParams::default();
        let si = Informer::new(secrets).params(lp);

        let mut secrets = si.poll().await?.boxed();
        let mut certs = Vec::new();
        while let Some(secret) = secrets.try_next().await? {
            if let Some(cert) = filter_certificate(secret).await? {
                certs.push(cert);
            }
        }
        Ok(certs)
    }
}

async fn filter_certificate(ev: WatchEvent<Secret>) -> anyhow::Result<Option<TLS>> {
    // dbg!("In handle_secret");
    match ev {
        WatchEvent::Added(secret) | WatchEvent::Modified(secret) => {
            let certificate_secret = match_certificate(secret);
            let data = extract_data(certificate_secret);
            match data {
                Some(data) => {
                    let tls = TLS::try_from(data)?;
                    Ok(Some(tls))
                },
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
        _ => Ok(None)
    }
}

fn match_certificate(secret: Secret) -> Option<Secret> {
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

fn extract_data(secret: Option<Secret>) -> Option<BTreeMap<String, ByteString>> {
    match secret {
        Some(secret) => secret.data,
        None => None
    }
}

impl TryFrom<BTreeMap<String, ByteString>> for TLS {
    type Error = anyhow::Error;

    fn try_from(value: BTreeMap<String, ByteString>) -> Result<Self, Self::Error> {
        let cert = match value.get("tls.crt") {
            Some(x) => x,
            None => return Err(anyhow!("Unable to get cert from secret")),
        };
        let key = match value.get("tls.key") {
            Some(x) => x,
            None => return Err(anyhow!("Unable to get key from secret")),
        };
        let mut tls = TLS::default();
        tls.cert = match String::from_utf8(cert.0.clone()) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Unable to parse the cert from secret")),
        };
        tls.key = match String::from_utf8(key.0.clone()) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Unable to parse the key from secret")),
        };
        Ok(tls)
    }
}
