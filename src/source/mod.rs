mod kubernetes;

use super::common::TLS;
use super::provider::Provider;

use async_trait::async_trait;
pub use kubernetes::SecretSource;

#[async_trait]
pub trait Source {
    fn name(&self) -> String;
    async fn receive<'a, T: Provider + Send + Sync>(
        &'a self,
        destination: &'a T,
    ) -> anyhow::Result<()>;
}
