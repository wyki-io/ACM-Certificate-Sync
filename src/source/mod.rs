mod kubernetes;

use super::common::TLS;

use async_trait::async_trait;
pub use kubernetes::SecretSource;

#[async_trait]
pub trait Source {
    fn name(&self) -> String;
    async fn receive(&self) -> anyhow::Result<Vec<TLS>>;
}
