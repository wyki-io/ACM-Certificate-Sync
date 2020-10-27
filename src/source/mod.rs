mod kubernetes;

use super::common::TLS;
use super::destination::Destination;

use async_trait::async_trait;
pub use kubernetes::SecretSource;

#[async_trait]
pub trait Source {
    fn name(&self) -> String;
    async fn receive<'a, T: Destination + Send + Sync>(
        &'a self,
        destination: &'a T,
    ) -> anyhow::Result<()>;
}
