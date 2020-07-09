use acs::{run, AcmAlbProvider, Provider, Receiver};
use async_trait::async_trait;
use rusoto_core::Region;

struct DummyReceiver {}

impl Receiver for DummyReceiver {
    fn receive() -> acs::TLS {
        todo!()
    }
}

struct DummyProvider {}

#[async_trait]
impl Provider for DummyProvider {
    fn name(&self) -> String {
        String::from("Dummy")
    }
    async fn publish(&self, tls: acs::TLS) -> anyhow::Result<()> {
        let _ = tls;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let receiver = DummyReceiver {};
    let provider = AcmAlbProvider::new(Region::EuWest3);
    run(receiver, provider).await
}
