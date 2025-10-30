use async_trait::async_trait;

#[async_trait(?Send)]
pub trait Task: Send + Sync {
    type Error;

    async fn execute(&self, target: String) -> Result<String, Self::Error>;
}
