use anyhow::Result;
use dotenvy::dotenv;

mod conns;
mod token;
mod ldap;

#[tokio::main]
async fn main() -> Result<()> {

    dotenv()?;

    conns::start_server("0.0.0.0", 7878).await?;

    Ok(())
}
