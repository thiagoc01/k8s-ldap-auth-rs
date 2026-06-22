use anyhow::Result;
use std::sync::Arc;

mod conns;
mod token;
mod ldap;
mod args;

const VERSION: &str = "v0.1.0";

#[tokio::main]
async fn main() -> Result<()> {

    let args =
        args::Args::new(
            std::env::args_os()
            .collect::<Vec<_>>(),
            VERSION
        )?;

    let (
        (ip_address, port),
        (key_path, server_cert_path, ca_cert_path),
        ldap_args
    ) = args.get_all_args();

    let ldap_connector: Arc<dyn ldap::LdapBackend> = Arc::new(ldap::LdapConnector::new(ldap_args)?);

    conns::start_server(
        ip_address,
        port,
        key_path,
        server_cert_path,
        ca_cert_path,
        ldap_connector
    ).await?;

    Ok(())
}