use std::sync::Arc;

use crate::args::Args;

mod args;
mod conns;
mod ldap;
mod logging;
mod token;

const VERSION: &str = "v0.2.0";

#[tokio::main]
async fn main() {
    let Ok(args) =
        Args::new(std::env::args_os().collect::<Vec<_>>(), VERSION).inspect_err(|error| {
            eprintln!(
                "Could not parse and enumerate the args for the application. {}",
                logging::format_error_chain(&**error)
            );
        })
    else {
        return;
    };

    let (
        (ip_address, port),
        (key_path, server_cert_path, ca_cert_path),
        ldap_args,
        _,
        _,
    ) = args.get_all_args();

    logging::list_related_env_vars_application();

    let ldap_connector: Arc<dyn ldap::LdapBackend> =
        match ldap::LdapConnector::new(ldap_args) {
            Ok(ldap_connector) => Arc::new(ldap_connector),
            Err(error) => {
                tracing::error!(
                    "Could not create the LDAP connections handler. {}",
                    logging::format_error_chain(&*error)
                );
                return;
            },
        };

    match conns::start_server(
        ip_address,
        port,
        key_path,
        server_cert_path,
        ca_cert_path,
        ldap_connector,
    )
    .await
    {
        Ok(_) => {},
        Err(error) => {
            tracing::error!(
                "Could not start server. {}",
                logging::format_error_chain(&*error)
            );
            return;
        },
    }
}
