use anyhow::{Context, Error, Result};
use async_trait::async_trait;
use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, LdapError, Scope,
    SearchEntry,
};
use native_tls::{Certificate, TlsConnector};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::time::{Duration, Instant};

use crate::logging;

#[derive(PartialEq, Eq, Debug)]
pub struct LdapArgs {
    ldap_url: String,
    ldap_bind_user: String,
    ldap_bind_password: String,
    ldap_search_base: String,
    ldap_user_attr: String,
    search_attrs: String,
    ldap_timeout_conn: String,
    ldap_cacert_file_path: Option<String>,
}

impl LdapArgs {
    pub fn new(
        ldap_url: String,
        ldap_bind_user: String,
        ldap_bind_password: String,
        ldap_search_base: String,
        ldap_user_attr: String,
        search_attrs: String,
        ldap_timeout_conn: String,
        ldap_cacert_file_path: Option<String>,
    ) -> Self {
        Self {
            ldap_url,
            ldap_bind_user,
            ldap_bind_password,
            ldap_search_base,
            ldap_user_attr,
            search_attrs,
            ldap_timeout_conn,
            ldap_cacert_file_path,
        }
    }
}

#[async_trait]
pub trait LdapBackend: Send + Sync {
    async fn search_user(
        &self,
        user: &str,
        password: &str,
    ) -> Result<SearchEntry>;

    fn get_attrs(&self) -> &HashMap<String, String>;
    fn get_timeout(&self) -> Duration;
}

pub struct LdapConnector {
    ldap_url: String,
    bind_user: String,
    bind_password: String,
    search_base: String,
    ldap_conn_settings: LdapConnSettings,
    timeout: Duration,
    search_filter: String,
    /*
        The attributes are modelled as hashmap since the field
        in k8s response may be different from the LDAP server.

        Key: The attribute in k8s struct;
        Value: The attribute in LDAP.

        When performing the search, the values are passed for the request
    */
    attrs: HashMap<String, String>,
}

impl LdapConnector {
    pub fn new(ldap_args: LdapArgs) -> Result<Self, Error> {
        let use_starttls: bool;

        if ldap_args.ldap_url.starts_with("ldap://") {
            use_starttls = false;
        } else if ldap_args.ldap_url.starts_with("ldaps://") {
            use_starttls = true;
        } else {
            return Err(Error::msg(
                "Provide a valid URL that starts with ldap or ldaps"
                    .to_string(),
            ));
        }

        let timeout = Duration::from_secs(
            ldap_args
                .ldap_timeout_conn
                .parse::<u64>()
                .ok()
                .and_then(|dur| {
                    if dur <= 60 { Some(dur) } else { Some(60) }
                })
                .unwrap_or(10),
        );

        let ldap_conn_settings = {
            let ca_server = {
                if use_starttls {
                    match ldap_args
                        .ldap_cacert_file_path
                        .map(|path| load_ca_certificate_ldap(&path))
                    {
                        Some(possible_cert) => Some(possible_cert?),
                        None => None, // If None. user is assuming that the LDAP server CA is trustable by host
                    }
                } else {
                    None
                }
            };

            let ldap_conn_settings = LdapConnSettings::new()
                .set_starttls(use_starttls)
                .set_conn_timeout(timeout);

            if use_starttls {
                if let Some(ca_server) = ca_server.clone() {
                    ldap_conn_settings.set_connector(
                        TlsConnector::builder()
                            .add_root_certificate(ca_server)
                            .build()
                            .unwrap(),
                    )
                } else {
                    ldap_conn_settings
                }
            } else {
                ldap_conn_settings
            }
        };

        let search_filter =
            format!("({}={{}})", ldap_args.ldap_user_attr);

        let attrs: HashMap<String, String> = ldap_args
            .search_attrs
            .split(",")
            .filter_map(|pair| {
                let mut s = pair.splitn(2, ':');
                Some((s.next()?.to_string(), s.next()?.to_string()))
            })
            .collect();

        Ok(Self {
            ldap_url: ldap_args.ldap_url,
            bind_user: ldap_args.ldap_bind_user,
            bind_password: ldap_args.ldap_bind_password,
            search_base: ldap_args.ldap_search_base,
            ldap_conn_settings,
            timeout,
            search_filter,
            attrs,
        })
    }

    async fn create_ldap_conn_handle(
        &self,
    ) -> Result<(LdapConnAsync, Ldap), LdapError> {
        LdapConnAsync::with_settings(
            self.ldap_conn_settings.clone(),
            &self.ldap_url,
        )
        .await
    }

    fn format_log_ldap_error(&self, message: String) -> Error {
        let error_msg = Error::msg(message);
        tracing::debug!("{}", error_msg); // Return value in TokenReview already shows the reason
        return error_msg;
    }

    pub async fn search_user(
        &self,
        user: &str,
        password: &str,
    ) -> Result<SearchEntry> {
        let (conn, mut ldap) =
            self.create_ldap_conn_handle().await.context(
                "Error on opening connection with LDAP server",
            )?;

        tracing::debug!(
            "Successfully opened LDAP connection with {}",
            self.ldap_url
        );

        ldap3::drive!(conn);

        match ldap
            .simple_bind(&self.bind_user, &self.bind_password)
            .await?
            .success()
        {
            Err(LdapError::LdapResult { result }) => {
                return Err(self.format_log_ldap_error(format!("LDAP bind user authentication failed. Reason: {}", self.ldap_rc_to_str(result.rc))));
            },

            Err(error) => {
                tracing::debug!(
                    "LDAP bind user authentication failed. {}",
                    logging::format_error_chain(&error)
                );
                return Err(Error::msg(format!(
                    "LDAP bind user authentication failed"
                )));
            },
            _ => {},
        }

        let final_filter = self.search_filter.replace("{}", user);

        let time_before_search = Instant::now();

        let (mut results, _) = match ldap
            .search(
                &self.search_base,
                Scope::Subtree,
                &final_filter,
                &self.attrs.values().collect::<Vec<&String>>(),
            )
            .await?
            .success()
        {
            Ok(results) => Ok(results),

            Err(LdapError::LdapResult { result }) => Err(self
                .format_log_ldap_error(format!(
                    "LDAP search failed for {}.\
                                            Reason {}",
                    &user,
                    self.ldap_rc_to_str(result.rc)
                ))),

            Err(error) => {
                tracing::debug!(
                    "LDAP search unknown error. {}",
                    logging::format_error_chain(&error)
                );
                Err(Error::msg(format!("LDAP search unknown error")))
            },
        }?;

        let time_after_search = time_before_search.elapsed();

        tracing::debug!(
            "Search for user {} in LDAP server took {} ms",
            user,
            time_after_search.as_millis()
        );

        let user_ldap = if let Some(entry) = results.pop() {
            let search_entry = SearchEntry::construct(entry);

            match ldap
                .simple_bind(&search_entry.dn, password)
                .await?
                .success()
            {
                Ok(_) => Ok(search_entry),

                Err(LdapError::LdapResult { result }) => {
                   Err(self.format_log_ldap_error(format!(
                            "LDAP authentication failed for {}. Reason: {}",
                            &user,
                            self.ldap_rc_to_str(result.rc)
                        )))
                },

                Err(error) => {
                    tracing::debug!("LDAP authentication failed. {}", logging::format_error_chain(&error));
                    Err(Error::msg(format!("LDAP authentication failed")))
                }
            }
        } else {
            Err(Error::msg(format!("LDAP user {} not found", user)))
        };

        let _ = ldap.unbind().await;

        user_ldap
    }

    fn ldap_rc_to_str(&self, rc: u32) -> &'static str {
        match rc {
            0 => "Success",
            1 => "Operations Error",
            2 => "Protocol Error",
            3 => "Time Limit Exceeded",
            4 => "Size Limit Exceeded",
            5 => "Compare False",
            6 => "Compare True",
            7 => "Auth Method Not Supported",
            8 => "Stronger Auth Required",
            10 => "Referral",
            11 => "Admin Limit Exceeded",
            12 => "Unavailable Critic Exception",
            13 => "Confidentiality Required",
            14 => "Sasl Bind In Progress",
            16 => "No Such Attribute",
            17 => "Undefined Attribute Type",
            18 => "Inappropriate Matching",
            19 => "Constraint Violation",
            20 => "Attribute Or Value Exists",
            21 => "Invalid Attribute Syntax",
            32 => "No Such Object",
            33 => "Alias Problem",
            34 => "Invalid DNS Syntax",
            36 => "Alias Dereferencing Problem",
            48 => "Inappropriate Authentication",
            49 => "Invalid Credentials",
            50 => "Insufficient Access Rights",
            51 => "Busy",
            52 => "Unavailable",
            53 => "Unwilling To Perform",
            54 => "Loop Detect",
            64 => "Naming Violation",
            65 => "Object Class Violation",
            66 => "Not Allowed On Non Leaf",
            67 => "Not Allowed On RDN",
            68 => "Entry Already Exists",
            69 => "Object Class Mods Prohibited",
            71 => "Affects Multiple DSAs",
            80 => "Other",
            _ => "Unknown",
        }
    }
}

fn load_ca_certificate_ldap(path: &str) -> Result<Certificate> {
    let mut cert_file = File::open(path)
        .context("Error opening LDAP server CA file")?;

    let mut buffer = vec![];

    cert_file
        .read_to_end(&mut buffer)
        .context("Error on reading LDAP server CA file")?;

    let cert = Certificate::from_pem(&buffer)
        .context("Error loading LDAP server CA")?;

    Ok(cert)
}

#[async_trait]
impl LdapBackend for LdapConnector {
    async fn search_user(
        &self,
        user: &str,
        password: &str,
    ) -> Result<SearchEntry> {
        self.search_user(user, password).await
    }

    fn get_attrs(&self) -> &HashMap<String, String> {
        &self.attrs
    }

    fn get_timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {

    use pretty_assertions::assert_eq;
    use rstest::*;

    use super::*;

    #[fixture]
    fn get_base_ldap_args() -> LdapArgs {
        LdapArgs::new(
            "ldap://localhost".to_string(),
            "cn=admin,dc=example,dc=test".to_string(),
            "secret".to_string(),
            "dc=example,dc=test".to_string(),
            "uid".to_string(),
            "".to_string(),
            "40".to_string(),
            None,
        )
    }

    #[fixture]
    fn get_base_ldap_args_wrong_scheme_ldap_url(
        mut get_base_ldap_args: LdapArgs,
    ) -> LdapArgs {
        get_base_ldap_args.ldap_url = "http://localhost".to_string();
        get_base_ldap_args
    }

    #[fixture]
    fn get_base_ldap_args_ldaps_url(
        mut get_base_ldap_args: LdapArgs,
    ) -> LdapArgs {
        get_base_ldap_args.ldap_url = "ldaps://localhost".to_string();
        get_base_ldap_args.ldap_cacert_file_path = None;
        get_base_ldap_args
    }

    #[fixture]
    fn get_base_ldap_args_user_attr(
        mut get_base_ldap_args: LdapArgs,
    ) -> LdapArgs {
        get_base_ldap_args.ldap_user_attr =
            "sAMAccountName".to_string();
        get_base_ldap_args
    }

    #[fixture]
    fn get_base_ldap_args_custom_search_attrs(
        mut get_base_ldap_args: LdapArgs,
    ) -> LdapArgs {
        get_base_ldap_args.search_attrs =
            "username:uid,mail:mail".to_string();
        get_base_ldap_args
    }

    #[fixture]
    fn get_base_ldap_args_valid_cert(
        mut get_base_ldap_args: LdapArgs,
    ) -> LdapArgs {
        get_base_ldap_args.ldap_url = "ldaps://localhost".to_string();
        get_base_ldap_args.ldap_cacert_file_path =
            Some("./pki/ca/ca.crt".to_string());
        get_base_ldap_args
    }

    #[fixture]
    fn get_base_ldap_args_invalid_cert(
        mut get_base_ldap_args: LdapArgs,
    ) -> LdapArgs {
        get_base_ldap_args.ldap_url = "ldaps://localhost".to_string();
        get_base_ldap_args.ldap_cacert_file_path =
            Some("".to_string());
        get_base_ldap_args
    }

    #[rstest]
    fn test_ldap_new_ldapconnector_instance(
        get_base_ldap_args: LdapArgs,
    ) {
        assert!(LdapConnector::new(get_base_ldap_args).is_ok());
    }

    #[rstest]
    fn test_ldap_new_invalid_scheme(
        get_base_ldap_args_wrong_scheme_ldap_url: LdapArgs,
    ) {
        assert!(
            LdapConnector::new(
                get_base_ldap_args_wrong_scheme_ldap_url
            )
            .is_err()
        );
    }

    #[rstest]
    fn test_ldap_new_starttls_flag(
        get_base_ldap_args_ldaps_url: LdapArgs,
    ) {
        let c =
            LdapConnector::new(get_base_ldap_args_ldaps_url).unwrap();
        assert!(c.ldap_conn_settings.starttls());
    }

    #[rstest]
    fn test_ldap_new_valid_ldap_ca_cert(
        get_base_ldap_args_valid_cert: LdapArgs,
    ) {
        let c = LdapConnector::new(get_base_ldap_args_valid_cert)
            .unwrap();
        assert!(c.ldap_conn_settings.starttls());
    }

    #[rstest]
    fn test_ldap_new_invalid_ldap_ca_cert(
        get_base_ldap_args_invalid_cert: LdapArgs,
    ) {
        assert!(
            LdapConnector::new(get_base_ldap_args_invalid_cert)
                .is_err()
        );
    }

    #[rstest]
    fn test_ldap_new_custom_attrs_parsed(
        get_base_ldap_args_custom_search_attrs: LdapArgs,
    ) {
        let c = LdapConnector::new(
            get_base_ldap_args_custom_search_attrs,
        )
        .unwrap();
        assert_eq!(c.get_attrs().get("username").unwrap(), "uid");
        assert_eq!(c.get_attrs().get("mail").unwrap(), "mail");
    }

    #[rstest]
    fn test_ldap_user_filter(get_base_ldap_args_user_attr: LdapArgs) {
        let c =
            LdapConnector::new(get_base_ldap_args_user_attr).unwrap();
        assert_eq!(c.search_filter, "(sAMAccountName={})");
    }
}

#[cfg(all(test, feature = "tests-ldap-ext"))]
mod tests_ldap_ext {

    use dtor::*;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rstest::*;
    use std::env::temp_dir;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::Instant;
    use testcontainers::{
        ContainerAsync, GenericImage, Healthcheck, ImageExt,
        core::{WaitFor, wait::HealthWaitStrategy},
        runners::AsyncRunner,
    };
    use tokio::sync::OnceCell;

    use super::*;

    const LDAP_PORT: u16 = 389;
    const LDAPS_PORT: u16 = 636;

    #[fixture]
    fn get_base_ldap_args() -> LdapArgs {
        LdapArgs {
            ldap_url: "ldap://localhost".to_string(),
            ldap_bind_user: "cn=admin,dc=example,dc=test".to_string(),
            ldap_bind_password: "admin".to_string(),
            ldap_search_base: "ou=users,dc=example,dc=test"
                .to_string(),
            ldap_user_attr: "uid".to_string(),
            search_attrs: "".to_string(),
            ldap_timeout_conn: "40".to_string(),
            ldap_cacert_file_path: None,
        }
    }

    static LDAP: OnceCell<ContainerAsync<GenericImage>> =
        OnceCell::const_new();
    static CERTS: OnceCell<Result<(String, String)>> =
        OnceCell::const_new();

    async fn get_cert_key_test() -> &'static Result<(String, String)>
    {
        CERTS
            .get_or_init(|| async {
                let subject_alt_names = vec![
                    "0.0.0.0".to_string(),
                    "localhost".to_string(),
                    "127.0.0.1".to_string(),
                ];

                let CertifiedKey { cert, signing_key } =
                    generate_simple_self_signed(subject_alt_names)
                        .unwrap();

                let cert_path = PathBuf::from(temp_dir())
                    .join("webhook-server-ldap.pem");

                let key_path = PathBuf::from(temp_dir())
                    .join("webhook-server-ldap.key");

                let mut cert_file = File::create(cert_path.clone())?;
                let mut key_file = File::create(key_path.clone())?;

                cert_file.write_all(cert.pem().as_bytes())?;
                key_file.write_all(
                    signing_key.serialize_pem().as_bytes(),
                )?;

                Ok((
                    cert_path.to_string_lossy().into_owned(),
                    key_path.to_string_lossy().into_owned(),
                ))
            })
            .await
    }

    async fn get_container_tests()
    -> &'static ContainerAsync<GenericImage> {
        let (cert_path, key_path) =
            get_cert_key_test().await.as_ref().clone().unwrap();

        LDAP.get_or_init(|| async {
            GenericImage::new("osixia/openldap", "1.5.0")
                .with_wait_for(WaitFor::Healthcheck(HealthWaitStrategy::new()))
                .with_health_check(
                    Healthcheck::cmd_shell(
                        "ldapsearch -x -H ldap://127.0.0.1 -D 'cn=admin,dc=example,dc=test' \
                -w admin -b 'dc=example,dc=test'",
                    )
                    .with_interval(Duration::from_secs(3))
                    .with_start_interval(Duration::from_secs(3)),
                )
                .with_cmd(["--copy-service", "--loglevel", "debug"])
                .with_env_var("LDAP_ORGANISATION", "k8s-ldap-auth-rs")
                .with_env_var("LDAP_DOMAIN", "example.test")
                .with_env_var("LDAP_ADMIN_PASSWORD", "admin")
                .with_env_var("LDAP_OVERLAY_MEMBEROF", "true")
                .with_env_var("LDAP_TLS_CRT_FILENAME", "webhook-server.pem")
                .with_env_var("LDAP_TLS_KEY_FILENAME", "webhook-server.key")
                .with_env_var("LDAP_TLS_CA_CRT_FILENAME", "ca.crt")
                .with_env_var("LDAP_TLS_VERIFY_CLIENT", "never")
                .with_network("bridge")
                .with_copy_to(
                    "/container/service/slapd/assets/config/bootstrap/ldif/1-ad-schema.ldif",
                    Path::new("./tests/ad-schema.ldif"),
                )
                .with_copy_to(
                    "/container/service/slapd/assets/config/bootstrap/ldif/2-bootstrap.ldif",
                    Path::new("./tests/entries.ldif"),
                )
                .with_copy_to(
                    "/container/service/slapd/assets/config/bootstrap/ldif/3-index.ldif",
                    Path::new("./tests/index-samaccountname.ldif"),
                )
                .with_copy_to(
                    "/container/service/slapd/assets/certs/webhook-server.pem",
                    Path::new(cert_path),
                )
                .with_copy_to(
                    "/container/service/slapd/assets/certs/webhook-server.key",
                    Path::new(key_path),
                )
                .with_copy_to(
                    "/container/service/slapd/assets/certs/ca.crt",
                    Path::new(cert_path),
                )
                .start()
                .await
                .unwrap()
        })
        .await
    }

    #[rstest]
    #[tokio::test]
    async fn test_ldap_ext_search_user_dn_plain(
        mut get_base_ldap_args: LdapArgs,
    ) {
        let container = get_container_tests().await;
        let port =
            container.get_host_port_ipv4(LDAP_PORT).await.unwrap();

        get_base_ldap_args.ldap_url =
            format!("ldap://127.0.0.1:{}", port);

        let connector =
            LdapConnector::new(get_base_ldap_args).unwrap();
        let entry = connector
            .search_user("johndoe", "johndoepass")
            .await
            .unwrap();
        assert_eq!(
            entry.dn,
            "uid=johndoe,ou=users,dc=example,dc=test"
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_ldap_ext_search_user_dn(
        mut get_base_ldap_args: LdapArgs,
    ) {
        let container = get_container_tests().await;
        let port =
            container.get_host_port_ipv4(LDAPS_PORT).await.unwrap();

        let cert_path =
            CERTS.get().unwrap().as_ref().unwrap().to_owned().0;

        get_base_ldap_args.ldap_url =
            format!("ldaps://127.0.0.1:{}", port);
        get_base_ldap_args.ldap_cacert_file_path = Some(cert_path);

        let connector =
            LdapConnector::new(get_base_ldap_args).unwrap();
        let entry = connector
            .search_user("johndoe", "johndoepass")
            .await
            .unwrap();
        assert_eq!(
            entry.dn,
            "uid=johndoe,ou=users,dc=example,dc=test"
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_ldap_ext_get_attrs(
        mut get_base_ldap_args: LdapArgs,
    ) {
        let container = get_container_tests().await;
        let port =
            container.get_host_port_ipv4(LDAPS_PORT).await.unwrap();

        let cert_path =
            CERTS.get().unwrap().as_ref().unwrap().to_owned().0;

        get_base_ldap_args.ldap_url =
            format!("ldaps://127.0.0.1:{}", port);
        get_base_ldap_args.ldap_cacert_file_path = Some(cert_path);
        get_base_ldap_args.search_attrs =
            "k8s_extra_sn:sn,groups:memberOf,k8s_extra_mail:mail"
                .to_string();

        let connector =
            LdapConnector::new(get_base_ldap_args).unwrap();
        let entry = connector
            .search_user("johndoe", "johndoepass")
            .await
            .unwrap();
        assert_eq!(
            entry.attrs,
            HashMap::from([
                ("sn".to_string(), vec!["Doe".to_string()]),
                (
                    "memberOf".to_string(),
                    vec![
                        "cn=k8s-admins,ou=groups,dc=example,dc=test"
                            .to_string(),
                        "cn=infra,ou=groups,dc=example,dc=test"
                            .to_string()
                    ]
                ),
                (
                    "mail".to_string(),
                    vec!["john@example.test".to_string()]
                )
            ])
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_ldap_ext_different_search_base(
        mut get_base_ldap_args: LdapArgs,
    ) {
        let container = get_container_tests().await;
        let port =
            container.get_host_port_ipv4(LDAPS_PORT).await.unwrap();

        let cert_path =
            CERTS.get().unwrap().as_ref().unwrap().to_owned().0;

        get_base_ldap_args.ldap_url =
            format!("ldaps://127.0.0.1:{}", port);
        get_base_ldap_args.ldap_cacert_file_path = Some(cert_path);
        get_base_ldap_args.ldap_search_base =
            "ou=sysaccounts,dc=example,dc=test".to_string();
        get_base_ldap_args.search_attrs =
            "k8s_extra_cn:cn,k8s_extra_homeDirectory:homeDirectory"
                .to_string();

        let connector =
            LdapConnector::new(get_base_ldap_args).unwrap();
        let entry = connector
            .search_user("johndoe", "johndoesysaccount")
            .await
            .unwrap();
        assert_eq!(
            entry.attrs,
            HashMap::from([
                ("cn".to_string(), vec!["John".to_string()]),
                (
                    "homeDirectory".to_string(),
                    vec!["/home/johndoe".to_string()]
                )
            ])
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_ldap_ext_different_user_attr(
        mut get_base_ldap_args: LdapArgs,
    ) {
        let container = get_container_tests().await;
        let port =
            container.get_host_port_ipv4(LDAPS_PORT).await.unwrap();

        let cert_path =
            CERTS.get().unwrap().as_ref().unwrap().to_owned().0;

        get_base_ldap_args.ldap_url =
            format!("ldaps://127.0.0.1:{}", port);
        get_base_ldap_args.ldap_cacert_file_path = Some(cert_path);
        get_base_ldap_args.ldap_search_base =
            "ou=users,dc=example,dc=test".to_string();
        get_base_ldap_args.search_attrs =
            "uid:uid,k8s_extra_homeDirectory:homeDirectory"
                .to_string();
        get_base_ldap_args.ldap_user_attr =
            "sAMAccountName".to_string();

        let connector =
            LdapConnector::new(get_base_ldap_args).unwrap();
        let entry = connector
            .search_user("alicecooper", "alicecooperpass")
            .await
            .unwrap();
        assert_eq!(
            entry.attrs,
            HashMap::from([
                ("uid".to_string(), vec!["alicecooper".to_string()]),
                (
                    "homeDirectory".to_string(),
                    vec!["/home/alicecooper".to_string()]
                )
            ])
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_ldap_ext_different_user_not_found(
        mut get_base_ldap_args: LdapArgs,
    ) {
        let container = get_container_tests().await;
        let port =
            container.get_host_port_ipv4(LDAPS_PORT).await.unwrap();

        let cert_path =
            CERTS.get().unwrap().as_ref().unwrap().to_owned().0;

        get_base_ldap_args.ldap_url =
            format!("ldaps://127.0.0.1:{}", port);
        get_base_ldap_args.ldap_cacert_file_path = Some(cert_path);
        get_base_ldap_args.ldap_search_base =
            "ou=sysaccounts,dc=example,dc=test".to_string();

        let connector =
            LdapConnector::new(get_base_ldap_args).unwrap();
        let entry = connector
            .search_user("alicecooper", "alicecooperpass")
            .await;
        assert_eq!(
            entry.err().unwrap().to_string(),
            "LDAP user alicecooper not found"
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_ldap_ext_timeout_desired(
        mut get_base_ldap_args: LdapArgs,
    ) {
        let container = get_container_tests().await;
        let port =
            container.get_host_port_ipv4(LDAPS_PORT).await.unwrap();

        let cert_path =
            CERTS.get().unwrap().as_ref().unwrap().to_owned().0;

        get_base_ldap_args.ldap_url =
            format!("ldaps://1.1.1.1:{}", port);
        get_base_ldap_args.ldap_cacert_file_path = Some(cert_path);
        get_base_ldap_args.ldap_timeout_conn = "3".to_string();

        let connector =
            LdapConnector::new(get_base_ldap_args).unwrap();
        let start = Instant::now();
        let _ = connector
            .search_user("alicecooper", "alicecooperpass")
            .await;
        let duration = start.elapsed();
        assert_eq!(duration.as_secs(), 3);
    }

    #[rstest]
    #[tokio::test]
    async fn test_ldap_ext_invalid_credentials(
        mut get_base_ldap_args: LdapArgs,
    ) {
        let container = get_container_tests().await;
        let port =
            container.get_host_port_ipv4(LDAPS_PORT).await.unwrap();

        let cert_path =
            CERTS.get().unwrap().as_ref().unwrap().to_owned().0;

        get_base_ldap_args.ldap_url =
            format!("ldaps://127.0.0.1:{}", port);
        get_base_ldap_args.ldap_cacert_file_path = Some(cert_path);
        get_base_ldap_args.ldap_search_base =
            "ou=sysaccounts,dc=example,dc=test".to_string();
        get_base_ldap_args.search_attrs = "".to_string();

        let connector =
            LdapConnector::new(get_base_ldap_args).unwrap();
        let entry =
            connector.search_user("johndoe", "johndoepass").await;
        assert_eq!(
            entry.err().unwrap().to_string(),
            "LDAP authentication failed for johndoe. Reason: Invalid Credentials"
        );
    }

    #[dtor(unsafe)]
    fn cleanup_ldap_container() {
        if let Some(container) = LDAP.get() {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", container.id()])
                .output();
        }
    }

    #[dtor(unsafe)]
    fn remove_pem_files() {
        if let Some(Ok((cert_path, key_path))) = CERTS.get() {
            let _ = std::fs::remove_file(cert_path);
            let _ = std::fs::remove_file(key_path);
        }
    }
}
