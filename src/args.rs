use clap::{Arg, Command, ArgMatches};
use dotenvy::from_filename_override;
use std::env::vars;
use anyhow::Result;

use crate::ldap::LdapArgs;

#[derive(PartialEq, Eq)]
pub enum LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR,
    CRITICAL
}

pub struct Args {
    log_level: LogLevel,
    socket_args: (String, u16),
    tls_args: (String, String, String),
    ldap_args: LdapArgs
}

impl Args {
    pub fn new<I, T>(iter: I, version: &'static str) -> Result<Self>
    where
        I: IntoIterator<Item = T> + Clone,
        T: Into<std::ffi::OsString> + Clone
    {

        let parser = Self::create_parser(&version);

        let env_file_path = Self::get_specific_arg(parser.clone(), "env-file", iter.clone());

        #[cfg(test)]

        let load_env_res = from_filename_override(env_file_path);

        #[cfg(not(test))]

        let mut load_env_res = from_filename_override(env_file_path);

        #[cfg(not(test))]
        if load_env_res.is_err() {
            load_env_res = dotenvy::dotenv();
        }

        let parser: Command;

        parser = Self::create_parser(&version);

        let log_level =  Self::get_specific_arg(parser.clone(), "log-level", iter.clone());

        let matches = match parser.clone().try_get_matches_from(iter) {
            Ok(matches) => matches,
            Err(error) => {

                #[cfg(not(test))] {
                    let _ = error.print();
                    std::process::exit(1);
                }

                #[cfg(test)]
                return Err(error.into());
            }
        };

        let socket_args = (
            Self::save_arg(&matches, "ip-address", |address: String| address),
            Self::save_arg(&matches, "port", |port: String| {
                    port.parse().unwrap_or_else(|error| {
                        println!("Could not parse the provided port number,\
                            falling back to port 7878. Caused by: {error}");
                        7878
                    })
                })
        );

        let tls_args = (
            Self::save_arg(&matches, "key", |key: String| key),
            Self::save_arg(&matches, "cert", |cert: String| cert),
            Self::save_arg(&matches, "cacert", |cacert: String| cacert)
        );

        Ok(
            Args {
                log_level: Self::parse_log_level(&log_level),
                socket_args,
                tls_args,
                ldap_args: LdapArgs::new(
                    Self::save_arg(&matches, "ldap-url", |ldap_url: String| ldap_url),
                    Self::save_arg(&matches, "ldap-bind-user", |ldap_bind_user: String| ldap_bind_user),
                    Self::save_arg(&matches, "ldap-bind-password", |ldap_bind_password: String| ldap_bind_password),
                    Self::save_arg(&matches, "ldap-search-base", |ldap_search_base: String| ldap_search_base),
                    Self::save_arg(&matches, "ldap-user-attr", |ldap_user_param: String| ldap_user_param),
                    Self::save_arg_many(&matches, "ldap-search-attrs", |attrs: Vec<String>| {
                            attrs.join(",")
                        }
                    ),
                    Self::save_arg(&matches, "ldap-timeout-conn", |ldap_timeout_conn: String| ldap_timeout_conn),
                    matches.try_get_one::<String>("ldap-cacert-path")
                            .map_or(None, |path| path.cloned())
                )                
            }
        )

    }

    fn save_arg<T, U>(matches: &ArgMatches, name: &str, process_arg: impl FnOnce(T) -> U) -> U
    where 
        T: Clone + Send + Sync + 'static,
        U: Clone + Send + Sync + 'static
    {

        let arg = matches.get_one::<T>(name).unwrap().to_owned();
        process_arg(arg)

    }

    fn save_arg_many<T, U>(matches: &ArgMatches, name: &str, process_arg: impl FnOnce(Vec<T>) -> U) -> U 
    where 
        T: Clone + Send + Sync + 'static,
        U: Clone + Send + Sync + 'static
    {

        let args = matches.get_many::<T>(name).unwrap().cloned().collect::<Vec<T>>();
        process_arg(args)

    }

    fn get_specific_arg<I, T>(parser: Command, arg_name: &str, iter: I) -> String
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {

        parser
        .ignore_errors(true)
        .get_matches_from(iter)
        .get_one::<String>(arg_name)
        .unwrap().to_owned()

    }

    fn check_env_vars() {

        for (k, _) in vars() {
            if k.starts_with("K8S_LDAP_AUTH") {
                println!("Loaded environment variable {}", k); // DEBUG
            }
        }

    }

    fn parse_log_level(log_level: &str) -> LogLevel {

        match &log_level.to_uppercase()[..] {
            "DEBUG" => LogLevel::DEBUG,
            "INFO" => LogLevel::INFO,
            "WARN" => LogLevel::WARN,
            "ERROR" => LogLevel::ERROR,
            "CRITICAL" => LogLevel::CRITICAL,
            _ => LogLevel::INFO
        }

    }

    fn create_parser(version: &'static str) -> Command {

        let mut command = Command::new("k8s-ldap-auth-rs");

        command = command
        .about("A webhook authentication server for a Kubernetes cluster")
        .version(version)
        .color(clap::ColorChoice::Always)
        .arg(
            Arg::new("env-file")
            .default_value(".env")
            .ignore_case(false)
            .num_args(1)
            .value_name("PATH")
            .long("env-file")
        )
        .arg(
            Arg::new("log-level")
            .env("K8S_LDAP_AUTH_LOG_LEVEL")
            //.value_parser(["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"])
            .default_value("INFO")
            .ignore_case(true)
            .value_name("LEVEL")
            .num_args(1)
            .long("log-level")
        )
        .arg(
            Arg::new("ip-address")
            .default_value("0.0.0.0")
            .num_args(1)
            .value_name("ADDRESS")
            .long("ip-address")
            .help("IP address of the socket")
        )
        .arg(
            Arg::new("port")
            .default_value("7878")
            .num_args(1)
            .value_name("PORT")
            .long("port")
            .help("Port of the socket")
        )
        .arg(
            Arg::new("key")
            .env("K8S_LDAP_AUTH_KEY_PATH")
            .default_value("./pki/server/webhook-server.key")
            .ignore_case(false)
            .value_name("PATH")
            .num_args(1)
            .long("key")
            .help("Path to the private key file")
        )
        .arg(
            Arg::new("cert")
            .env("K8S_LDAP_AUTH_CERT_PATH")
            .default_value("./pki/server/webhook-server.pem")
            .ignore_case(false)
            .value_name("PATH")
            .num_args(1)
            .long("cert")
            .help("Path to the certificate of the server")
        )
        .arg(
            Arg::new("cacert")
            .env("K8S_LDAP_AUTH_CA_CERT_PATH")
            .default_value("./pki/ca/ca.crt")
            .ignore_case(false)
            .value_name("PATH")
            .num_args(1)
            .long("cacert")
            .help("Path to the CA certificate to authenticate the clients")
        )
        .arg(
            Arg::new("ldap-url")
            .env("K8S_LDAP_AUTH_LDAP_URL")
            .ignore_case(false)
            .value_name("URL")
            .num_args(1)
            .long("ldap-url")
            .required(true)
            .help("LDAP URL to authenticate the users")
        )
        .arg(
            Arg::new("ldap-bind-user")
            .env("K8S_LDAP_AUTH_LDAP_BIND_USER")
            .ignore_case(false)
            .value_name("BIND-USER")
            .num_args(1)
            .long("ldap-bind-user")
            .required(true)
            .help("LDAP bind user that will search the users")
        )
        .arg(
            Arg::new("ldap-bind-password")
            .env("K8S_LDAP_AUTH_LDAP_BIND_PASSWORD")
            .ignore_case(false)
            .value_name("BIND-PASSWORD")
            .num_args(1)
            .long("ldap-bind-password")
            .required(true)
            .help("Password of the LDAP bind user that will search \
                the users (Preferred to pass as environment variable)"
            )
        )
        .arg(
            Arg::new("ldap-search-base")
            .env("K8S_LDAP_AUTH_LDAP_SEARCH_BASE")
            .ignore_case(false)
            .value_name("SEARCH-BASE-DN")
            .num_args(1)
            .long("ldap-search-base")
            .required(true)
            .help("DN specifying the subtree to look for the users")
        )
        .arg(
            Arg::new("ldap-user-attr")
            .env("K8S_LDAP_AUTH_LDAP_USER_ATTR")
            .default_value("uid")
            .ignore_case(false)
            .value_name("PARAM")
            .num_args(1)
            .long("ldap-user-attr")
            .help("Attribute that will be used to match the username from the token")
        )
        .arg(
            Arg::new("ldap-search-attrs")
            .env("K8S_LDAP_AUTH_LDAP_SEARCH_ATTRS")
            .ignore_case(false)
            .default_value("")
            .value_name("ATTR_IN_K8S:ATTR_IN_LDAP_SERVER")
            .num_args(0..)
            .value_delimiter(',')
            .action(clap::ArgAction::Append)
            .long("ldap-search-attrs")
            .help("Attributes to retrieve from LDAP server. \
                Note: This is an array of key:value values separated by comma"
            )
        )
        .arg(
            Arg::new("ldap-timeout-conn")
            .env("K8S_LDAP_AUTH_LDAP_TIMEOUT_CONN")
            .value_name("TIMEOUT")
            .default_value("10")
            .num_args(1)
            .long("ldap-timeout-conn")
            .help("Timeout for LDAP connection")
        )
        .arg(
            Arg::new("ldap-cacert-path")
            .env("K8S_LDAP_AUTH_LDAP_CA_CERT_PATH")
            .value_name("PATH")
            .num_args(1)
            .long("ldap-cacert-path")
            .help("Path to the LDAP CA file to check the LDAP server")
        );

        command

    }

    pub fn get_all_args(self) -> ((String, u16), (String, String, String), LdapArgs) {

        (self.socket_args, self.tls_args, self.ldap_args)

    }

}

#[cfg(test)]
mod tests {

    use pretty_assertions::assert_eq;
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use rstest::*;
    use serial_test::serial;
    use std::env::temp_dir;
    use dtor::*;

    use super::*;

    const VERSION: &str = "MOCK";

    #[fixture]
    #[once]
    fn base_args() -> Vec<&'static str> {

        vec![
            "k8s-ldap-auth-rs",
            "--env-file",           "",
            "--key",                "webhook-server.key",
            "--cert",               "webhook-server.pem",
            "--cacert",             "ca.crt",
            "--ldap-url",           "ldaps://localhost",
            "--ldap-bind-user",     "cn=admin,dc=example,dc=test",
            "--ldap-bind-password", "secret",
            "--ldap-search-base",   "dc=example,dc=test",
        ]

    }

    unsafe fn clear_env() {

        for key in &[
            "K8S_LDAP_AUTH_KEY_PATH",
            "K8S_LDAP_AUTH_CERT_PATH",
            "K8S_LDAP_AUTH_CA_CERT_PATH",
            "K8S_LDAP_AUTH_LDAP_URL",
            "K8S_LDAP_AUTH_LDAP_BIND_USER",
            "K8S_LDAP_AUTH_LDAP_BIND_PASSWORD",
            "K8S_LDAP_AUTH_LDAP_SEARCH_BASE",
            "K8S_LDAP_AUTH_LOG_LEVEL",
            "K8S_LDAP_AUTH_LDAP_CA_CERT_PATH",
            "K8S_LDAP_AUTH_LDAP_SEARCH_ATTRS",
            "K8S_LDAP_AUTH_LDAP_TIMEOUT_CONN",
            "K8S_LDAP_AUTH_LDAP_USER_ATTR"
        ] {
            unsafe { env::remove_var(key) };
        }

    }

    #[rstest]
    #[case("DEBUG",    matches!(Args::parse_log_level("DEBUG"),    LogLevel::DEBUG))]
    #[case("info",     matches!(Args::parse_log_level("info"),     LogLevel::INFO))]
    #[case("Warn",     matches!(Args::parse_log_level("Warn"),     LogLevel::WARN))]
    #[case("ERROR",    matches!(Args::parse_log_level("ERROR"),    LogLevel::ERROR))]
    #[case("critical", matches!(Args::parse_log_level("critical"), LogLevel::CRITICAL))]
    #[case("garbage",  matches!(Args::parse_log_level("garbage"),  LogLevel::INFO))]
    #[case("",         matches!(Args::parse_log_level(""),         LogLevel::INFO))]
    fn test_args_parse_log_level(#[case] _input: &str, #[case] result: bool) {

        assert!(result);

    }

    #[rstest]
    #[serial]
    fn test_args_default_args() {

        unsafe { clear_env() };

        let args = vec![
            "k8s-ldap-auth-rs",
            "--env-file",           "",
            "--ldap-url",           "ldaps://localhost",
            "--ldap-bind-user",     "cn=admin,dc=example,dc=test",
            "--ldap-bind-password", "secret",
            "--ldap-search-base",   "dc=example,dc=test",
            "--ldap-cacert-path",   "ldap-ca.crt"
        ];
        
        let (
            (ip, port),
            (key, cert, cacert),
            ldap_args
        ) = Args::new(args, VERSION).unwrap().get_all_args();

        assert_eq!(ip, "0.0.0.0");
        assert_eq!(port, 7878u16);
        assert_eq!(key, "./pki/server/webhook-server.key");
        assert_eq!(cert, "./pki/server/webhook-server.pem");
        assert_eq!(cacert, "./pki/ca/ca.crt");
        assert_eq!(ldap_args, LdapArgs::new(
                "ldaps://localhost".to_string(),
                "cn=admin,dc=example,dc=test".to_string(),
                "secret".to_string(),
                "dc=example,dc=test".to_string(),
                "uid".to_string(),
                "".to_string(),
                "10".to_string(),
                Some("ldap-ca.crt".to_string())
            )
        );

    }

    #[rstest]
    #[serial]
    fn test_args_custom_args(base_args: &'static Vec<&str>) {

        unsafe { clear_env() };

        let mut args = base_args.clone();
        args.extend(
            [
                "--ip-address", "127.0.0.1",
                "--port", "9443",
                "--ldap-cacert-path", "/path/to/ca.crt",
                "--ldap-search-attrs", "k8s_extra_sn:sn",
                "--ldap-search-attrs", "username:uid"
            ]
        );

        let (
            (ip, port),
            (key, cert, cacert),
            ldap_args
        ) = Args::new(args, VERSION).unwrap().get_all_args();

        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 9443u16);
        assert_eq!(key, "webhook-server.key");
        assert_eq!(cert, "webhook-server.pem");
        assert_eq!(cacert, "ca.crt");
        assert_eq!(ldap_args, LdapArgs::new(
            "ldaps://localhost".to_string(),
            "cn=admin,dc=example,dc=test".to_string(),
            "secret".to_string(),
            "dc=example,dc=test".to_string(),
            "uid".to_string(),
            "k8s_extra_sn:sn,username:uid".to_string(),
            "10".to_string(),
            Some("/path/to/ca.crt".to_string())
        ));

    }

    #[rstest]
    #[serial]
    fn test_args_invalid_port_falls_back_to_7878(base_args: &'static Vec<&str>) {

        unsafe { clear_env() };

        let mut args = base_args.clone();
        args.extend(["--port", "nonsensevalue"]);

        let (
            (_, port),
            _,
            _
        ) = Args::new(args, VERSION).unwrap().get_all_args();

        assert_eq!(port, 7878u16);

    }

    #[rstest]
    #[serial]
    fn test_args_absent_required() {

        unsafe { clear_env() };

        let args: Vec<&str> = vec![
            "k8s-ldap-auth-rs", "--env-file",   ""
        ];

        let res = Args::new(args, VERSION);

        assert!(res.is_err());

    }

    #[rstest]
    #[serial]
    fn test_args_tls_args_from_env() {

        unsafe {
            clear_env();
            env::set_var("K8S_LDAP_AUTH_KEY_PATH",     "env/server.key");
            env::set_var("K8S_LDAP_AUTH_CERT_PATH",    "env/server.pem");
            env::set_var("K8S_LDAP_AUTH_CA_CERT_PATH", "env/ca.crt");
        }

        let args = vec![
            "k8s-ldap-auth-rs",
            "--env-file",           "",
            "--ldap-url",           "ldap://localhost:389",
            "--ldap-bind-user",     "cn=admin,dc=example,dc=test",
            "--ldap-bind-password", "secret",
            "--ldap-search-base",   "dc=example,dc=test",
        ];

        let (
            _,
            (key, cert, cacert),
            _
        ) = Args::new(args, VERSION).unwrap().get_all_args();

        assert_eq!(key,    "env/server.key");
        assert_eq!(cert,   "env/server.pem");
        assert_eq!(cacert, "env/ca.crt");

        unsafe { clear_env() };

    }


    #[rstest]
    #[case("DEBUG",    LogLevel::DEBUG)]
    #[case("INFO",    LogLevel::INFO)]
    #[case("WARN",     LogLevel::WARN)]
    #[case("ERROR",    LogLevel::ERROR)]
    #[case("CRITICAL", LogLevel::CRITICAL)]
    #[serial]
    fn test_args_log_level_from_cli(#[case] level: &'static str, #[case] expected: LogLevel) {

        unsafe { clear_env() };

        let mut args = base_args();
        args.extend(["--log-level", level]);

        let parsed = Args::new(args, VERSION).unwrap();

        assert!(parsed.log_level == expected);

    }

    #[rstest]
    #[serial]
    fn test_args_ldap_cacert_absent(base_args: &'static Vec<&str>) {

        unsafe { clear_env() };

        let base_args = base_args.clone();
        
        let (
            _,
            _,
            ldap_args
        ) = Args::new(base_args, VERSION).unwrap().get_all_args();

        assert_eq!(
            ldap_args,
            LdapArgs::new(
                "ldaps://localhost".to_string(),
                "cn=admin,dc=example,dc=test".to_string(),
                "secret".to_string(),
                "dc=example,dc=test".to_string(),
                "uid".to_string(),
                "".to_string(),
                "10".to_string(),
                None
            )
        );

    }

    #[rstest]
    #[serial]
    fn test_args_ldap_cacert_present() {

        unsafe { clear_env() };

        let mut args = base_args();
        args.extend(["--ldap-cacert-path", "/etc/ssl/ldap-ca.crt"]);

        let (
            _,
            _,
            ldap_args
        ) = Args::new(args, VERSION).unwrap().get_all_args();

        assert_eq!(
            ldap_args,
            LdapArgs::new(
                "ldaps://localhost".to_string(),
                "cn=admin,dc=example,dc=test".to_string(),
                "secret".to_string(),
                "dc=example,dc=test".to_string(),
                "uid".to_string(),
                "".to_string(),
                "10".to_string(),
                Some("/etc/ssl/ldap-ca.crt".to_string())
            )
        );

    }

    #[rstest]
    #[serial]
    fn test_args_ldap_timeout_custom() {

        unsafe { clear_env() };

        let mut args = base_args();
        args.extend(["--ldap-timeout-conn", "30"]);

        let (
            _,
            _,
            ldap_args
        ) = Args::new(args, VERSION).unwrap().get_all_args();

        assert_eq!(
            ldap_args,
            LdapArgs::new(
                "ldaps://localhost".to_string(),
                "cn=admin,dc=example,dc=test".to_string(),
                "secret".to_string(),
                "dc=example,dc=test".to_string(),
                "uid".to_string(),
                "".to_string(),
                "30".to_string(),
                None
            )
        );

    }

    #[rstest]
    #[serial]
    fn test_args_env_file_loaded() -> Result<()> {

        unsafe { clear_env() };

        let env_file_path = PathBuf::from(temp_dir()).join("k8s-ldap-auth-rs-test.env");
        let mut env_file = File::create(env_file_path.clone())?;

        let env_vars = [
            ("K8S_LDAP_AUTH_KEY_PATH=env-file/server.key"),
            ("K8S_LDAP_AUTH_CERT_PATH=env-file/server.pem"),
            ("K8S_LDAP_AUTH_CA_CERT_PATH=env-file/ca.crt"),
            ("K8S_LDAP_AUTH_LDAP_CA_CERT_PATH=env-file/ldap/ca.crt"),
            ("K8S_LDAP_AUTH_LDAP_URL=ldap://envfile:389"),
            ("K8S_LDAP_AUTH_LDAP_BIND_USER=cn=admin,dc=env,dc=test"),
            ("K8S_LDAP_AUTH_LDAP_BIND_PASSWORD=envpassword"),
            ("K8S_LDAP_AUTH_LDAP_SEARCH_BASE=dc=env,dc=test"),
            ("K8S_LDAP_AUTH_LDAP_USER_ATTR=sAMAccountName"),
            ("K8S_LDAP_AUTH_LDAP_SEARCH_ATTRS=k8s_extra_cn:cn"),
            ("K8S_LDAP_AUTH_LDAP_TIMEOUT_CONN=9"),
            ("K8S_LDAP_AUTH_LOG_LEVEL=CRITICAL")
        ];

        for env_var in env_vars {
            writeln!(env_file, "{env_var}")?;
        }

        let args = vec!["k8s-ldap-auth-rs", "--env-file", env_file_path.to_str().unwrap()];

        let log_level = Args::new(args.clone(), VERSION).unwrap().log_level;

        let (
            _,
            (key, cert, cacert),
            ldap_args
        ) = Args::new(args, VERSION).unwrap().get_all_args();

        assert_eq!(key, "env-file/server.key");
        assert_eq!(cert, "env-file/server.pem");
        assert_eq!(cacert, "env-file/ca.crt");
        assert!(log_level == LogLevel::CRITICAL);

        assert_eq!(
            ldap_args,
            LdapArgs::new(
                "ldap://envfile:389".to_string(),
                "cn=admin,dc=env,dc=test".to_string(),
                "envpassword".to_string(),
                "dc=env,dc=test".to_string(),
                "sAMAccountName".to_string(),
                "k8s_extra_cn:cn".to_string(),
                "9".to_string(),
                Some("env-file/ldap/ca.crt".to_string())
            )
        );

        unsafe { clear_env() };

        Ok(())

    }

    #[dtor(unsafe)]
    fn remove_test_env_file() {

        let env_file_path = PathBuf::from(temp_dir()).join("k8s-ldap-auth-rs-test.env");

        if env_file_path.exists() {

            let _ = std::fs::remove_file(env_file_path);

        }

    }

}
