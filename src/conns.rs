use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use rustls_pki_types::{CertificateDer, pem::PemObject, PrivateKeyDer, pem::Error};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{ServerConfig, RootCertStore};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::server::{TlsStream};
use anyhow::{Context, Result};

use crate::token::handle_tokenreview_request;
use crate::ldap::LdapBackend;

use crate::logging;

enum ParseOutcome {
    Body(String, String, usize),
    Handled(u16, String, String, usize),
}

fn load_cert(path: &str) -> Result<CertificateDer<'static>, Error> {

    CertificateDer::from_pem_file(path)

}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, Error> {

    PrivateKeyDer::from_pem_file(path)

}

fn set_tls(key_path: &str, server_cert_path: &str, ca_cert_path: &str) -> Result<TlsAcceptor> {

    let ca_cert: CertificateDer<'_> = load_cert(ca_cert_path).context("Could not load the CA certificate")?;

    tracing::debug!("Loading CA cert on path {}", ca_cert_path);

    let server_cert: CertificateDer<'_> = load_cert(server_cert_path).context("Could not load the certificate for mTLS")?;

    tracing::debug!("Loading server cert on path {}", server_cert_path);

    let key: PrivateKeyDer<'_> = load_key(key_path).context("Could not load the key for mTLS")?;

    tracing::debug!("Loading server key on path {}", key_path);

    let mut ca_root_store = RootCertStore::empty();

    ca_root_store.add(ca_cert).context("Could not initialize CA root store")?;

    let client_cert_verifier = WebPkiClientVerifier::builder(
        ca_root_store.into())
        .build().context("Could not create verifier for clients certificates")?;

    let server_tls_config = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(vec![server_cert], key)
        .context("Could not create TLS configuration for server")?;

    // TLS configured both for accept clients' certs signed with the CA provided
    // and to serve the cert and key pair

    Ok(TlsAcceptor::from(Arc::new(server_tls_config)))

}

pub async fn start_server(
    ip_address: String,
    port: u16,
    key_path: String,
    server_cert_path: String,
    ca_cert_path: String,
    ldap_connector: Arc<dyn LdapBackend>
) -> Result<String> {

    let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from_str(&ip_address)
                        .unwrap_or(Ipv4Addr::new(0,0,0,0))),
            port);

    let tls_handshaker =
        set_tls(&key_path, &server_cert_path, &ca_cert_path)
        .inspect_err(|e| {
                tracing::error!(
                    "{}", logging::format_error_chain(&**e)
                );
            }
        )?;

    let listener = TcpListener::bind(&addr).await.context("Could not listen at the provided socket")?;

    tracing::info!("Server listening on {addr}");

    loop {

        let (socket, socket_addr) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::error!("Could not start a connection. {}", logging::format_error_chain(&error));
                continue;
            }
        };

        let tls_handshaker = tls_handshaker.clone();
        let ldap_connector = ldap_connector.clone();

        tokio::spawn(async move {
            let peer_ip = socket_addr.ip();
            match tls_handshaker.accept(socket).await {

                Ok(mut tls_stream) => {

                    if let Err(error) = handle_conn(&mut tls_stream, &ldap_connector).await {
                        tracing::error!("{} - {} - {}", peer_ip, 500, error);
                    }
                },
                Err(error) => {
                    if error.to_string().starts_with("invalid peer certificate") {
                        tracing::error!("{} - {} - mTLS handshake failed - {}", peer_ip, 526, logging::format_error_chain(&error));
                    }

                    else {
                        tracing::error!("{} - {} - mTLS handshake failed - {}", peer_ip, 525, logging::format_error_chain(&error));
                    }

                }
            }
        });

    }

}

async fn handle_conn(stream: &mut TlsStream<TcpStream>, ldap_connector: &Arc<dyn LdapBackend>) -> Result<()> {

    let peer_addr = stream.get_ref().0.peer_addr().context("Could not get the peer address")?.ip();

    let (body_str, endpoint, bytes_read) = match parse_http_request(stream).await? {
        ParseOutcome::Handled(code, endpoint, method, bytes_read) => {
            if code == 400 || code == 411 || code == 413 {
                tracing::warn!("{} - {} - {} {} - {}", peer_addr, code, method, endpoint, bytes_read);
            }

            else {
                tracing::info!("{} - {} - {} {} - {}", peer_addr, code, method, endpoint, bytes_read);
            }

            return Ok(());
        },
        ParseOutcome::Body(body, endpoint, bytes_read) => (body, endpoint, bytes_read),
    };

    let token_review_str = tokio::select! {
        token_review_str = handle_tokenreview_request(&body_str, &ldap_connector) => {
            token_review_str
        }

        _ = _check_remote_peer(stream, &peer_addr, endpoint.clone()) => {
            return Ok(());
        }
    };

    _verify_token_review_str_result(token_review_str, stream, endpoint, peer_addr, bytes_read).await

}

async fn parse_http_request(stream: &mut TlsStream<TcpStream>) -> Result<ParseOutcome> {

    const MAX_SIZE_PAYLOAD : usize = 65536;
    let mut buffer = [0u8 ; 4096];
    let mut raw_request = Vec::new();

    let header_end: usize;
    
    loop {

        let bytes_read = stream.read(&mut buffer).await?;

        if bytes_read == 0 {
            return Ok(ParseOutcome::Handled(204, "UNKNOWN".to_string(), "UNKNOWN".to_string(), 0))
        }

        let old_len = raw_request.len();

        raw_request.extend_from_slice(&buffer[..bytes_read]);

        let start = old_len.saturating_sub(3);

        if let Some(pos) = raw_request[start..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
        {

            header_end = start + pos + 4;

            break;

        }

        if raw_request.len() > MAX_SIZE_PAYLOAD {

            _send_response(stream, 413, b"").await?;

            return Ok(ParseOutcome::Handled(413, "UNKNOWN".to_string(), "UNKNOWN".to_string(), raw_request.len()));

        }

    }

    let request_str = String::from_utf8_lossy(&raw_request[..header_end]);

    let (method, endpoint) =
        request_str
        .lines()
        .next()
        .and_then(|line| {
            let method = line.split(' ').nth(0).unwrap_or("UNKNOWN");
            let endpoint = line.split(' ').nth(1).map(|endpoint| {
                if !endpoint.starts_with('/') {
                    let endpoint= String::from("/") + endpoint;
                    endpoint
                }
                else {
                    endpoint.to_string()
                }
            }).unwrap_or("UNKNOWN".to_string());

            Some((method.to_string(), endpoint))
        })
        .unwrap_or(("UNKNOWN".to_string(), "UNKNOWN".to_string()));

    if endpoint == "UNKNOWN" {
        _send_response(stream, 400, b"", ).await?;
        return Ok(ParseOutcome::Handled(400, endpoint, method, raw_request.len() - header_end));
    }

    else if endpoint != "/authenticate" {
        _send_response(stream, 404, b"").await?;
        return Ok(ParseOutcome::Handled(404, endpoint, method, raw_request.len() - header_end));
    }

    else if method != "POST" {
        _send_response(stream, 405, b"").await?;
        return Ok(ParseOutcome::Handled(405, endpoint, method, raw_request.len() - header_end));
    }

    let content_length: Option<usize> = request_str
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|length| length.trim().parse::<usize>().ok())
        .or(None);

    if let Some(content_length) = content_length {

        if content_length > MAX_SIZE_PAYLOAD {
            _send_response(stream, 413, b"").await?;
            return Ok(ParseOutcome::Handled(413, endpoint, method, raw_request.len() - header_end));
        }

        let already_read_from_body = raw_request.len() - header_end;

        if already_read_from_body < content_length {

            let remaining = content_length - already_read_from_body;
            let mut buffer = vec![0u8; remaining];
            stream.read_exact(&mut buffer).await?;
            raw_request.extend_from_slice(&buffer);

        }

        let body_str =
            String::from_utf8_lossy(
                &raw_request[header_end..header_end + content_length]
            )
            .into_owned();

        Ok(ParseOutcome::Body(body_str, endpoint, content_length))

    }

    else {
        _send_response(stream, 411, b"").await?;
        return Ok(ParseOutcome::Handled(411, endpoint, method, header_end));
    }

}

async fn _check_remote_peer(stream: &mut TlsStream<TcpStream>, peer_addr: &IpAddr, endpoint: String) -> Result<()> {

    const MAX_SIZE_PAYLOAD : usize = 65536;

    let mut buffer = [0u8; MAX_SIZE_PAYLOAD];

    match stream.get_mut().0.read(&mut buffer).await {

        Ok(0) => {

            tracing::info!("{} - {} - {}", peer_addr, 499, endpoint);
            stream.shutdown().await?;
            Ok(())

        },

        Ok(_) => Ok(()),

        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock  => Ok(()),

        Err(error) => {

            tracing::error!("{} - {} - {}", peer_addr, 499, endpoint);
            stream.shutdown().await?;
            return Err(error.into());

        }

    }

}

async fn _verify_token_review_str_result(
    token_review_str: Result<(String, String, bool)>,
    stream: &mut TlsStream<TcpStream>,
    endpoint: String,
    peer_addr: IpAddr,
    bytes_read: usize
) -> Result<()>
{

    match token_review_str {

        Ok((token_review_str, user, is_authenticated)) => {

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                token_review_str.len(),
                token_review_str
            )
            .into_bytes();

            if let Err(error) =
                _send_response(
                    stream, 200, &response
                )
                .await
            {
                return Err(
                    anyhow::Error::msg(
                        format!(
                            "- {} - {} - Failed to send response - {}",
                            endpoint,
                            user,
                            logging::format_error_chain(&*error)
                        )
                    )
                );
            }

            if is_authenticated {
                tracing::info!("{} - 200 - POST {} - {} - {} - SUCCESS", peer_addr, endpoint, bytes_read, user);
            }

            else {
                tracing::info!("{} - 200 - POST {} - {} - {} - FAIL", peer_addr, endpoint, bytes_read, user);
            }

            Ok(())

        }

        Err(error) if error.to_string().starts_with("Error") => {

            if let Err(error) =
                _send_response(
                    stream, 400, b""
                )
                .await
            {
                return Err(
                    anyhow::Error::msg(
                        format!(
                            "- {} - Failed to send response - {}",
                            endpoint,
                            logging::format_error_chain(&*error)
                        )
                    )
                );
            }

            tracing::warn!("{} - 400 - POST {} - {} - ERROR - {}", peer_addr, endpoint, bytes_read, logging::format_error_chain(&*error));

            Ok(())

        },

        Err(error) => {

            if let Err(error) =
                _send_response(
                    stream, 500, b""
                )
                .await
            {
                return Err(
                    anyhow::Error::msg(
                        format!(
                            "- {} - Failed to send response - {}",
                            endpoint,
                            logging::format_error_chain(&*error)
                        )
                    )
                );
            }

            tracing::error!("{} - 500 - POST {} - {} - ERROR - {}", peer_addr, endpoint, bytes_read, logging::format_error_chain(&*error));

            Ok(())

        }

    }

}

async fn _send_response(stream: &mut TlsStream<TcpStream>, code: u16, response: &[u8]) -> Result<()> {

    let response: &[u8] = match code {

        200 => response,
        400 => b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
        404 => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        405 => b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
        411 => b"HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\n\r\n",
        413 => b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n",
        500 => b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
        _ => b""

    };

    stream.write_all(response).await?;
    stream.flush().await?;
    stream.shutdown().await?;

    Ok(())

}

#[cfg(test)]
mod tests {

    use pretty_assertions::assert_eq;
    use rstest::*;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::client::{TlsConnector, TlsStream};
    use rustls_pki_types::ServerName;
    use tokio::runtime::Runtime;
    use tokio::sync::OnceCell;
    use tokio::time::sleep;
    use async_trait::async_trait;
    use ldap3::SearchEntry;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::collections::HashMap;
    use std::env::temp_dir;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::time::Duration;
    use dtor::*;
    use port_selector::random_free_tcp_port;

    use super::*;

    struct LdapTest {
        result: Result<SearchEntry, String>,
        attrs: HashMap<String, String>
    }

    #[async_trait]
    impl LdapBackend for LdapTest {

        async fn search_user(&self, _user: &str, _pass: &str) -> anyhow::Result<SearchEntry> {

            self.result
                .as_ref()
                .map(|e| e.clone())
                .map_err(|e| anyhow::anyhow!(e.clone()))

        }

        fn get_attrs(&self) -> &HashMap<String, String> {

            &self.attrs

        }

    }

    struct LdapTestPeerReset {
        result: Result<SearchEntry, String>,
        attrs: HashMap<String, String>
    }

    #[async_trait]
    impl LdapBackend for LdapTestPeerReset {

        async fn search_user(&self, _user: &str, _pass: &str) -> anyhow::Result<SearchEntry> {

            sleep(Duration::from_secs(5)).await; // Simulates server not responding

            self.result
                .as_ref()
                .map(|e| e.clone())
                .map_err(|e| anyhow::anyhow!(e.clone()))

        }

        fn get_attrs(&self) -> &HashMap<String, String> {

            &self.attrs

        }

    }

    fn make_entry(dn: &str, attrs: HashMap<String, Vec<String>>) -> SearchEntry {

        SearchEntry {
            dn: dn.to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        }

    }

    #[fixture]
    #[once]
    fn get_ldap_test() -> Arc<LdapTest> {

        let attrs = HashMap::from(
            [
                (
                    "cn".to_string(),
                    vec![
                        "John Doe".to_string()
                    ]
                ),
                (
                    "givenName".to_string(),
                    vec![
                        "John".to_string()
                    ]
                ),
                (
                    "memberOf".to_string(),
                    vec![
                        "cn=group1,cn=groups,cn=accounts,dc=example,dc=test".to_string(),
                        "cn=group2,cn=groups,cn=accounts,dc=example,dc=test".to_string()
                    ]
                ),
                (
                    "uid".to_string(),
                    vec!["johndoe".to_string()]
                )
            ]

        );

        Arc::new(
            LdapTest {

                result: Ok(make_entry("uid=johndoe,cn=users,cn=accounts,dc=example,dc=test", attrs)),
                attrs: HashMap::from(
                    [
                        ("k8s_extra_cn".to_string(), "cn".to_string()),
                        ("k8s_extra_givenName".to_string(), "givenName".to_string()),
                        ("groups".to_string(), "memberOf".to_string())
                    ]
                )

            }
        )

    }

    #[fixture]
    fn get_target_addr() -> String {

        format!("{}:{}", "127.0.0.1", get_server_test())

    }

    #[fixture]
    async fn get_client_config() -> Result<ClientConfig> {

        get_cert_key_test().await;

        let mut ca_root_store = RootCertStore::empty();

        let cert_path =
            PathBuf::from(temp_dir())
            .join("webhook-server.pem")
            .to_string_lossy()
            .into_owned();

        let key_path =
            PathBuf::from(temp_dir())
            .join("webhook-server.key")
            .to_string_lossy()
            .into_owned();

        ca_root_store.add(
            CertificateDer::from_pem_file(
                cert_path.clone()
            )?
        )?;

        Ok(ClientConfig::builder()
        .with_root_certificates(ca_root_store)
        .with_client_auth_cert(
            vec![
                CertificateDer::from_pem_file(cert_path).unwrap()
            ],
            PrivateKeyDer::from_pem_file(key_path).unwrap()
        )?)

    }

    #[fixture]
    async fn get_tls_stream(
        get_target_addr: String,
        #[future] get_client_config: Result<ClientConfig>
    ) -> Result<TlsStream<TcpStream>>
    {

        let target_addr = get_target_addr;

        get_tls_connector(target_addr, get_client_config.await?).await

    }

    /*
        Since we're running a server in a thread,
        if we use #[tokio::test] the runtime will be dropped
        and it will also drop the spawned thread.
        Therefore, with SERVER and RUNTIME locks we keep
        both the runtime and server available throughout
        all the tests.
    */

    #[macro_export]
    macro_rules! run_async_test {

        ($($body:tt)*) => {{

            let rt = get_runtime();

            get_server_test();

            rt.block_on(async move {
                $($body)*
            })

        }};

    }

    static SERVER: OnceLock<u16> = OnceLock::new();
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    static CERTS: OnceCell<Result<()>> = OnceCell::const_new();

    async fn wait_server_is_alive(random_port: u16) {

        for _ in 0..100 {
            if TcpStream::connect(format!("127.0.0.1:{random_port}")).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

    }

    async fn get_cert_key_test() -> &'static Result<()> {

        CERTS.get_or_init(|| async {

                let subject_alt_names =
                    vec![
                        "0.0.0.0".to_string(),
                        "localhost".to_string(),
                        "127.0.0.1".to_string()
                    ];

                let CertifiedKey { cert, signing_key } =
                    generate_simple_self_signed(subject_alt_names).unwrap();

                let cert_path = PathBuf::from(temp_dir()).join("webhook-server.pem");

                let key_path = PathBuf::from(temp_dir()).join("webhook-server.key");

                let mut cert_file = File::create(cert_path)?;
                let mut key_file = File::create(key_path)?;

                cert_file.write_all(cert.pem().as_bytes())?;
                key_file.write_all(signing_key.serialize_pem().as_bytes())?;

                Ok(())

            }
        ).await

    }

    fn get_runtime() -> &'static Runtime {

        RUNTIME.get_or_init(|| {
                Runtime::new().expect("Failed to create global Tokio runtime")
            }
        )

    }

    fn get_server_test() -> u16 {

        let rt = get_runtime();

        *SERVER.get_or_init(
            || {

                rt.block_on(async {

                        get_cert_key_test().await;

                        let random_port = random_free_tcp_port().unwrap();

                        let cert_path = PathBuf::from(temp_dir()).join("webhook-server.pem");
                        let key_path = PathBuf::from(temp_dir()).join("webhook-server.key");

                        tokio::spawn(async move {

                                start_server(String::from("127.0.0.1"),
                                    random_port,
                                    String::from(key_path.to_string_lossy().into_owned()),
                                String::from(cert_path.to_string_lossy().into_owned()),
                                String::from(cert_path.to_string_lossy().into_owned()),
                                get_ldap_test()
                                ).await
                            }
                        );

                        wait_server_is_alive(random_port).await;

                        random_port

                    }
                )
            }
        )

    }

    async fn get_tls_connector(target_addr: String, config: ClientConfig) -> Result<TlsStream<TcpStream>> {

        let arc_config = Arc::new(config);

        let server_name = ServerName::try_from("127.0.0.1")?;

        let sock = TcpStream::connect(target_addr).await?;

        let connector = TlsConnector::from(arc_config);

        match connector.connect(server_name, sock).await {
            Ok(tls_stream) => Ok(tls_stream),
            Err(error) => Err(error.into())
        }

    }

    async fn get_response(request: &str, mut tls_stream: TlsStream<TcpStream>) -> Result<Vec<u8>> {

        tls_stream.write_all(request.as_bytes()).await?;
        tls_stream.flush().await?;

        let mut buffer = vec![0u8; 4096];
        let mut response = Vec::with_capacity(4096);

        loop {

            match tls_stream.read(&mut buffer).await {

                Ok(0) => break,

                Ok(read) => {

                    response.extend_from_slice(&buffer[..read]);

                },

                Err(e) => return Err(e.into()),

            }

        };

        Ok(response.to_vec())

    }

    fn get_request_for_test(token: &str) -> String {

        let payload = format!(
            r#"
                {{
                    "apiVersion":"authentication.k8s.io/v1",
                    "kind":"TokenReview",
                    "spec":{{
                        "token":"{}",
                        "audiences": ["https://example.test", "https://internal.example.test"]
                    }}
                }}
            "#,
            token
        );

        format!(
            "POST /authenticate HTTP/1.1\r\n\
            Host: 127.0.0.1\r\n\
            Connection: close\r\n\
            Content-Length: {}\r\n\r\n{}",
            payload.len(),
            payload
        )

    }

    #[rstest]
    fn test_server_404(#[future] get_tls_stream: Result<TlsStream<TcpStream>>) -> Result<()> {

        run_async_test!(

            let tls_stream = get_tls_stream.await?;

            let request = format!(
                "GET / HTTP/1.1\r\n\
                Host: 127.0.0.1\r\n\
                Connection: close\r\n\r\n"
            );

            let response = get_response(&request, tls_stream).await?;

            assert_eq!(response, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");

            Ok(())

        )

    }

    #[rstest]
    fn test_server_valid_user(#[future] get_tls_stream: Result<TlsStream<TcpStream>>) {

        run_async_test!(

            let tls_stream = get_tls_stream.await.unwrap();

            let request = get_request_for_test("am9obmRvZTpwYXNzd29yZA==");

            let response = get_response(&request, tls_stream).await.unwrap();

            let expected = "\
                HTTP/1.1 200 OK\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 295\r\n\r\n\
                {\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\
                \"metadata\":{},\"spec\":{},\"status\":{\"audiences\":\
                [\"https://example.test\",\"https://internal.example.test\"],\
                \"authenticated\":true,\"user\":{\"extra\":{\"cn\":[\"John Doe\"],\
                \"givenName\":[\"John\"]},\"groups\":[\"group1\",\"group2\"],\
                \"username\":\"johndoe\"}}}\
            ";

            assert_eq!(String::from_utf8(response).unwrap(), String::from(expected));

        )

    }

    #[rstest]
    fn test_server_413(#[future] get_tls_stream: Result<TlsStream<TcpStream>>) -> Result<()> {

        run_async_test!(

            let tls_stream = get_tls_stream.await?;

            let request = b"POST /authenticate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length:69004\r\n\r\n";

            let big_payload = vec![0u8; 69000];

            let request = String::from_utf8([request, big_payload.as_slice(), b"\r\n\r\n"].concat()).unwrap();

            let response = get_response(&request, tls_stream).await?;

            assert_eq!(response, b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n");

            Ok(())

        )

    }

    #[rstest]
    fn test_server_411(#[future] get_tls_stream: Result<TlsStream<TcpStream>>) -> Result<()> {

        run_async_test!(

            let tls_stream = get_tls_stream.await?;

            let request = "POST /authenticate HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

            let response = get_response(&request, tls_stream).await?;

            assert_eq!(response, b"HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\n\r\n");

            Ok(())

        )

    }

    #[rstest]
    fn test_server_400(#[future] get_tls_stream: Result<TlsStream<TcpStream>>) -> Result<()> {

        run_async_test!(

            let tls_stream = get_tls_stream.await?;

            let request = get_request_for_test("am9obmRvZTpwYXNzd2"); // Malformed token

            let response = get_response(&request, tls_stream).await?;

            assert_eq!(response, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");

            Ok(())

        )

    }

    #[rstest]
    fn test_server_reset_peer(#[future] get_client_config: Result<ClientConfig>) -> Result<()> {

        run_async_test!(

            let random_port =  random_free_tcp_port().unwrap();

            let cert_path = PathBuf::from(temp_dir()).join("webhook-server.pem");
            let key_path = PathBuf::from(temp_dir()).join("webhook-server.key");

            let ldap_connector_sleep = Arc::new(LdapTestPeerReset {
                result: Ok(make_entry("uid=johndoe,cn=users,cn=accounts,dc=example,dc=test", HashMap::new())),
                attrs: HashMap::new()
            });

            tokio::spawn(start_server(String::from("127.0.0.1"),
                random_port,
                String::from(key_path.to_string_lossy().into_owned()),
                String::from(cert_path.to_string_lossy().into_owned()),
                String::from(cert_path.to_string_lossy().into_owned()),
                ldap_connector_sleep
            ));

            wait_server_is_alive(random_port).await;

            let target_addr = format!("{}:{}", "127.0.0.1", random_port);

            let config = get_client_config.await?;

            let mut tls_stream = get_tls_connector(target_addr, config).await?;

            let request = get_request_for_test("dGhpYWdvY2FzdHJvbzp0ZXN0ZQ==");

            tls_stream.write_all(request.as_bytes()).await?;
            tls_stream.shutdown().await?;

            assert_eq!(tls_stream.read(vec![0u8; 4096].as_mut_slice()).await?, 0);

            Ok(())

        )

    }

    #[rstest]
    #[tokio::test]
    async fn test_server_invalid_tls_params() {

        let handle = start_server(String::from("127.0.0.1"),
            0,
            String::from("webhook-server.keyy"),
            String::from("webhook-server.pem."),
            String::from("ca.crt"),
            get_ldap_test()
        ).await;

        assert!(handle.is_err());

    }

    #[rstest]
    fn test_server_invalid_mtls_no_cert() -> Result<()> {

        run_async_test!(

            let target_addr = format!("{}:{}", "127.0.0.1", get_server_test());

            let cert_path =
                PathBuf::from(temp_dir())
                .join("webhook-server.pem")
                .to_string_lossy()
                .into_owned();

            let mut ca_root_store = RootCertStore::empty();

            ca_root_store.add(CertificateDer::from_pem_file(cert_path)?)?;

            let config =
                ClientConfig::builder()
                .with_root_certificates(ca_root_store)
                .with_no_client_auth();


            let mut connection = get_tls_connector(target_addr, config).await?;

            assert!(connection.read(&mut vec![0u8;10]).await.is_err());

            Ok(())

        )

    }

    #[dtor(unsafe)]
    fn remove_pem_files() {

        if let Some(_) = CERTS.get() {

            let cert_path = PathBuf::from(temp_dir()).join("webhook-server.pem");

            let key_path = PathBuf::from(temp_dir()).join("webhook-server.key");

            let _ = std::fs::remove_file(cert_path);
            let _ = std::fs::remove_file(key_path);

        }

    }

}