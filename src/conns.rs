use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::env::var;
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
use crate::ldap::LdapConnector;

enum ParseOutcome {
    Body(String),
    Handled(String),
}

fn load_cert(env_var: &str, path: &str) -> Result<CertificateDer<'static>, Error> {

    let path = var(env_var).unwrap_or(path.to_string());

    CertificateDer::from_pem_file(path)
}

fn load_key() -> Result<PrivateKeyDer<'static>, Error> {

    let path = var("K8S_LDAP_AUTH_KEY_PATH")
            .unwrap_or("./pki/webhook-server.key".to_string());

    PrivateKeyDer::from_pem_file(path)
}

fn set_tls() -> Result<TlsAcceptor> {

    let ca_cert = load_cert("K8S_LDAP_AUTH_CA_CERT_PATH",
                                "./pki/ca.crt").context("Could not load the CA certificate")?;

    let server_cert = load_cert("K8S_LDAP_AUTH_CERT_PATH",
                                    "./pki/webhook-server.pem").context("Could not load the certificate for mTLS")?;

    let key = load_key().context("Could not load the key for mTLS")?;

    let mut ca_root_store = RootCertStore::empty();

    ca_root_store.add(ca_cert)?;

    let client_cert_verifier = WebPkiClientVerifier::builder(
        ca_root_store.into())
        .build()?;

    let server_tls_config = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(vec![server_cert], key)?;

    // TLS configured both for accept clients' certs signed with the CA provided
    // and to serve the cert and key pair

    Ok(TlsAcceptor::from(Arc::new(server_tls_config)))

}

pub async fn start_server(address: &str, port: u16) -> Result<String> {

    let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from_str(address)
                        .unwrap_or(Ipv4Addr::new(0,0,0,0))),
            port);

    let tls_handshaker = set_tls()?;

    let listener = TcpListener::bind(&addr).await.context("Could not listen at the provided socket")?;

    let ldap_connector = Arc::new(LdapConnector::new()?);

    println!("Listening on {addr}");

    loop {

        let (socket, socket_addr) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => { eprintln!("Could not start connection with {}", error); continue;}
        };

        let tls_handshaker = tls_handshaker.clone();
        let ldap_connector = ldap_connector.clone();

        tokio::spawn(async move {
            match tls_handshaker.accept(socket).await {
                Ok(mut tls_stream) => {
                    let _ = handle_conn(&mut tls_stream, &ldap_connector).await;
                },
                Err(error) => {
                    eprintln!{"mTLS handshake error on connection {}. Error: {}", socket_addr, error.to_string()};
                }
            }
        });

    }
}

async fn handle_conn(stream: &mut TlsStream<TcpStream>, ldap_connector: &Arc<LdapConnector>) -> Result<()> {

    let peer_addr = stream.get_ref().0.peer_addr()?;

    let body_str = match parse_http_request(stream, &peer_addr).await? {
        ParseOutcome::Handled(msg) => {
            println!("{msg}");
            return Ok(());
        },
        ParseOutcome::Body(body) => body,
    };

    let token_review_str = tokio::select! {
        token_review_str = handle_tokenreview_request(&body_str, &ldap_connector) => {
            token_review_str
        }

        _ = check_remote_peer( stream, &peer_addr) => {
            return Ok(());
        }
    };

    match token_review_str {

        Ok(token_review_str) => {

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                token_review_str.len(),
                token_review_str
            );
            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
            println!("Connection {} closed with HTTP 200 status", peer_addr);
            Ok(())
            
        }
        Err(error) if error.to_string().starts_with("Error") => {

            let response = format!("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
            eprint!("Connection {} closed with HTTP 400 status; ", peer_addr);
            for cause in error.chain() {
                eprint!("{}; ", cause);
            }
            eprintln!("");
            Ok(())

        },
        Err(error) => {
            
            let response = format!("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
            eprintln!("Connection {} closed with HTTP 500 status; ", peer_addr);
            for cause in error.chain() {
                eprint!("{}; ", cause);
            }
            eprintln!("");
            Ok(())

        }

    }

}

async fn parse_http_request(stream: &mut TlsStream<TcpStream>, peer_addr: &SocketAddr) -> Result<ParseOutcome> {

    const MAX_SIZE_PAYLOAD : usize = 65536;
    let mut buffer = [0u8 ; 4096];
    let mut raw_request = Vec::new();

    let header_end: usize;
    
    loop {
        let bytes_read = stream.read(&mut buffer).await?;

        if bytes_read == 0 {
            return Ok(ParseOutcome::Handled(format!("Read 0 bytes from connection {}", peer_addr)))
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
            stream.write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n").await?;
            stream.flush().await?;
            return Ok(ParseOutcome::Handled(format!("Connection {} sent oversized headers", peer_addr)));
        }
    }

    let request_str = String::from_utf8_lossy(&raw_request[..header_end]);

    if !request_str.starts_with("POST /authenticate ") {
        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?;
        stream.flush().await?;
        return Ok(ParseOutcome::Handled(format!("Connection {} closed with HTTP 404 status", peer_addr)));
    }

    let content_length: usize = request_str
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|length| length.trim().parse().ok())
        .unwrap_or(0);

    if content_length > MAX_SIZE_PAYLOAD {
        stream.write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n").await?;
        stream.flush().await?;
        return Ok(ParseOutcome::Handled(format!("Connection {} sent oversized body", peer_addr)));
    }

    let already_read_from_body = raw_request.len() - header_end;

    if already_read_from_body < content_length {
        let remaining = content_length - already_read_from_body;
        let mut buffer = vec![0u8; remaining];
        stream.read_exact(&mut buffer).await?;
        raw_request.extend_from_slice(&buffer);
    }

    let body_str = String::from_utf8_lossy(&raw_request[header_end..header_end + content_length]).into_owned();

    Ok(ParseOutcome::Body(body_str))

}

async fn check_remote_peer(stream: &mut TlsStream<TcpStream>, peer_addr: &SocketAddr) -> Result<()> {

    const MAX_SIZE_PAYLOAD : usize = 65536;

    let mut buffer = [0u8; MAX_SIZE_PAYLOAD];

    match stream.get_mut().0.read(&mut buffer).await {

        Ok(0) => {
            println!("Connection {} closed by the remote peer", peer_addr);
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock  => Ok(()),
        Err(error) => {
            println!("Connection {} reset", peer_addr);
            return Err(error.into());
        }

    }

}