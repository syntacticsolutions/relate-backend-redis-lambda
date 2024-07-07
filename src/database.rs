use dotenv::dotenv;
use redis::{aio::MultiplexedConnection, Client, RedisError};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::Error;
use std::env;
use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};

use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::rustls::{
    client::ServerName, Certificate, ClientConfig, PrivateKey, RootCertStore,
};
use url::Url;

pub struct RedisConfig {
    redis_client: Client,
    tls_connector: TlsConnector,
    redis_url: String,
}

// Custom verifier that skips server name validation
struct NoServerNameVerification;

impl ServerCertVerifier for NoServerNameVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
}

fn load_certificates(path: &str) -> io::Result<Vec<Certificate>> {
    let cert_file = File::open(path)?;
    let mut reader = BufReader::new(cert_file);
    let certs = certs(&mut reader)?;
    let certs: Vec<Certificate> = certs.into_iter().map(Certificate).collect();

    Ok(certs)
}

fn load_private_key(path: &str) -> io::Result<PrivateKey> {
    let key_file = File::open(path)?;
    let mut reader = BufReader::new(key_file);
    let keys = pkcs8_private_keys(&mut reader)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid PKCS8 private key"))?;

    if !keys.is_empty() {
        Ok(PrivateKey(keys[0].clone()))
    } else {
        let rsa_keys = rsa_private_keys(&mut reader)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid RSA private key"))?;
        if !rsa_keys.is_empty() {
            Ok(PrivateKey(rsa_keys[0].clone()))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No valid private keys found",
            ))
        }
    }
}

pub fn initialize_redis() -> Arc<RedisConfig> {
    dotenv().ok();

    let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");
    let ca_cert_path = env::var("CA_CERT_PATH").expect("CA_CERT_PATH must be set");
    let client_cert_path = env::var("CLIENT_CERT_PATH").expect("CLIENT_CERT_PATH must be set");
    let client_key_path = env::var("CLIENT_KEY_PATH").expect("CLIENT_KEY_PATH must be set");
    let redis_password = env::var("REDIS_PASSWORD").expect("REDIS_PASSWORD must be set");

    // Parse the URL and append the password if necessary
    let mut redis_url_with_auth = Url::parse(&redis_url).expect("Invalid REDIS_URL format");
    if redis_url_with_auth.username().is_empty() {
        redis_url_with_auth
            .set_username("default")
            .expect("Failed to set username");
    }
    redis_url_with_auth
        .set_password(Some(&redis_password))
        .expect("Failed to set password");

    let redis_client =
        Client::open(redis_url_with_auth.as_str()).expect("Problem connecting to Redis.");
    let tls_connector = get_tls_connector(&ca_cert_path, &client_cert_path, &client_key_path);

    Arc::new(RedisConfig {
        redis_client,
        tls_connector,
        redis_url: redis_url,
    })
}

fn get_tls_connector(
    ca_cert_path: &str,
    client_cert_path: &str,
    client_key_path: &str,
) -> TlsConnector {
    // Load CA certificates
    let mut root_cert_store = RootCertStore::empty();
    let ca_cert_file =
        std::fs::File::open(ca_cert_path).expect("Failed to open CA certificate file");
    let mut reader = std::io::BufReader::new(ca_cert_file);
    let ca_certs = rustls_pemfile::certs(&mut reader).expect("Failed to read CA certificates");
    for cert in ca_certs {
        root_cert_store
            .add(&Certificate(cert))
            .expect("Failed to add CA certificate");
    }

    // Load client certificate and key
    let client_certs =
        load_certificates(client_cert_path).expect("Failed to load client certificates");
    let client_key = load_private_key(client_key_path).expect("Failed to load client key");

    // Custom verifier that skips server name validation
    let verifier = NoServerNameVerification {};

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_single_cert(client_certs, client_key)
        .expect("Failed to configure client certificates");

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(verifier));

    TlsConnector::from(Arc::new(config))
}

pub async fn get_secure_connection(
    config: Arc<RedisConfig>,
) -> Result<MultiplexedConnection, RedisError> {
    let client = config.redis_client.clone();
    let connector = config.tls_connector.clone();

    // Extract host and port from the redis_url
    let url = url::Url::parse(&config.redis_url).expect("Invalid Redis URL");
    let host = url.host_str().expect("Invalid host in Redis URL");
    let port = url.port().unwrap_or(6379);

    // Create a TCP connection to the Redis server
    let tcp_stream = TcpStream::connect((host, port)).await?;

    // Convert host to ServerName
    // Convert host to ServerName
    let server_name = match ServerName::try_from(host) {
        Ok(name) => name,
        Err(_) => {
            return Err(RedisError::from((
                redis::ErrorKind::IoError,
                "Invalid server name",
            )));
        }
    };

    // Upgrade the TCP connection to a TLS connection
    match connector.connect(server_name, tcp_stream).await {
        Ok(tls_stream) => {
            // Create Redis connection info
            let connection_info = client.get_connection_info();
            let redis_connection_info = connection_info.redis.clone();

            // Create a Redis connection using the TLS stream
            match redis::aio::MultiplexedConnection::new(&redis_connection_info, tls_stream).await {
                Ok((connection, driver)) => {
                    // Spawn the driver to run in the background
                    tokio::spawn(driver);
                    Ok(connection)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e.into()),
    }
}
