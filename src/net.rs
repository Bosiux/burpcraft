//! HTTP/1.x framing, upstream connections (plain + TLS) and the MITM certificate authority.
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

pub trait Stream: Read + Write + Send {
    /// Read timeout on the underlying socket (used to multiplex WebSocket relays).
    fn set_timeout(&self, d: Option<Duration>);
}
impl Stream for TcpStream {
    fn set_timeout(&self, d: Option<Duration>) {
        let _ = self.set_read_timeout(d);
    }
}
impl Stream for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_timeout(&self, d: Option<Duration>) {
        let _ = self.sock.set_read_timeout(d);
    }
}
impl Stream for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    fn set_timeout(&self, d: Option<Duration>) {
        let _ = self.sock.set_read_timeout(d);
    }
}
impl Stream for Box<dyn Stream> {
    fn set_timeout(&self, d: Option<Duration>) {
        (**self).set_timeout(d)
    }
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Value of the first header called `name` (case-insensitive) in a message head.
pub fn header(msg: &str, name: &str) -> Option<String> {
    msg.split("\r\n\r\n")
        .next()?
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
}

/// Reads exactly one HTTP message (head + body), honouring its framing, and returns the raw bytes.
pub fn read_message<R: BufRead>(
    r: &mut R,
    is_response: bool,
    head_request: bool,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let n = r.read_until(b'\n', &mut out)?;
        if n == 0 {
            return if out.is_empty() {
                Err(io::ErrorKind::UnexpectedEof.into())
            } else {
                Ok(out)
            };
        }
        if out == b"\r\n" || out == b"\n" {
            out.clear(); // stray CRLF between pipelined messages
            continue;
        }
        if out.ends_with(b"\r\n\r\n") || out.ends_with(b"\n\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&out).into_owned();
    if is_response {
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if head_request || status / 100 == 1 || status == 204 || status == 304 {
            return Ok(out);
        }
    }
    if header(&head, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        loop {
            let start = out.len();
            r.read_until(b'\n', &mut out)?;
            let line = String::from_utf8_lossy(&out[start..]).into_owned();
            let size =
                usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
            if size == 0 {
                loop {
                    let s = out.len();
                    if r.read_until(b'\n', &mut out)? == 0 || out[s..].trim_ascii().is_empty() {
                        break;
                    }
                }
                break;
            }
            let s = out.len();
            out.resize(s + size, 0);
            r.read_exact(&mut out[s..])?;
            r.read_until(b'\n', &mut out)?;
        }
    } else if let Some(len) = header(&head, "content-length").and_then(|v| v.parse::<usize>().ok())
    {
        let s = out.len();
        out.resize(s + len, 0);
        r.read_exact(&mut out[s..])?;
    } else if is_response {
        // close-delimited body; servers often skip TLS close_notify, so a truncation EOF is fine
        if let Err(e) = r.read_to_end(&mut out)
            && e.kind() != io::ErrorKind::UnexpectedEof
        {
            return Err(e);
        }
    }
    Ok(out)
}

#[derive(Debug)]
struct AcceptAll(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn client_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let p = provider();
        // a testing proxy must reach hosts with broken certs, like the original does
        let mut c = rustls::ClientConfig::builder_with_provider(p.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAll(p)))
            .with_no_client_auth();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(c)
    })
    .clone()
}

/// HTTPS with full certificate verification (Mozilla roots), for BurpCraft's own calls that carry
/// secrets (API keys) - unlike `connect`, which must accept any certificate to test targets.
pub fn send_verified(host: &str, req: &[u8]) -> io::Result<Vec<u8>> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let cfg = CFG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let mut c = rustls::ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            c.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(c)
        })
        .clone();
    let tcp = TcpStream::connect((host, 443))?;
    tcp.set_read_timeout(Some(Duration::from_secs(300)))?;
    let conn =
        rustls::ClientConnection::new(cfg, ServerName::try_from(host.to_string()).map_err(io_err)?)
            .map_err(io_err)?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    s.write_all(req)?;
    s.flush()?;
    read_message(&mut BufReader::new(s), true, false)
}

pub fn connect(host: &str, port: u16, tls: bool) -> io::Result<Box<dyn Stream>> {
    let tcp = TcpStream::connect((host, port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    tcp.set_nodelay(true).ok();
    if !tls {
        return Ok(Box::new(tcp));
    }
    let name = ServerName::try_from(host.to_string()).map_err(io_err)?;
    let conn = rustls::ClientConnection::new(client_config(), name).map_err(io_err)?;
    Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
}

/// True when the request line asks for HTTP/2 (`GET / HTTP/2`).
pub fn is_h2(req: &[u8]) -> bool {
    req.split(|&b| b == b'\n')
        .next()
        .is_some_and(|l| l.trim_ascii_end().ends_with(b" HTTP/2"))
}

/// Sends a raw request and returns the raw response. `HTTP/2` request lines over TLS go out as h2.
pub fn send(host: &str, port: u16, tls: bool, req: &[u8]) -> io::Result<Vec<u8>> {
    if is_h2(req) {
        if !tls {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HTTP/2 requires HTTPS (h2c is not supported)",
            ));
        }
        return crate::h2up::send(host, port, req);
    }
    let mut s = connect(host, port, tls)?;
    s.write_all(req)?;
    s.flush()?;
    read_message(&mut BufReader::new(s), true, req.starts_with(b"HEAD "))
}

/// Like [`send`], but keeps the connection for protocol upgrades (WebSockets).
pub fn send_keep(
    host: &str,
    port: u16,
    tls: bool,
    req: &[u8],
) -> io::Result<(Vec<u8>, BufReader<Box<dyn Stream>>)> {
    let mut s = connect(host, port, tls)?;
    s.write_all(req)?;
    s.flush()?;
    let mut r = BufReader::new(s);
    let resp = read_message(&mut r, true, false)?;
    Ok((resp, r))
}

// ---------------------------------------------------------------- MITM CA

pub struct Ca {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    leaf_key: rcgen::KeyPair,
    pub cert_pem: String,
    pub cert_der: CertificateDer<'static>,
    cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

pub fn data_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_default();
    PathBuf::from(home).join(".burpcraft")
}

fn ca_params() -> rcgen::CertificateParams {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.distinguished_name
        .push(rcgen::DnType::CommonName, "BurpCraft CA");
    p.distinguished_name
        .push(rcgen::DnType::OrganizationName, "BurpCraft");
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    p.not_before = rcgen::date_time_ymd(2024, 1, 1);
    p.not_after = rcgen::date_time_ymd(2044, 1, 1);
    p
}

impl Ca {
    /// Loads the CA from `~/.burpcraft`, creating it on first run so users install it once.
    pub fn load_or_create() -> Result<Ca, Box<dyn std::error::Error>> {
        let dir = data_dir();
        std::fs::create_dir_all(&dir)?;
        let (kp, cp) = (dir.join("ca.key"), dir.join("ca.pem"));
        let (key, cert_pem) = match (std::fs::read_to_string(&kp), std::fs::read_to_string(&cp)) {
            (Ok(k), Ok(c)) => (rcgen::KeyPair::from_pem(&k)?, c),
            _ => {
                let key = rcgen::KeyPair::generate()?;
                let pem = ca_params().self_signed(&key)?.pem();
                std::fs::write(&kp, key.serialize_pem())?;
                std::fs::write(&cp, &pem)?;
                (key, pem)
            }
        };
        let der = pem_to_der(&cert_pem).ok_or("bad CA pem")?;
        Ok(Ca {
            issuer: rcgen::Issuer::new(ca_params(), key),
            leaf_key: rcgen::KeyPair::generate()?,
            cert_pem,
            cert_der: CertificateDer::from(der),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// TLS server config presenting a certificate for `host`, signed by this CA.
    pub fn server_config(&self, host: &str) -> io::Result<Arc<rustls::ServerConfig>> {
        if let Some(c) = self.cache.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let mut p = rcgen::CertificateParams::new(vec![host.to_string()]).map_err(io_err)?;
        p.distinguished_name.push(rcgen::DnType::CommonName, host);
        p.not_before = rcgen::date_time_ymd(2024, 1, 1);
        p.not_after = rcgen::date_time_ymd(2034, 1, 1);
        let cert = p.signed_by(&self.leaf_key, &self.issuer).map_err(io_err)?;
        let key = PrivateKeyDer::Pkcs8(self.leaf_key.serialize_der().into());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(io_err)?
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone(), self.cert_der.clone()], key)
            .map_err(io_err)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    crate::codec::base64_decode(&b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_to_local_server() {
        // the path Repeater, Intruder and Sequencer use, against a throwaway local server
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let req =
                read_message(&mut BufReader::new(c.try_clone().unwrap()), false, false).unwrap();
            let body = format!("got {} bytes", req.len());
            write!(
                c,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let resp = send(
            "127.0.0.1",
            port,
            false,
            b"POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
        )
        .unwrap();
        assert!(String::from_utf8(resp).unwrap().ends_with("got 42 bytes"));
    }

    #[test]
    fn framing() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nNEXT";
        let mut r = BufReader::new(&raw[..]);
        let m = read_message(&mut r, true, false).unwrap();
        assert!(m.ends_with(b"0\r\n\r\n"));
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nhiGET";
        let m = read_message(&mut BufReader::new(&raw[..]), false, false).unwrap();
        assert!(m.ends_with(b"\r\n\r\nhi"));
        assert_eq!(
            header("GET / HTTP/1.1\r\nHost: a.b\r\n\r\n", "host").as_deref(),
            Some("a.b")
        );
    }
}
