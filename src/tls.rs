//! TLS termination for the edge listener.
//!
//! One certificate pair from disk, served for every name. Whatever issues it —
//! certbot, a DNS-01 client, a private CA for `.lan`-style names that no public
//! CA will sign — keeps owning renewal; bastion just notices the files changed
//! and swaps the new pair in without a restart.
//!
//! A reload that fails keeps the old pair. A broken renewal therefore shows up
//! as an expiry date on the settings page, not as every host going dark at once.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// What the settings page shows about the loaded certificate.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub names: Vec<String>,
    pub not_after: i64,
    pub loaded_at: i64,
    /// The last reload attempt failed; the previous pair is still in use.
    pub reload_error: Option<String>,
}

#[derive(Debug)]
pub struct CertStore {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    current: RwLock<Arc<CertifiedKey>>,
    info: RwLock<CertInfo>,
    stamp: RwLock<(Option<SystemTime>, Option<SystemTime>)>,
}

impl CertStore {
    pub fn load(cert_path: PathBuf, key_path: PathBuf) -> Result<CertStore> {
        let (key, info) = read_pair(&cert_path, &key_path)?;
        let stamp = (mtime(&cert_path), mtime(&key_path));
        Ok(CertStore {
            cert_path,
            key_path,
            current: RwLock::new(Arc::new(key)),
            info: RwLock::new(info),
            stamp: RwLock::new(stamp),
        })
    }

    pub fn info(&self) -> CertInfo {
        self.info.read().unwrap().clone()
    }

    /// Re-read the pair if either file's mtime moved. Both are checked
    /// together so a renewal that rewrites them one at a time is picked up
    /// once the second lands, and a half-written pair that fails to parse is
    /// simply retried next tick.
    fn reload_if_changed(&self) {
        let now = (mtime(&self.cert_path), mtime(&self.key_path));
        if *self.stamp.read().unwrap() == now {
            return;
        }
        match read_pair(&self.cert_path, &self.key_path) {
            Ok((key, info)) => {
                tracing::info!(names = ?info.names, "reloaded TLS certificate");
                *self.current.write().unwrap() = Arc::new(key);
                *self.info.write().unwrap() = info;
                *self.stamp.write().unwrap() = now;
            }
            Err(e) => {
                tracing::warn!(error = %e, "TLS certificate changed but did not load; keeping the old one");
                self.info.write().unwrap().reload_error = Some(format!("{:#}", e));
            }
        }
    }

    pub fn spawn_reloader(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await;
            loop {
                tick.tick().await;
                self.reload_if_changed();
            }
        });
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().unwrap().clone())
    }
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn read_pair(cert_path: &Path, key_path: &Path) -> Result<(CertifiedKey, CertInfo)> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing {}", cert_path.display()))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("{} has no certificates in it", cert_path.display()))?;
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow!("{}: unsupported key: {}", key_path.display(), e))?;
    let info = describe(leaf)?;
    let ck = CertifiedKey::new(certs, signer);
    ck.keys_match()
        .map_err(|e| anyhow!("certificate and key don't belong together: {}", e))?;
    Ok((ck, info))
}

fn describe(leaf: &CertificateDer<'_>) -> Result<CertInfo> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| anyhow!("unreadable certificate: {}", e))?;
    let mut names: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if names.is_empty() {
        names.extend(
            cert.subject()
                .iter_common_name()
                .filter_map(|cn| cn.as_str().ok().map(String::from)),
        );
    }
    Ok(CertInfo {
        names,
        not_after: cert.validity().not_after.timestamp(),
        loaded_at: chrono::Utc::now().timestamp(),
        reload_error: None,
    })
}

/// Server config for the edge listener. HTTP/1.1 only, matching the gateway
/// this replaces; WebSockets ride on it unchanged.
pub fn server_config(store: Arc<CertStore>) -> Result<rustls::ServerConfig> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(store);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}
