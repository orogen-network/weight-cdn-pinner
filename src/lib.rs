//! Content-addressed weight CDN pinner.
//!
//! For each registered model/adapter (`pallet-model-registry`), the pinner:
//!   1. Pulls weight blobs from one of N configured mirrors (S3, R2, IPFS).
//!   2. Verifies SHA-256 against the on-chain root hash.
//!   3. Pins locally + republishes to other mirrors for redundancy.
//!
//! Worker daemons pull from local cache when hot; cold-fetch falls through
//! to the pinner's mirror set. Foundation hot-pins top-100 models; long-tail
//! falls back to IPFS DHT.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEntry {
    pub model_id: String, // 0x-prefixed H256
    pub expected_sha256: [u8; 32],
    pub mirrors: Vec<String>, // s3://..., r2://..., ipfs://...
    pub size_bytes: u64,
}

pub const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 10 * 1024 * 1024 * 1024;

impl ModelEntry {
    pub fn expected_hex(&self) -> String {
        hex::encode(self.expected_sha256)
    }
}

#[derive(Error, Debug)]
pub enum PinError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("no mirror could serve {model_id}")]
    NoMirrorAvailable { model_id: String },
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),
    #[error("forbidden mirror url: {0}")]
    ForbiddenMirrorUrl(String),
    #[error("invalid model_id: {0}")]
    InvalidModelId(String),
    #[error("download too large: limit {limit} bytes, got at least {actual} bytes")]
    DownloadTooLarge { limit: u64, actual: u64 },
}

/// 64-char (optionally `0x`-prefixed) hex SHA-256 / H256. Reject anything else
/// before composing a filesystem path (MED-SVC-014).
fn is_valid_model_id(s: &str) -> bool {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    stripped.len() == 64 && stripped.chars().all(|c| c.is_ascii_hexdigit())
}

/// SSRF allow-list (MED-SVC-013). When `WEIGHT_PIN_ALLOWED_HOSTS` is set,
/// only those host suffixes (case-insensitive) are accepted; with no env var,
/// any non-private public hostname is allowed. RFC1918, loopback, link-local,
/// and metadata IPs are always rejected.
fn validate_mirror_url(url: &str) -> Result<(), PinError> {
    let parsed =
        Url::parse(url).map_err(|e| PinError::ForbiddenMirrorUrl(format!("parse error: {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(PinError::ForbiddenMirrorUrl(format!(
            "unsupported scheme: {scheme}"
        )));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(PinError::ForbiddenMirrorUrl(
            "url credentials not allowed".to_string(),
        ));
    }
    // `host_str()` wraps IPv6 in brackets; strip them so the IP-literal path
    // below sees a parseable address.
    let raw_host = parsed
        .host_str()
        .ok_or_else(|| PinError::ForbiddenMirrorUrl("url has no host".to_string()))?
        .to_ascii_lowercase();
    let host = raw_host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(|s| s.to_string())
        .unwrap_or(raw_host);
    if matches!(
        host.as_str(),
        "localhost"
            | "metadata.google.internal"
            | "metadata.azure.com"
            | "metadata"
            | "169.254.169.254"
            | "100.100.100.200"
    ) {
        return Err(PinError::ForbiddenMirrorUrl(format!(
            "forbidden host: {host}"
        )));
    }
    // Allow-list, if configured (host suffix match — accommodates wildcards
    // like `*.r2.cloudflarestorage.com`).
    if let Ok(allow) = std::env::var("WEIGHT_PIN_ALLOWED_HOSTS") {
        let allowed: Vec<String> = allow
            .split(',')
            .map(|s| {
                s.trim()
                    .trim_start_matches('*')
                    .trim_start_matches('.')
                    .to_ascii_lowercase()
            })
            .filter(|s| !s.is_empty())
            .collect();
        if !allowed.is_empty()
            && !allowed
                .iter()
                .any(|a| host == *a || host.ends_with(&format!(".{a}")))
        {
            return Err(PinError::ForbiddenMirrorUrl(format!(
                "host {host} not in allow-list"
            )));
        }
    }
    // If the host is a literal IP, reject private/loopback/link-local immediately.
    // (`WEIGHT_PIN_ALLOW_LOOPBACK=1` opens a dev/test escape hatch so unit tests
    // can point at `http://127.0.0.1:<mock port>`.)
    let allow_loopback = std::env::var("WEIGHT_PIN_ALLOW_LOOPBACK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip_is_forbidden(&ip) {
            // 169.254.169.254 et al. are always forbidden, even with the loopback flag.
            let metadata_ip =
                ip.to_string() == "169.254.169.254" || ip.to_string() == "100.100.100.200";
            if metadata_ip || !(allow_loopback && ip.is_loopback()) {
                return Err(PinError::ForbiddenMirrorUrl(format!("forbidden ip: {ip}")));
            }
        }
    }
    Ok(())
}

async fn validate_resolved_host(url: &str) -> Result<(), PinError> {
    let parsed =
        Url::parse(url).map_err(|e| PinError::ForbiddenMirrorUrl(format!("parse error: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| PinError::ForbiddenMirrorUrl("url has no host".to_string()))?;
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| PinError::ForbiddenMirrorUrl("url has no port".to_string()))?;
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| PinError::ForbiddenMirrorUrl(format!("dns lookup failed: {e}")))?;
    let allow_loopback = std::env::var("WEIGHT_PIN_ALLOW_LOOPBACK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    for addr in addrs {
        let ip = addr.ip();
        if ip_is_forbidden(&ip) {
            if allow_loopback && ip.is_loopback() {
                continue;
            }
            return Err(PinError::ForbiddenMirrorUrl(format!(
                "host {host} resolved to forbidden ip: {ip}"
            )));
        }
    }
    Ok(())
}

fn ip_is_forbidden(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 169.254.0.0/16 (handled by is_link_local for IPv4 ranges 169.254.x.x)
                // 100.64.0.0/10 (CGNAT) — Rust stdlib lacks helper; do manual check.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 — unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 — link local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub struct Pinner {
    cache_dir: PathBuf,
    http: reqwest::Client,
}

impl Pinner {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        // No-redirect client (MED-SVC-013): an attacker-controlled mirror cannot
        // bounce us to a metadata endpoint via 301/302.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client build");
        Self {
            cache_dir: cache_dir.into(),
            http,
        }
    }

    pub fn cache_path(&self, model_id: &str) -> PathBuf {
        // Hard fail-closed on malformed IDs so a chain entry with `model_id =
        // "../foo"` can never resolve a path outside the cache (MED-SVC-014).
        assert!(
            is_valid_model_id(model_id),
            "invalid model_id format: {model_id:?}"
        );
        self.cache_dir.join(format!("{}.bin", strip_0x(model_id)))
    }

    pub fn try_cache_path(&self, model_id: &str) -> Result<PathBuf, PinError> {
        if !is_valid_model_id(model_id) {
            return Err(PinError::InvalidModelId(model_id.to_string()));
        }
        Ok(self.cache_dir.join(format!("{}.bin", strip_0x(model_id))))
    }

    /// Returns true if a verified copy is already cached locally.
    pub async fn is_cached(&self, entry: &ModelEntry) -> Result<bool, PinError> {
        let p = self.cache_path(&entry.model_id);
        if !p.exists() {
            return Ok(false);
        }
        let bytes = tokio::fs::read(&p).await?;
        let actual = sha256(&bytes);
        Ok(actual == entry.expected_sha256)
    }

    /// Fetch the blob, verify the hash, and write to cache. Tries mirrors in order.
    pub async fn fetch_and_pin(&self, entry: &ModelEntry) -> Result<PathBuf, PinError> {
        let dest = self.cache_path(&entry.model_id);
        if self.is_cached(entry).await? {
            tracing::info!(model_id = %entry.model_id, "cache hit");
            return Ok(dest);
        }
        tokio::fs::create_dir_all(&self.cache_dir).await?;
        for mirror in &entry.mirrors {
            match self.fetch_one(mirror, entry).await {
                Ok(bytes) => {
                    tokio::fs::write(&dest, &bytes).await?;
                    return Ok(dest);
                }
                Err(e) => {
                    tracing::warn!(mirror, error = ?e, "mirror failed, trying next");
                }
            }
        }
        Err(PinError::NoMirrorAvailable {
            model_id: entry.model_id.clone(),
        })
    }

    async fn fetch_one(&self, mirror: &str, entry: &ModelEntry) -> Result<Vec<u8>, PinError> {
        let bytes = if mirror.starts_with("http://") || mirror.starts_with("https://") {
            // SSRF defence (MED-SVC-013).
            validate_mirror_url(mirror)?;
            validate_resolved_host(mirror).await?;
            self.fetch_http(mirror, entry.size_bytes).await?
        } else if mirror.starts_with("s3://")
            || mirror.starts_with("r2://")
            || mirror.starts_with("ipfs://")
        {
            // For S3/R2/IPFS we delegate to an HTTP gateway. In production a real
            // S3 SDK + IPFS daemon would replace this; for the skeleton + tests we
            // accept that mirrors are pre-resolved to HTTP gateways by config.
            return Err(PinError::UnsupportedScheme(format!(
                "scheme not yet wired in skeleton: {}",
                mirror
            )));
        } else {
            return Err(PinError::UnsupportedScheme(mirror.to_string()));
        };
        let actual = sha256(&bytes);
        if actual != entry.expected_sha256 {
            return Err(PinError::HashMismatch {
                expected: hex::encode(entry.expected_sha256),
                actual: hex::encode(actual),
            });
        }
        Ok(bytes)
    }

    async fn fetch_http(&self, url: &str, expected_size: u64) -> Result<Vec<u8>, PinError> {
        let limit = if expected_size > 0 {
            expected_size
        } else {
            std::env::var("WEIGHT_PIN_MAX_DOWNLOAD_BYTES")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(DEFAULT_MAX_DOWNLOAD_BYTES)
        };
        let resp = self.http.get(url).send().await?;
        if let Some(len) = resp.content_length() {
            if len > limit {
                return Err(PinError::DownloadTooLarge { limit, actual: len });
            }
        }
        let mut out = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let next_len = (out.len() as u64).saturating_add(chunk.len() as u64);
            if next_len > limit {
                return Err(PinError::DownloadTooLarge {
                    limit,
                    actual: next_len,
                });
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Serve a cached blob for local worker daemon (e.g. via Unix socket / HTTP).
    pub async fn serve(&self, model_id: &str) -> Result<Vec<u8>, PinError> {
        let p = self.cache_path(model_id);
        Ok(tokio::fs::read(&p).await?)
    }

    pub fn pin_path(&self, model_id: &str) -> PathBuf {
        self.cache_path(model_id)
    }

    pub fn cache_root(&self) -> &Path {
        &self.cache_dir
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Tests mutate process-global env vars, so they must run with a single
    /// reader/writer at a time. `LoopbackTestGuard::new()` returns a held
    /// MutexGuard that releases on drop.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// RAII guard that sets WEIGHT_PIN_ALLOW_LOOPBACK so mockito (which binds
    /// to 127.0.0.1) is reachable inside the SSRF allow-list, AND holds a
    /// process-wide mutex so concurrent tests don't see flapping env.
    struct LoopbackTestGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }
    impl LoopbackTestGuard {
        fn new() -> Self {
            let g = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var("WEIGHT_PIN_ALLOW_LOOPBACK", "1");
            Self { _guard: g }
        }
    }
    impl Drop for LoopbackTestGuard {
        fn drop(&mut self) {
            std::env::remove_var("WEIGHT_PIN_ALLOW_LOOPBACK");
        }
    }

    /// Same lock, but does NOT set the env var — for tests that explicitly
    /// require loopback to be forbidden.
    struct NoLoopbackTestGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }
    impl NoLoopbackTestGuard {
        fn new() -> Self {
            let g = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            std::env::remove_var("WEIGHT_PIN_ALLOW_LOOPBACK");
            Self { _guard: g }
        }
    }

    fn sample_entry(bytes: &[u8], mirrors: Vec<String>) -> ModelEntry {
        ModelEntry {
            model_id: "0x".to_string() + &"01".repeat(32),
            expected_sha256: sha256(bytes),
            mirrors,
            size_bytes: bytes.len() as u64,
        }
    }

    #[test]
    fn validate_mirror_rejects_metadata_endpoints() {
        let _g = NoLoopbackTestGuard::new();
        assert!(validate_mirror_url("http://169.254.169.254/").is_err());
        assert!(validate_mirror_url("http://metadata.google.internal/").is_err());
        assert!(validate_mirror_url("http://[::1]/").is_err());
    }

    #[test]
    fn validate_mirror_rejects_private_ips() {
        let _g = NoLoopbackTestGuard::new();
        assert!(validate_mirror_url("http://10.0.0.1/blob").is_err());
        assert!(validate_mirror_url("http://192.168.1.5/blob").is_err());
        assert!(validate_mirror_url("http://172.16.0.1/blob").is_err());
    }

    #[test]
    fn validate_mirror_rejects_bad_scheme() {
        let _g = NoLoopbackTestGuard::new();
        assert!(validate_mirror_url("file:///etc/passwd").is_err());
        assert!(validate_mirror_url("gopher://example.com").is_err());
    }

    #[test]
    fn validate_mirror_accepts_public_https() {
        let _g = NoLoopbackTestGuard::new();
        assert!(validate_mirror_url("https://s3.amazonaws.com/bucket/key").is_ok());
    }

    #[test]
    fn cache_path_rejects_traversal_id() {
        let tmp = TempDir::new().unwrap();
        let pinner = Pinner::new(tmp.path());
        assert!(pinner.try_cache_path("../etc/passwd").is_err());
        let ok_id = format!("0x{}", "01".repeat(32));
        assert!(pinner.try_cache_path(&ok_id).is_ok());
    }

    #[tokio::test]
    async fn is_cached_returns_false_for_missing() {
        let tmp = TempDir::new().unwrap();
        let pinner = Pinner::new(tmp.path());
        let entry = sample_entry(b"hello world", vec![]);
        assert!(!pinner.is_cached(&entry).await.unwrap());
    }

    #[tokio::test]
    async fn is_cached_returns_true_for_valid_cache() {
        let tmp = TempDir::new().unwrap();
        let pinner = Pinner::new(tmp.path());
        let entry = sample_entry(b"hello world", vec![]);
        tokio::fs::write(pinner.cache_path(&entry.model_id), b"hello world")
            .await
            .unwrap();
        assert!(pinner.is_cached(&entry).await.unwrap());
    }

    #[tokio::test]
    async fn is_cached_detects_corruption() {
        let tmp = TempDir::new().unwrap();
        let pinner = Pinner::new(tmp.path());
        let entry = sample_entry(b"hello world", vec![]);
        tokio::fs::write(pinner.cache_path(&entry.model_id), b"corrupted")
            .await
            .unwrap();
        assert!(!pinner.is_cached(&entry).await.unwrap());
    }

    #[tokio::test]
    async fn fetch_rejects_hash_mismatch() {
        let _g = LoopbackTestGuard::new();
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/blob")
            .with_status(200)
            .with_body("not the right bytes")
            .create_async()
            .await;

        let tmp = TempDir::new().unwrap();
        let pinner = Pinner::new(tmp.path());
        let entry = sample_entry(b"hello world", vec![format!("{}/blob", server.url())]);

        let result = pinner.fetch_and_pin(&entry).await;
        mock.assert_async().await;
        match result {
            Err(PinError::NoMirrorAvailable { .. }) => {}
            other => panic!("expected NoMirrorAvailable, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn fetch_rejects_body_larger_than_declared_size() {
        let _g = LoopbackTestGuard::new();
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/blob")
            .with_status(200)
            .with_body("too large")
            .create_async()
            .await;

        let tmp = TempDir::new().unwrap();
        let pinner = Pinner::new(tmp.path());
        let mut entry = sample_entry(b"too large", vec![format!("{}/blob", server.url())]);
        entry.size_bytes = 3;

        let result = pinner.fetch_and_pin(&entry).await;
        mock.assert_async().await;
        match result {
            Err(PinError::NoMirrorAvailable { .. }) => {}
            other => panic!("expected NoMirrorAvailable, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn fetch_succeeds_when_hash_matches() {
        let _g = LoopbackTestGuard::new();
        let mut server = mockito::Server::new_async().await;
        let body = b"hello world";
        let mock = server
            .mock("GET", "/blob")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let tmp = TempDir::new().unwrap();
        let pinner = Pinner::new(tmp.path());
        let entry = sample_entry(body, vec![format!("{}/blob", server.url())]);

        let path = pinner.fetch_and_pin(&entry).await.unwrap();
        mock.assert_async().await;
        let cached = tokio::fs::read(&path).await.unwrap();
        assert_eq!(cached, body);
    }

    #[tokio::test]
    async fn fetch_rejects_ssrf_mirror_without_guard() {
        let _g = NoLoopbackTestGuard::new();
        // Without the loopback guard, the pinner must refuse 127.0.0.1.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/blob")
            .with_status(200)
            .with_body(b"x")
            .create_async()
            .await;
        let tmp = TempDir::new().unwrap();
        let pinner = Pinner::new(tmp.path());
        let entry = sample_entry(b"x", vec![format!("{}/blob", server.url())]);
        let r = pinner.fetch_and_pin(&entry).await;
        match r {
            Err(PinError::NoMirrorAvailable { .. }) => {}
            other => panic!("expected NoMirrorAvailable, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn fetch_falls_through_mirrors() {
        let _g = LoopbackTestGuard::new();
        let mut server = mockito::Server::new_async().await;
        let body = b"hello world";
        let _bad = server
            .mock("GET", "/bad")
            .with_status(500)
            .create_async()
            .await;
        let _good = server
            .mock("GET", "/good")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let tmp = TempDir::new().unwrap();
        let pinner = Pinner::new(tmp.path());
        let entry = sample_entry(
            body,
            vec![
                format!("{}/bad", server.url()),
                format!("{}/good", server.url()),
            ],
        );
        let path = pinner.fetch_and_pin(&entry).await.unwrap();
        let cached = tokio::fs::read(&path).await.unwrap();
        assert_eq!(cached, body);
    }
}
