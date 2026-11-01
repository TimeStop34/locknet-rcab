use std::time::Duration;
use url::Url;

#[derive(Clone, Debug)]
pub struct LockNetConfig {
    pub base_url: Url,
    pub space: String,
    pub user_agent: String,
    pub sync_on_connect: bool,
    pub event_sync_limit: u32,
    pub http_timeout: Duration,
    pub ws_ping_interval: Duration,
    pub reconnect_backoff_initial: Duration,
    pub reconnect_backoff_max: Duration,
    pub accept_invalid_certs: bool,
}

impl LockNetConfig {
    pub fn new(base_url: &str, space: &str) -> std::result::Result<Self, url::ParseError> {
        Ok(Self {
            base_url: Url::parse(base_url)?,
            space: space.to_string(),
            user_agent: format!("LockNet-RCAB/{}", env!("CARGO_PKG_VERSION")),
            sync_on_connect: true,
            event_sync_limit: 200,
            http_timeout: Duration::from_secs(30),
            ws_ping_interval: Duration::from_secs(30),
            reconnect_backoff_initial: Duration::from_secs(1),
            reconnect_backoff_max: Duration::from_secs(60),
            accept_invalid_certs: true,
        })
    }

    pub fn ws_url(&self) -> String {
        let scheme = if self.base_url.scheme() == "https" { "wss" } else { "ws" };
        let host = self.base_url.host_str().unwrap_or("localhost");
        let port = self.base_url.port().map(|p| format!(":{}", p)).unwrap_or_default();
        format!("{}://{}{}/ws", scheme, host, port)
    }

    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url.as_str().trim_end_matches('/'), path)
    }
}