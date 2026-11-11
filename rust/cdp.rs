//! Minimal synchronous Chrome DevTools Protocol client: target discovery over
//! HTTP `GET /json/list` plus one blocking websocket per page target. Only what
//! the passkey commands need: request/response calls that ignore CDP events.

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::ErrorKind,
    net::TcpStream,
    time::{Duration, Instant},
};
use tungstenite::client::{IntoClientRequest, client};
use tungstenite::{Message, WebSocket};

/// A local handshake answers immediately; a slow one means the wrong endpoint.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a single command may wait for its reply before it is stuck.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Read timeout slice so callers stay responsive to their own deadlines.
const READ_SLICE: Duration = Duration::from_millis(500);

/// One entry from `GET <cdp>/json/list`.
#[derive(Clone, Debug, Deserialize)]
pub struct Target {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    #[serde(rename = "webSocketDebuggerUrl", default)]
    pub web_socket_debugger_url: Option<String>,
}

/// Connection inputs shared by the passkey commands: `--cdp`, `--target`,
/// `--target-id`.
pub struct ConnectOptions {
    pub url: String,
    pub target: Option<String>,
    pub target_id: Option<String>,
}

impl ConnectOptions {
    pub fn connect(&self) -> Result<Cdp> {
        let targets = list_targets(&self.url)?;
        let target = select_target(&targets, self.target.as_deref(), self.target_id.as_deref())?;
        Cdp::connect(&target)
    }
}

pub fn list_targets(base_url: &str) -> Result<Vec<Target>> {
    let url = format!("{}/json/list", base_url.trim_end_matches('/'));
    let mut response = ureq::get(&url)
        .call()
        .with_context(|| format!("GET {url} (is Chrome running with --remote-debugging-port?)"))?;
    let body = response
        .body_mut()
        .read_to_string()
        .with_context(|| format!("read {url} response"))?;
    serde_json::from_str(&body).with_context(|| format!("parse {url} response"))
}

/// `--target-id` wins; otherwise the first page whose url contains `substring`,
/// or the only page open. Errors list page urls only, never titles.
pub fn select_target(
    targets: &[Target],
    substring: Option<&str>,
    id: Option<&str>,
) -> Result<Target> {
    if let Some(id) = id {
        return targets
            .iter()
            .find(|target| target.id == id)
            .cloned()
            .with_context(|| format!("no CDP target with id {id}"));
    }
    let pages: Vec<&Target> = targets
        .iter()
        .filter(|target| target.kind == "page")
        .collect();
    if let Some(substring) = substring {
        return pages
            .iter()
            .find(|target| target.url.contains(substring))
            .map(|target| (*target).clone())
            .with_context(|| {
                format!(
                    "no page target whose url contains {substring:?}; open pages: {}",
                    page_urls(&pages)
                )
            });
    }
    match pages.as_slice() {
        [page] => Ok((*page).clone()),
        _ => bail!(
            "expected exactly one open page but found {}; pass --target or --target-id. open pages: {}",
            pages.len(),
            page_urls(&pages)
        ),
    }
}

fn page_urls(pages: &[&Target]) -> String {
    if pages.is_empty() {
        return "none".to_owned();
    }
    pages
        .iter()
        .map(|page| page.url.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A CDP error response reduced to the fields that are safe to report. Every
/// other field (notably `data`) is dropped because a rejected command may be
/// answered with detail that echoes the request params, and the
/// `WebAuthn.addCredential` params carry a private key.
#[derive(Clone, Debug)]
pub struct CdpError {
    code: Option<i64>,
    message: Option<String>,
}

impl CdpError {
    /// Reduce a CDP error response object to its code and message.
    fn from_value(error: &Value) -> CdpError {
        CdpError {
            code: error.get("code").and_then(Value::as_i64),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }
}

impl std::fmt::Display for CdpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.code, &self.message) {
            (Some(code), Some(message)) => write!(formatter, "code {code}: {message}"),
            (Some(code), None) => write!(formatter, "code {code}"),
            (None, Some(message)) => write!(formatter, "message: {message}"),
            (None, None) => formatter.write_str("code and message missing"),
        }
    }
}

/// Why one [`Cdp::call_checked`] did not return a result. Keeping the CDP
/// error response separate lets a caller whose params hold secrets report the
/// entry and the error's code and message fields alone.
#[derive(Debug)]
pub enum CdpCallError {
    /// The command could not be sent or read, including the per-call timeout.
    Transport(anyhow::Error),
    /// The browser answered with an error response.
    Rejected(CdpError),
}

impl std::fmt::Display for CdpCallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CdpCallError::Transport(error) => write!(formatter, "{error:#}"),
            CdpCallError::Rejected(error) => error.fmt(formatter),
        }
    }
}

/// One websocket connection to one target. The browser removes a virtual
/// authenticator when this connection drops, so callers keep it open until the
/// ceremony is done.
pub struct Cdp {
    socket: WebSocket<TcpStream>,
    next_id: u64,
}

impl Cdp {
    pub fn connect(target: &Target) -> Result<Cdp> {
        let url = target
            .web_socket_debugger_url
            .as_deref()
            .with_context(|| format!("CDP target {} has no webSocketDebuggerUrl", target.id))?;
        let request = url
            .into_client_request()
            .with_context(|| format!("invalid websocket url {url}"))?;
        // The socket below is plain TCP, so only ws:// can be served; a
        // wss:// url would otherwise fail later with a confusing handshake
        // error.
        match request.uri().scheme_str() {
            Some("ws") => {}
            Some(scheme) => bail!("CDP websocket url {url} must use ws://, not {scheme}://"),
            None => bail!("CDP websocket url {url} must use ws://"),
        }
        let host = request
            .uri()
            .host()
            .context("websocket url has no host")?
            .to_owned();
        let port = request.uri().port_u16().unwrap_or(80);
        let stream = TcpStream::connect((host.as_str(), port))
            .with_context(|| format!("connect to {host}:{port}"))?;
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        let (mut socket, _response) = client(request, stream)
            .map_err(|error| anyhow!("CDP websocket handshake failed: {error}"))?;
        socket.get_mut().set_read_timeout(Some(READ_SLICE))?;
        Ok(Cdp { socket, next_id: 1 })
    }

    /// Send one CDP command and return its `result`. Events and replies to
    /// other ids are ignored; a CDP error is reported with only its code and
    /// message fields.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        self.call_checked(method, params).map_err(|error| match error {
            CdpCallError::Transport(error) => error,
            CdpCallError::Rejected(error) => anyhow!("CDP {method} failed: {error}"),
        })
    }

    /// Like [`Cdp::call`], but a CDP error response stays typed so a caller
    /// whose params hold secrets (the `WebAuthn.addCredential` private key)
    /// can report the entry and the error code/message without the params.
    pub fn call_checked(
        &mut self,
        method: &str,
        params: Value,
    ) -> std::result::Result<Value, CdpCallError> {
        let id = self.next_id;
        self.next_id += 1;
        let message = json!({"id": id, "method": method, "params": params});
        self.socket
            .send(Message::text(message.to_string()))
            .with_context(|| format!("send CDP {method}"))
            .map_err(CdpCallError::Transport)?;
        let deadline = Instant::now() + CALL_TIMEOUT;
        loop {
            // Checked here as well as after a read timeout: a stream of
            // events must not keep the loop from its deadline.
            if Instant::now() >= deadline {
                return Err(CdpCallError::Transport(anyhow!(
                    "timed out waiting for CDP {method}"
                )));
            }
            match self.socket.read() {
                Ok(Message::Text(text)) => {
                    let message: Value = serde_json::from_str(&text).map_err(|error| {
                        CdpCallError::Transport(anyhow!(error).context("parse CDP message"))
                    })?;
                    if message.get("id").and_then(Value::as_u64) != Some(id) {
                        continue; // an event, or somebody else's reply
                    }
                    if let Some(error) = message.get("error") {
                        return Err(CdpCallError::Rejected(CdpError::from_value(error)));
                    }
                    return Ok(message.get("result").cloned().unwrap_or(Value::Null));
                }
                Ok(Message::Close(_)) => {
                    return Err(CdpCallError::Transport(anyhow!(
                        "CDP websocket closed while waiting for {method}"
                    )));
                }
                Ok(_) => {}
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    if Instant::now() >= deadline {
                        return Err(CdpCallError::Transport(anyhow!(
                            "timed out waiting for CDP {method}"
                        )));
                    }
                }
                Err(error) => {
                    return Err(CdpCallError::Transport(
                        anyhow!(error)
                            .context(format!("read CDP websocket while waiting for {method}")),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: &str, kind: &str, url: &str) -> Target {
        Target {
            id: id.into(),
            kind: kind.into(),
            url: url.into(),
            web_socket_debugger_url: None,
        }
    }

    #[test]
    fn target_selection_prefers_id_then_substring_then_the_only_page() {
        let targets = vec![
            target("a", "page", "https://accounts.google.com/signin"),
            target("b", "page", "https://webauthn.io/"),
            target("c", "service_worker", "https://example.test/sw.js"),
        ];
        assert_eq!(
            select_target(&targets, Some("google"), None).unwrap().id,
            "a"
        );
        assert_eq!(select_target(&targets, None, Some("b")).unwrap().id, "b");
        assert_eq!(select_target(&targets, None, Some("c")).unwrap().id, "c");
        assert!(select_target(&targets, Some("missing"), None).is_err());
        assert!(select_target(&targets, None, Some("missing")).is_err());
        assert!(select_target(&targets, None, None).is_err());
        assert_eq!(select_target(&targets[..1], None, None).unwrap().id, "a");
    }

    #[test]
    fn target_errors_list_page_urls_only() {
        let targets = vec![
            target("a", "page", "https://one.test/"),
            target("b", "page", "https://two.test/"),
        ];
        let error = select_target(&targets, None, None).unwrap_err().to_string();
        assert!(error.contains("https://one.test/"));
        assert!(error.contains("https://two.test/"));
    }

    // Both urls are rejected before any socket is opened, so this needs no
    // server.
    #[test]
    fn connect_rejects_websocket_urls_that_are_not_ws() {
        let target = Target {
            id: "a".into(),
            kind: "page".into(),
            url: "https://example.test/".into(),
            web_socket_debugger_url: Some("wss://example.test/devtools/page/a".into()),
        };
        let error = Cdp::connect(&target)
            .err()
            .expect("wss:// must be rejected")
            .to_string();
        assert!(error.contains("must use ws://"), "error: {error}");
        let target = Target {
            web_socket_debugger_url: Some("http://example.test/devtools/page/a".into()),
            ..target
        };
        let error = Cdp::connect(&target)
            .err()
            .expect("http:// must be rejected")
            .to_string();
        assert!(error.contains("must use ws://"), "error: {error}");
    }
}
