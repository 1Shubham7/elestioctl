//! HTTP client for the Elestio API.
//!
//! Everything that leaves this process goes through [`ApiClient::request`].
//! That single funnel is where the read-only allowlist (R53), the JWT
//! injection (R6), the per-attempt timeout (R14), the retry policy (R15),
//! the envelope check (R16), and the path-naming parse errors (R17) live.
//! The typed methods below it (`sign_in`, `list_services`, ...) only build a
//! body and pick fields out of the result.
//!
//! Rust note: this module is `async`. The alternative, `reqwest::blocking`,
//! would read more simply, but the test mock server (`wiremock`) is
//! async-native and mixing the two means running the blocking client on a
//! separate thread inside every test. A `current_thread` tokio runtime in
//! `main` costs nothing measurable for a CLI that makes a handful of
//! sequential requests.

use std::fmt;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::config::Credentials;
use crate::model::{FirewallRule, RawService, Service};
use crate::secret::Secret;

/// Production API (R13).
pub const DEFAULT_BASE_URL: &str = "https://api.elest.io";
/// Environment variable overriding the base URL (R13).
pub const ENV_BASE_URL: &str = "ELESTIO_API_URL";
/// Environment variable overriding the per-attempt timeout in seconds (R14).
pub const ENV_TIMEOUT_SECS: &str = "ELESTIO_TIMEOUT_SECS";
/// Environment variable overriding the retry backoff base in milliseconds (R15).
pub const ENV_RETRY_BASE_MS: &str = "ELESTIO_RETRY_BASE_MS";
/// Default per-attempt timeout (R14).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default backoff base: retry 1 waits this long, retry 2 waits double (R15).
pub const DEFAULT_RETRY_BASE: Duration = Duration::from_millis(500);
/// Total requests per call, including the first (R15).
pub const MAX_ATTEMPTS: u32 = 3;

/// The closed set of calls this tool may make (R53).
///
/// Each variant is one row of the allowlist. There is no variant for
/// anything that mutates, and no way to construct a request for a path that
/// is not here except through [`ApiClient::request`], which checks
/// [`is_allowed`] first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// `POST /api/auth/checkAPIToken`: exchange email and API token for a JWT.
    CheckApiToken,
    /// `POST /api/servers/getServices`: list services in a project.
    GetServices,
    /// `POST /api/servers/getServerDetails`: one service by `vmID`.
    GetServerDetails,
    /// `POST /api/servers/DoActionOnServer` with `action = "getFirewallRules"`.
    GetFirewallRules,
}

impl Endpoint {
    /// URL path.
    pub fn path(self) -> &'static str {
        match self {
            Endpoint::CheckApiToken => "/api/auth/checkAPIToken",
            Endpoint::GetServices => "/api/servers/getServices",
            Endpoint::GetServerDetails => "/api/servers/getServerDetails",
            Endpoint::GetFirewallRules => "/api/servers/DoActionOnServer",
        }
    }

    /// The `action` body member, for the shared action endpoint.
    pub fn action(self) -> Option<&'static str> {
        match self {
            Endpoint::GetFirewallRules => Some("getFirewallRules"),
            _ => None,
        }
    }

    /// Whether the call needs a JWT in the body. Only sign-in does not.
    pub fn needs_jwt(self) -> bool {
        !matches!(self, Endpoint::CheckApiToken)
    }

    /// Every allowed endpoint, in a fixed order.
    pub const ALL: [Endpoint; 4] = [
        Endpoint::CheckApiToken,
        Endpoint::GetServices,
        Endpoint::GetServerDetails,
        Endpoint::GetFirewallRules,
    ];
}

/// R53: true only for the exact (method, path, action) triples in the spec.
///
/// `action` is the value of the request body's `action` member, or `None`
/// when the body has none. The shared action endpoint is allowed only with
/// `getFirewallRules`; the same path with any other action, or with no
/// action, is refused.
pub fn is_allowed(method: &str, path: &str, action: Option<&str>) -> bool {
    method == "POST"
        && Endpoint::ALL
            .iter()
            .any(|e| e.path() == path && e.action() == action)
}

/// Errors from the client. Each variant names the path involved (R12, R16).
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The call is not on the allowlist (R53). Nothing was sent.
    #[error("refusing to send {method} {path}{}: not on the read-only allowlist", action_suffix(.action))]
    NotAllowed {
        /// HTTP method requested.
        method: String,
        /// Path requested.
        path: String,
        /// Body `action`, if any.
        action: Option<String>,
    },
    /// An authenticated call was attempted before signing in.
    #[error("cannot call {path}: not signed in")]
    MissingJwt {
        /// Path requested.
        path: String,
    },
    /// The connection failed on every attempt (R15).
    // The source is deliberately not repeated in the message: anyhow prints the
    // chain, and thiserror's convention is that a `#[source]` speaks for itself.
    #[error("{path}: transport error after {attempts} attempt(s)")]
    Transport {
        /// Path requested.
        path: String,
        /// Requests made.
        attempts: u32,
        /// Last underlying error.
        #[source]
        source: reqwest::Error,
    },
    /// A non-2xx status that was either not retryable or still failing after
    /// the last retry (R16).
    #[error("{path}: HTTP {status} after {attempts} attempt(s)")]
    HttpStatus {
        /// Path requested.
        path: String,
        /// Final status code.
        status: u16,
        /// Requests made.
        attempts: u32,
    },
    /// A 2xx response whose body says `"status": "KO"` (R16).
    #[error("{path}: API error: {message}")]
    Api {
        /// Path requested.
        path: String,
        /// The API's `message`, or a placeholder when absent.
        message: String,
    },
    /// Sign-in was refused (R20).
    #[error("credentials rejected by the API: {message}")]
    AuthRejected {
        /// The API's `message`, or a placeholder when absent.
        message: String,
    },
    /// The body was not the JSON shape expected (R17).
    #[error("{path}: failed to parse response at {json_path}: {reason}")]
    Parse {
        /// Path requested.
        path: String,
        /// Dotted JSON path to the offending field.
        json_path: String,
        /// serde's message.
        reason: String,
    },
    /// An environment override could not be parsed.
    #[error("invalid value for {name}: {reason}")]
    InvalidSetting {
        /// Variable name.
        name: &'static str,
        /// What was wrong.
        reason: String,
    },
    /// The HTTP client itself could not be built.
    #[error("failed to build HTTP client: {0}")]
    Build(#[source] reqwest::Error),
}

fn action_suffix(action: &Option<String>) -> String {
    match action {
        Some(a) => format!(" (action {a})"),
        None => String::new(),
    }
}

/// Tunables for [`ApiClient`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Base URL without a trailing slash (R13).
    pub base_url: String,
    /// Per-attempt timeout (R14).
    pub timeout: Duration,
    /// Backoff base (R15).
    pub retry_base: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout: DEFAULT_TIMEOUT,
            retry_base: DEFAULT_RETRY_BASE,
        }
    }
}

impl ClientConfig {
    /// Read overrides from the process environment (R13, R14, R15).
    /// Unset or empty variables keep the defaults; unparsable ones are errors.
    pub fn from_env() -> Result<Self, ClientError> {
        let mut cfg = ClientConfig::default();
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        if let Some(url) = var(ENV_BASE_URL) {
            cfg.base_url = url.trim_end_matches('/').to_string();
        }
        if let Some(secs) = var(ENV_TIMEOUT_SECS) {
            let n: u64 = secs.parse().map_err(|e| ClientError::InvalidSetting {
                name: ENV_TIMEOUT_SECS,
                reason: format!("{e} (got {secs:?})"),
            })?;
            cfg.timeout = Duration::from_secs(n);
        }
        if let Some(ms) = var(ENV_RETRY_BASE_MS) {
            let n: u64 = ms.parse().map_err(|e| ClientError::InvalidSetting {
                name: ENV_RETRY_BASE_MS,
                reason: format!("{e} (got {ms:?})"),
            })?;
            cfg.retry_base = Duration::from_millis(n);
        }
        Ok(cfg)
    }
}

/// The API client. Holds the JWT once signed in; `Debug` redacts it (R6).
pub struct ApiClient {
    http: reqwest::Client,
    config: ClientConfig,
    jwt: Option<Secret>,
}

impl fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiClient")
            .field("config", &self.config)
            .field("jwt", &self.jwt)
            .finish()
    }
}

/// What one attempt produced, before the retry decision.
enum Attempt {
    Body(Value),
    RetryableStatus(u16),
    FinalStatus(u16),
    Transport(reqwest::Error),
}

impl ApiClient {
    /// Build a client. The timeout applies to every request the client makes (R14).
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        // reqwest is built with `rustls-no-provider` (aws-lc-sys needs cmake,
        // which is not a given on a developer machine), so the process must
        // install a crypto provider before the first client is built.
        // `install_default` fails only if one is already installed, which is
        // fine: the second client in a test process reuses the first's.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(concat!("elestioctl/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(ClientError::Build)?;
        Ok(ApiClient {
            http,
            config,
            jwt: None,
        })
    }

    /// The configured base URL.
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Install a JWT obtained elsewhere (the cached one from `config.json`, R2).
    pub fn set_jwt(&mut self, jwt: Secret) {
        self.jwt = Some(jwt);
    }

    /// True once a JWT is available.
    pub fn is_signed_in(&self) -> bool {
        self.jwt.is_some()
    }

    /// R18, R20: exchange credentials for a JWT and keep it in the client.
    pub async fn sign_in(&mut self, creds: &Credentials) -> Result<(), ClientError> {
        let body = json!({ "email": creds.email, "token": creds.api_token.expose() });
        let value = match self
            .request("POST", Endpoint::CheckApiToken.path(), body)
            .await
        {
            Ok(v) => v,
            // The auth endpoint reports bad credentials as a KO envelope;
            // surface that as a distinct error so the caller can tell it apart
            // from "no credentials" and from network failure (R20).
            Err(ClientError::Api { message, .. }) => {
                return Err(ClientError::AuthRejected { message })
            }
            Err(e) => return Err(e),
        };
        match value.get("jwt").and_then(Value::as_str) {
            Some(jwt) if !jwt.is_empty() => {
                self.jwt = Some(Secret::new(jwt));
                Ok(())
            }
            _ => Err(ClientError::AuthRejected {
                message: message_of(&value).unwrap_or_else(|| "no jwt in response".to_string()),
            }),
        }
    }

    /// R21: services in a project.
    pub async fn list_services(&self, project: &str) -> Result<Vec<Service>, ClientError> {
        let path = Endpoint::GetServices.path();
        let body = json!({
            "appid": "Cloudxx",
            "projectId": project,
            "isActiveService": "true",
        });
        let value = self.request("POST", path, body).await?;
        // The official CLI accepts either `servers` or `data.services`.
        let list = value
            .get("servers")
            .or_else(|| value.pointer("/data/services"))
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let raw: Vec<RawService> = parse_typed(path, list)?;
        Ok(raw.into_iter().map(Service::from).collect())
    }

    /// R26, R27: one service, or `None` when the API returns an empty
    /// `serviceInfos` for the id in that project.
    pub async fn get_service(
        &self,
        project: &str,
        vm_id: &str,
    ) -> Result<Option<Service>, ClientError> {
        let path = Endpoint::GetServerDetails.path();
        let body = json!({ "vmID": vm_id, "projectID": project });
        let value = self.request("POST", path, body).await?;
        let list = value
            .get("serviceInfos")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let mut raw: Vec<RawService> = parse_typed(path, list)?;
        if raw.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Service::from(raw.remove(0))))
        }
    }

    /// R29: firewall rules for a service. The caller decides what a disabled
    /// firewall means; this just returns what the API lists.
    pub async fn get_firewall_rules(&self, vm_id: &str) -> Result<Vec<FirewallRule>, ClientError> {
        let path = Endpoint::GetFirewallRules.path();
        let body = json!({ "vmID": vm_id, "action": "getFirewallRules" });
        let value = self.request("POST", path, body).await?;
        // The official CLI accepts `rules`, `data.rules`, or a bare array.
        let list = if value.is_array() {
            value
        } else {
            value
                .get("rules")
                .or_else(|| value.pointer("/data/rules"))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()))
        };
        parse_typed(path, list)
    }

    /// The single funnel every request goes through.
    ///
    /// Order of checks: allowlist (R53, nothing is sent on failure), JWT
    /// presence and injection into the body (R6: never the URL), then up to
    /// [`MAX_ATTEMPTS`] attempts with exponential backoff (R15), each bounded
    /// by the client timeout (R14). A 2xx body is parsed as JSON and its
    /// `status` checked for `KO` (R16).
    ///
    /// `body` must be a JSON object. Its `action` member, if any, is what the
    /// allowlist checks against.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        mut body: Value,
    ) -> Result<Value, ClientError> {
        let action = body
            .get("action")
            .and_then(Value::as_str)
            .map(str::to_string);
        // R53
        if !is_allowed(method, path, action.as_deref()) {
            return Err(ClientError::NotAllowed {
                method: method.to_string(),
                path: path.to_string(),
                action,
            });
        }
        let needs_jwt = path != Endpoint::CheckApiToken.path();
        if needs_jwt {
            match &self.jwt {
                Some(jwt) => {
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert("jwt".to_string(), Value::String(jwt.expose().to_string()));
                    }
                }
                None => {
                    return Err(ClientError::MissingJwt {
                        path: path.to_string(),
                    })
                }
            }
        }

        let url = format!("{}{}", self.config.base_url, path);
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            tracing::debug!(method, path, attempt, "sending request");
            let outcome = self.attempt(&url, &body).await;
            match outcome {
                Attempt::Body(value) => {
                    // R16: the API reports failure inside a 200.
                    if value.get("status").and_then(Value::as_str) == Some("KO") {
                        return Err(ClientError::Api {
                            path: path.to_string(),
                            message: message_of(&value).unwrap_or_else(|| "no message".to_string()),
                        });
                    }
                    return Ok(value);
                }
                Attempt::FinalStatus(status) => {
                    tracing::debug!(path, status, attempt, "non-retryable status");
                    return Err(ClientError::HttpStatus {
                        path: path.to_string(),
                        status,
                        attempts: attempt,
                    });
                }
                Attempt::RetryableStatus(status) => {
                    tracing::debug!(path, status, attempt, "retryable status");
                    if attempt >= MAX_ATTEMPTS {
                        return Err(ClientError::HttpStatus {
                            path: path.to_string(),
                            status,
                            attempts: attempt,
                        });
                    }
                }
                Attempt::Transport(source) => {
                    tracing::debug!(path, attempt, error = %source, "transport error");
                    if attempt >= MAX_ATTEMPTS {
                        return Err(ClientError::Transport {
                            path: path.to_string(),
                            attempts: attempt,
                            source,
                        });
                    }
                }
            }
            // R15: base * 2^(n-1) before retry n.
            let delay = self.config.retry_base * 2u32.saturating_pow(attempt - 1);
            tokio::time::sleep(delay).await;
        }
    }

    async fn attempt(&self, url: &str, body: &Value) -> Attempt {
        let response = match self.http.post(url).json(body).send().await {
            Ok(r) => r,
            Err(e) => return Attempt::Transport(e),
        };
        let status = response.status();
        let code = status.as_u16();
        if is_retryable_status(code) {
            return Attempt::RetryableStatus(code);
        }
        if !status.is_success() {
            return Attempt::FinalStatus(code);
        }
        match response.json::<Value>().await {
            Ok(v) => Attempt::Body(v),
            // A 2xx whose body is not JSON at all. reqwest reports this as
            // a decode error; treat it as transport so it is retried, since
            // a truncated body is the usual cause.
            Err(e) => Attempt::Transport(e),
        }
    }
}

/// R15: 408, 429, and every 5xx are retried. Nothing else is.
pub fn is_retryable_status(code: u16) -> bool {
    code == 408 || code == 429 || (500..=599).contains(&code)
}

fn message_of(value: &Value) -> Option<String> {
    value
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// R17: deserialise with the JSON path attached to any failure.
fn parse_typed<T: DeserializeOwned>(path: &str, value: Value) -> Result<T, ClientError> {
    serde_path_to_error::deserialize(value).map_err(|e| ClientError::Parse {
        path: path.to_string(),
        json_path: e.path().to_string(),
        reason: e.inner().to_string(),
    })
}
