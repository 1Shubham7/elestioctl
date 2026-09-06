//! Credentials and defaults, read from the same files the official CLI
//! writes (R1, R2) with environment overrides (R3).
//!
//! Nothing in this module writes to disk (R54). The `home` argument on the
//! loader exists so tests can point it at a temporary directory instead of
//! the real `~/.elestio`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::secret::Secret;

/// Environment variable holding the account email (R3).
pub const ENV_EMAIL: &str = "ELESTIO_EMAIL";
/// Environment variable holding the API token (R3).
pub const ENV_API_TOKEN: &str = "ELESTIO_API_TOKEN";
/// Directory under `$HOME` that the official CLI uses.
pub const CONFIG_DIR: &str = ".elestio";
/// Credentials file name inside [`CONFIG_DIR`] (R1).
pub const CREDENTIALS_FILE: &str = "credentials";
/// Defaults file name inside [`CONFIG_DIR`] (R2).
pub const CONFIG_FILE: &str = "config.json";

/// How far in the future a cached JWT must expire to be reused (R2).
const JWT_FRESHNESS_MARGIN: Duration = Duration::from_secs(5 * 60);

/// Where the credentials came from. Reported in `auth test` output and used
/// to decide whether a cached JWT may be trusted (R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    /// Read from `~/.elestio/credentials`.
    File,
    /// Read from `ELESTIO_EMAIL` and `ELESTIO_API_TOKEN`.
    Environment,
}

/// Account email plus API token. `Debug` redacts the token (R6).
#[derive(Debug, Clone)]
pub struct Credentials {
    /// Account email.
    pub email: String,
    /// API token; redacted in `Debug`.
    pub api_token: Secret,
    /// Where these came from.
    pub source: CredentialSource,
}

/// A JWT read from `config.json` together with its expiry (R2).
#[derive(Debug, Clone)]
pub struct CachedJwt {
    /// The token; redacted in `Debug`.
    pub jwt: Secret,
    /// Expiry as milliseconds since the Unix epoch, as the official CLI stores it.
    pub expires_at_ms: u64,
}

impl CachedJwt {
    /// True when the token expires more than five minutes after `now` (R2).
    pub fn is_fresh_at(&self, now: SystemTime) -> bool {
        let now_ms = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;
        self.expires_at_ms > now_ms.saturating_add(JWT_FRESHNESS_MARGIN.as_millis() as u64)
    }
}

/// Everything the tool knows before it talks to the API.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Resolved credentials.
    pub credentials: Credentials,
    /// `defaultProject` from `config.json`, if any (R2).
    pub default_project: Option<String>,
    /// Cached JWT from `config.json`, if present and if the credentials came
    /// from the file. Environment credentials always ignore the cache (R3).
    pub cached_jwt: Option<CachedJwt>,
    /// Warnings to print to stderr (R4). Collected rather than printed so the
    /// loader stays free of I/O other than reading files.
    pub warnings: Vec<String>,
}

/// Errors from loading configuration. Every variant names the path or
/// variable involved (R5, R12).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// No credentials in the file or the environment (R5).
    #[error(
        "no credentials found: looked for {path} and the environment variables {env_email} and {env_token}"
    )]
    NoCredentials {
        /// Path that was checked.
        path: PathBuf,
        /// Email variable name.
        env_email: &'static str,
        /// Token variable name.
        env_token: &'static str,
    },
    /// The credentials file exists but is not the JSON shape the official CLI writes.
    #[error("failed to parse credentials file {path}: {reason}")]
    MalformedCredentials {
        /// File path.
        path: PathBuf,
        /// What was wrong.
        reason: String,
    },
    /// `config.json` exists but is not valid JSON.
    #[error("failed to parse config file {path}: {reason}")]
    MalformedConfig {
        /// File path.
        path: PathBuf,
        /// What was wrong.
        reason: String,
    },
    /// A file could not be read for a reason other than not existing.
    #[error("failed to read {path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// The shape of `~/.elestio/credentials` (R1).
#[derive(Deserialize)]
struct CredentialsFile {
    email: Option<String>,
    #[serde(rename = "apiToken")]
    api_token: Option<String>,
}

/// The subset of `~/.elestio/config.json` this tool reads (R2). Unknown
/// fields are ignored by default in serde, which is exactly what we want.
#[derive(Deserialize, Default)]
struct ConfigFile {
    #[serde(rename = "defaultProject")]
    default_project: Option<JsonStringOrNumber>,
    jwt: Option<String>,
    #[serde(rename = "jwtExpiry")]
    jwt_expiry: Option<u64>,
}

/// The official CLI stores `defaultProject` as a string, but it is a number
/// in the API, so accept either.
#[derive(Deserialize)]
#[serde(untagged)]
enum JsonStringOrNumber {
    Str(String),
    Num(u64),
}

impl fmt::Display for JsonStringOrNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonStringOrNumber::Str(s) => f.write_str(s),
            JsonStringOrNumber::Num(n) => write!(f, "{n}"),
        }
    }
}

/// Environment values, passed in explicitly so tests do not have to mutate
/// the process environment (which is racy across threads).
#[derive(Debug, Default, Clone)]
pub struct EnvOverrides {
    /// Value of `ELESTIO_EMAIL`, if set.
    pub email: Option<String>,
    /// Value of `ELESTIO_API_TOKEN`, if set; redacted in `Debug`.
    pub api_token: Option<Secret>,
}

impl EnvOverrides {
    /// Read the overrides from the real process environment. Empty strings
    /// count as unset.
    pub fn from_process_env() -> Self {
        let non_empty = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        EnvOverrides {
            email: non_empty(ENV_EMAIL),
            api_token: non_empty(ENV_API_TOKEN).map(Secret::new),
        }
    }
}

/// Path of the config directory under `home`.
pub fn config_dir(home: &Path) -> PathBuf {
    home.join(CONFIG_DIR)
}

/// Resolve the user's home directory from `HOME` (or `USERPROFILE` on
/// Windows). Returns `None` when neither is set.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Load settings from `home/.elestio/*` and the given environment overrides.
///
/// Precedence (R3): environment credentials win over the file. When the
/// environment supplies either value, the cached JWT is ignored because it
/// may belong to a different account.
pub fn load(home: &Path, env: &EnvOverrides) -> Result<Settings, ConfigError> {
    let dir = config_dir(home);
    let credentials_path = dir.join(CREDENTIALS_FILE);
    let config_path = dir.join(CONFIG_FILE);
    let mut warnings = Vec::new();

    let env_supplied = env.email.is_some() || env.api_token.is_some();

    // R1: the file the official CLI writes.
    let file_creds = read_credentials_file(&credentials_path, &mut warnings)?;

    // R3: environment takes precedence, field by field.
    let email = env
        .email
        .clone()
        .or_else(|| file_creds.as_ref().and_then(|c| c.email.clone()));
    let api_token = env.api_token.clone().or_else(|| {
        file_creds
            .as_ref()
            .and_then(|c| c.api_token.clone())
            .map(Secret::new)
    });

    let credentials = match (email, api_token) {
        (Some(email), Some(api_token)) if !email.is_empty() && !api_token.is_empty() => {
            Credentials {
                email,
                api_token,
                source: if env_supplied {
                    CredentialSource::Environment
                } else {
                    CredentialSource::File
                },
            }
        }
        // R5: name the path and both variables.
        _ => {
            return Err(ConfigError::NoCredentials {
                path: credentials_path,
                env_email: ENV_EMAIL,
                env_token: ENV_API_TOKEN,
            })
        }
    };

    // R2: defaults and cached JWT. A missing file is not an error.
    let config = read_config_file(&config_path)?;
    let default_project = config.default_project.as_ref().map(|p| p.to_string());
    let cached_jwt = if env_supplied {
        None
    } else {
        match (config.jwt, config.jwt_expiry) {
            (Some(jwt), Some(expires_at_ms)) if !jwt.is_empty() => Some(CachedJwt {
                jwt: Secret::new(jwt),
                expires_at_ms,
            }),
            _ => None,
        }
    };

    Ok(Settings {
        credentials,
        default_project,
        cached_jwt,
        warnings,
    })
}

fn read_credentials_file(
    path: &Path,
    warnings: &mut Vec<String>,
) -> Result<Option<CredentialsFile>, ConfigError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };

    // R4: warn on loose permissions, Unix only.
    if let Some(w) = permission_warning(path) {
        warnings.push(w);
    }

    let parsed: CredentialsFile =
        serde_json::from_slice(&bytes).map_err(|e| ConfigError::MalformedCredentials {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
    Ok(Some(parsed))
}

fn read_config_file(path: &Path) -> Result<ConfigFile, ConfigError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| ConfigError::MalformedConfig {
            path: path.to_path_buf(),
            reason: e.to_string(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConfigFile::default()),
        Err(source) => Err(ConfigError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// R4: on Unix, return a warning when any group or other permission bit is
/// set on the credentials file. `0o077` masks exactly those bits, so `0600`
/// and `0400` pass and `0644` does not.
#[cfg(unix)]
fn permission_warning(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        Some(format!(
            "warning: {} has mode {:04o}; it should be 0600 so other users cannot read your API token",
            path.display(),
            mode
        ))
    } else {
        None
    }
}

/// R4: no mode bits on non-Unix platforms, so no check.
#[cfg(not(unix))]
fn permission_warning(_path: &Path) -> Option<String> {
    None
}
