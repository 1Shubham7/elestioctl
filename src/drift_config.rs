//! Declared state: the drift TOML file (R32 to R36).
//!
//! Parsing happens in two stages on purpose. Stage one is serde: the TOML
//! text becomes raw structs where `id` is optional. Stage two is
//! validation: missing ids (R35) and duplicate ids (R36) are checked in
//! plain Rust. If `id` were a required field in the serde struct, a missing
//! one would surface as a TOML parse error with a line number, and the spec
//! asks for a validation error naming the entry's index instead.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::diff::{Declared, FirewallMode, Rule};

/// Errors from reading or validating a drift config.
#[derive(Debug, thiserror::Error)]
pub enum DriftConfigError {
    /// The file could not be read.
    #[error("failed to read drift config {path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// R34: not valid TOML, or valid TOML of the wrong shape.
    #[error("TOML parse error at line {line}: {message}")]
    Toml {
        /// 1-based line of the error.
        line: usize,
        /// The parser's message, first line only, so the error stays on one line (R10).
        message: String,
    },
    /// R35: a `[[service]]` entry without an `id`.
    #[error("service entry at index {index} has no id")]
    MissingId {
        /// Zero-based index of the entry.
        index: usize,
    },
    /// R36: the same id declared twice.
    #[error("duplicate service id {id}")]
    DuplicateId {
        /// The repeated id.
        id: String,
    },
    /// R22, R32: a service with no project from any source.
    #[error(
        "service {id}: no project declared; set `project` in the config, pass --project, or set a default with `elestio config --set-default-project <id>`"
    )]
    NoProject {
        /// The service id.
        id: String,
    },
}

/// A TOML value that may be written as a string or an integer. Ids and
/// ports are strings in the API but people write `id = 41928` in TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum StringOrInt {
    Str(String),
    Int(i64),
}

impl StringOrInt {
    fn into_string(self) -> String {
        match self {
            StringOrInt::Str(s) => s,
            StringOrInt::Int(n) => n.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    project: Option<StringOrInt>,
    #[serde(default)]
    service: Vec<RawService>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    id: Option<StringOrInt>,
    project: Option<StringOrInt>,
    name: Option<String>,
    server_type: Option<String>,
    provider: Option<String>,
    datacenter: Option<String>,
    version: Option<StringOrInt>,
    #[serde(default)]
    firewall_mode: FirewallMode,
    firewall: Option<Vec<RawRule>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    #[serde(rename = "type")]
    rule_type: String,
    port: StringOrInt,
    protocol: String,
    #[serde(default)]
    targets: Vec<String>,
}

/// One `[[service]]` entry after validation, before project resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredEntry {
    /// The service's `vmID`.
    pub id: String,
    /// Per-service project override, if any.
    pub project: Option<String>,
    /// Declared `displayName`.
    pub name: Option<String>,
    /// Declared `serverType`.
    pub server_type: Option<String>,
    /// Declared `provider`.
    pub provider: Option<String>,
    /// Declared `datacenter`.
    pub datacenter: Option<String>,
    /// Declared `selected_software_tag`.
    pub version: Option<String>,
    /// Firewall comparison mode; defaults to subset.
    pub firewall_mode: FirewallMode,
    /// Declared rules, canonicalised. `None` when the key is absent (R33).
    pub firewall: Option<Vec<Rule>>,
}

/// A parsed and validated drift config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftConfig {
    /// Top-level `project`, if any.
    pub project: Option<String>,
    /// Services in file order.
    pub services: Vec<DeclaredEntry>,
}

impl DriftConfig {
    /// Resolve each service's project: per-service, then top-level, then the
    /// fallback (from `--project` or `defaultProject`). Fails naming the
    /// first service that has none.
    pub fn resolve(&self, fallback: Option<&str>) -> Result<Vec<Declared>, DriftConfigError> {
        self.services
            .iter()
            .map(|s| {
                let project = s
                    .project
                    .clone()
                    .or_else(|| self.project.clone())
                    .or_else(|| fallback.map(str::to_string))
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| DriftConfigError::NoProject { id: s.id.clone() })?;
                Ok(Declared {
                    id: s.id.clone(),
                    project,
                    name: s.name.clone(),
                    server_type: s.server_type.clone(),
                    provider: s.provider.clone(),
                    datacenter: s.datacenter.clone(),
                    version: s.version.clone(),
                    firewall_mode: s.firewall_mode,
                    firewall: s.firewall.clone(),
                })
            })
            .collect()
    }
}

/// Read and parse a drift config file (R32, R34).
pub fn load(path: &Path) -> Result<DriftConfig, DriftConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| DriftConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&text)
}

/// Parse drift config text (R32 to R36).
pub fn parse(text: &str) -> Result<DriftConfig, DriftConfigError> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| toml_error(text, &e))?;

    let mut services = Vec::with_capacity(raw.service.len());
    let mut seen = std::collections::BTreeSet::new();
    for (index, s) in raw.service.into_iter().enumerate() {
        // R35
        let id =
            s.id.map(StringOrInt::into_string)
                .filter(|id| !id.trim().is_empty())
                .ok_or(DriftConfigError::MissingId { index })?;
        // R36
        if !seen.insert(id.clone()) {
            return Err(DriftConfigError::DuplicateId { id });
        }
        let firewall = s.firewall.map(|rules| {
            rules
                .into_iter()
                .map(|r| Rule::new(&r.rule_type, &r.port.into_string(), &r.protocol, r.targets))
                .collect()
        });
        services.push(DeclaredEntry {
            id,
            project: s.project.map(StringOrInt::into_string),
            name: s.name,
            server_type: s.server_type,
            provider: s.provider,
            datacenter: s.datacenter,
            version: s.version.map(StringOrInt::into_string),
            firewall_mode: s.firewall_mode,
            firewall,
        });
    }

    Ok(DriftConfig {
        project: raw.project.map(StringOrInt::into_string),
        services,
    })
}

/// R34: turn a toml error into a one-line message with a line number.
fn toml_error(text: &str, e: &toml::de::Error) -> DriftConfigError {
    let line = e
        .span()
        .map(|span| text[..span.start.min(text.len())].matches('\n').count() + 1)
        .unwrap_or(1);
    let message = e
        .message()
        .lines()
        .next()
        .unwrap_or("invalid TOML")
        .trim()
        .to_string();
    DriftConfigError::Toml { line, message }
}
