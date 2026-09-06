//! Command logic, independent of argument parsing and printing.
//!
//! Each command is an `async fn` that takes a client and settings and returns
//! plain data. `src/main.rs` turns arguments into these calls and
//! `src/output.rs` turns the results into text. Keeping the three apart means
//! QA can drive a command against a mock server without spawning the binary,
//! and can snapshot the rendering without a server at all.

use std::time::SystemTime;

use crate::client::{ApiClient, ClientError};
use crate::config::{CredentialSource, Settings};
use crate::model::{FirewallRule, Service};

/// Errors a command can produce beyond what the client reports.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    /// R22: no `--project`, no `defaultProject`.
    #[error(
        "no project selected: pass --project <id> or set a default with `elestio config --set-default-project <id>`"
    )]
    NoProject,
    /// R27: the API returned no service for this id in this project.
    #[error("service {vm_id} not found in project {project}")]
    NotFound {
        /// The id that was asked for.
        vm_id: String,
        /// The project it was looked for in.
        project: String,
    },
    /// Anything the client reported (network, auth, parse, allowlist).
    #[error(transparent)]
    Client(#[from] ClientError),
}

/// How the client came to hold a JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSource {
    /// A fresh `checkAPIToken` call was made.
    SignedIn,
    /// The cached JWT from `config.json` was used (R2).
    Cached,
}

/// Make sure `client` holds a JWT, preferring the cached one when it is
/// fresh at `now` (R2) and signing in otherwise. Nothing is written back to
/// disk either way (R54).
pub async fn ensure_session(
    client: &mut ApiClient,
    settings: &Settings,
    now: SystemTime,
) -> Result<SessionSource, ClientError> {
    if let Some(cached) = &settings.cached_jwt {
        if cached.is_fresh_at(now) {
            client.set_jwt(cached.jwt.clone());
            return Ok(SessionSource::Cached);
        }
    }
    client.sign_in(&settings.credentials).await?;
    Ok(SessionSource::SignedIn)
}

/// R9, R21, R22: the project to operate on. The flag wins; otherwise the
/// config default; otherwise an error that says how to set one.
pub fn resolve_project(flag: Option<&str>, settings: &Settings) -> Result<String, CommandError> {
    flag.filter(|p| !p.is_empty())
        .map(str::to_string)
        .or_else(|| settings.default_project.clone().filter(|p| !p.is_empty()))
        .ok_or(CommandError::NoProject)
}

/// Result of `auth test`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthReport {
    /// Always `true` when this struct exists; failure is an error, not a report.
    pub authenticated: bool,
    /// R19: the email that authenticated.
    pub email: String,
    /// Where the credentials came from.
    pub source: CredentialSource,
}

/// R18: always sign in afresh, ignoring any cached JWT, and report the
/// identity that authenticated (R19). A rejection surfaces as
/// [`ClientError::AuthRejected`], distinct from the "no credentials" error
/// raised earlier by config loading (R20).
pub async fn auth_test(
    client: &mut ApiClient,
    settings: &Settings,
) -> Result<AuthReport, CommandError> {
    client.sign_in(&settings.credentials).await?;
    Ok(AuthReport {
        authenticated: true,
        email: settings.credentials.email.clone(),
        source: settings.credentials.source,
    })
}

/// R21: list services in `project`.
pub async fn list_services(
    client: &ApiClient,
    project: &str,
) -> Result<Vec<Service>, CommandError> {
    Ok(client.list_services(project).await?)
}

/// R26, R27: one service, or a `NotFound` error that names the id and
/// project and is a different variant from any network failure.
pub async fn get_service(
    client: &ApiClient,
    project: &str,
    vm_id: &str,
) -> Result<Service, CommandError> {
    client
        .get_service(project, vm_id)
        .await?
        .ok_or_else(|| CommandError::NotFound {
            vm_id: vm_id.to_string(),
            project: project.to_string(),
        })
}

/// Result of `firewall get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallReport {
    /// The service the rules belong to.
    pub vm_id: String,
    /// R29: `isFirewallActivated` from the service details.
    pub enabled: bool,
    /// Rules as the API lists them. Empty when the firewall is disabled.
    pub rules: Vec<FirewallRule>,
}

/// R29: fetch the service first to learn whether the firewall is enabled,
/// then the rules. A disabled firewall short-circuits to an empty rule list
/// rather than asking the action endpoint for rules that do not apply.
pub async fn firewall_get(
    client: &ApiClient,
    project: &str,
    vm_id: &str,
) -> Result<FirewallReport, CommandError> {
    let service = get_service(client, project, vm_id).await?;
    let rules = if service.firewall_enabled {
        client.get_firewall_rules(vm_id).await?
    } else {
        Vec::new()
    };
    Ok(FirewallReport {
        vm_id: service.id,
        enabled: service.firewall_enabled,
        rules,
    })
}

/// Result of `drift`: the resolved declarations and everything the API
/// reported, ready for the pure engine and the renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftReport {
    /// Differences in R42 order. Empty means no drift (R50).
    pub differences: Vec<crate::diff::Difference>,
    /// How many services were declared. Zero triggers a warning (R50).
    pub declared_count: usize,
}

impl DriftReport {
    /// R51: whether the process should exit 2.
    pub fn drift_detected(&self) -> bool {
        !self.differences.is_empty()
    }
}

/// R37: fetch actual state for every declared service and diff it.
///
/// For each declared service, `getServerDetails` is called in its resolved
/// project. An empty result becomes `None`, which the engine reports as
/// `Missing` (R39). Firewall rules are fetched only when the declaration
/// has a `firewall` key (R33) and the service says its firewall is enabled;
/// a disabled firewall means an empty actual rule set (R29). Any fetch
/// error aborts the whole command (R37): a partial report that exits 1
/// would be ambiguous to a CI gate.
pub async fn drift(
    client: &ApiClient,
    declared: &[crate::diff::Declared],
) -> Result<DriftReport, CommandError> {
    use crate::diff::{Actual, Rule};
    use std::collections::BTreeMap;

    let mut actual: BTreeMap<String, Actual> = BTreeMap::new();
    for d in declared {
        let Some(service) = client.get_service(&d.project, &d.id).await? else {
            continue;
        };
        let firewall = match (&d.firewall, service.firewall_enabled) {
            (Some(_), true) => client
                .get_firewall_rules(&d.id)
                .await?
                .iter()
                .map(Rule::from)
                .collect(),
            _ => Vec::new(),
        };
        actual.insert(
            d.id.clone(),
            Actual {
                name: service.name,
                server_type: service.server_type,
                provider: service.provider,
                datacenter: service.datacenter,
                version: service.version,
                firewall,
            },
        );
    }

    Ok(DriftReport {
        differences: crate::diff::diff(declared, &actual),
        declared_count: declared.len(),
    })
}
