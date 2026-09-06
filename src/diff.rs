//! The drift engine: pure functions from declared and actual state to a
//! list of differences (R37 to R47).
//!
//! There is no I/O in this module. No HTTP, no filesystem, no clock, no
//! environment, no logging. Functions take values and return values. That
//! is what makes it property-testable (feed it generated inputs and assert
//! invariants) and mutation-testable (flip an operator and see whether a
//! test notices) without a mock server in the way.
//!
//! Rust note on ownership: every function here borrows its inputs (`&`) and
//! returns freshly allocated output. Nothing is mutated in place. This keeps
//! the call sites free to reuse the declared config after diffing, and it
//! means a `Difference` owns its strings and can outlive both inputs, which
//! the report renderer relies on.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::model::FirewallRule;

/// How declared firewall rules compare with actual ones (R32, R41).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallMode {
    /// Every declared rule must exist; extra actual rules are ignored.
    #[default]
    Subset,
    /// The declared set must equal the actual set.
    Exact,
}

/// A firewall rule in canonical form (R40).
///
/// `rule_type` is upper-cased and `protocol` lower-cased on construction so
/// that `input`/`INPUT` and `TCP`/`tcp` compare equal. `targets` is a
/// `BTreeSet`, so order and duplicates do not matter and iteration is
/// sorted. `port` and each target are compared exactly.
///
/// The derived `Ord` compares fields in declaration order: type, port,
/// protocol, targets. That is exactly the sort order R42 asks for, so the
/// engine never writes a comparator by hand.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rule {
    /// `INPUT` or `OUTPUT`, upper-cased.
    pub rule_type: String,
    /// Port or range, exact.
    pub port: String,
    /// `tcp` or `udp`, lower-cased.
    pub protocol: String,
    /// CIDR targets as a set.
    pub targets: BTreeSet<String>,
}

impl Rule {
    /// Build a canonical rule from raw parts.
    pub fn new(
        rule_type: &str,
        port: &str,
        protocol: &str,
        targets: impl IntoIterator<Item = String>,
    ) -> Rule {
        // R40: type and protocol fold case; port and targets compare
        // exactly, so they are not trimmed or otherwise normalised.
        Rule {
            rule_type: rule_type.to_ascii_uppercase(),
            port: port.to_string(),
            protocol: protocol.to_ascii_lowercase(),
            targets: targets.into_iter().collect(),
        }
    }

    /// R48: `INPUT 22/tcp [0.0.0.0/0, ::/0]`.
    pub fn render(&self) -> String {
        let targets: Vec<&str> = self.targets.iter().map(String::as_str).collect();
        format!(
            "{} {}/{} [{}]",
            self.rule_type,
            self.port,
            self.protocol,
            targets.join(", ")
        )
    }
}

impl From<&FirewallRule> for Rule {
    fn from(r: &FirewallRule) -> Rule {
        Rule::new(
            &r.rule_type,
            &r.port,
            &r.protocol,
            r.targets.iter().cloned(),
        )
    }
}

/// What the user asserted about one service (R32, R33). `None` means "not
/// declared, do not check".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Declared {
    /// The service's `vmID`.
    pub id: String,
    /// The project the service is expected in, already resolved.
    pub project: String,
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
    /// How to compare `firewall`.
    pub firewall_mode: FirewallMode,
    /// Declared rules. `None` skips the check; `Some(vec![])` asserts there
    /// are none (R33).
    pub firewall: Option<Vec<Rule>>,
}

/// What the API reported for one service, reduced to the comparable fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Actual {
    /// `displayName`.
    pub name: Option<String>,
    /// `serverType`.
    pub server_type: Option<String>,
    /// `provider`.
    pub provider: Option<String>,
    /// `datacenter`.
    pub datacenter: Option<String>,
    /// `selected_software_tag`.
    pub version: Option<String>,
    /// Firewall rules. Empty when the firewall is disabled (R29).
    pub firewall: Vec<Rule>,
}

/// R43: the declaration that asserts every field of `actual`, in exact mode.
pub fn declare_all(id: &str, project: &str, actual: &Actual) -> Declared {
    Declared {
        id: id.to_string(),
        project: project.to_string(),
        name: actual.name.clone(),
        server_type: actual.server_type.clone(),
        provider: actual.provider.clone(),
        datacenter: actual.datacenter.clone(),
        version: actual.version.clone(),
        firewall_mode: FirewallMode::Exact,
        firewall: Some(actual.firewall.clone()),
    }
}

/// Scalar field names in report order (R42).
pub const SCALAR_FIELDS: [&str; 5] = ["name", "server_type", "provider", "datacenter", "version"];

/// The field name used for every firewall difference (R45).
pub const FIREWALL_FIELD: &str = "firewall";

/// One reported difference (R38, R39, R41).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Difference {
    /// A declared scalar field differs from the actual value.
    Mismatch {
        /// Service id.
        service_id: String,
        /// One of [`SCALAR_FIELDS`].
        field: &'static str,
        /// What the config says.
        declared: String,
        /// What the API says; `None` when the API did not report the field.
        actual: Option<String>,
    },
    /// The API returned nothing for this id in this project.
    Missing {
        /// Service id.
        service_id: String,
        /// Project searched.
        project: String,
    },
    /// A declared rule is not present.
    Absent {
        /// Service id.
        service_id: String,
        /// The rule.
        rule: Rule,
    },
    /// An actual rule was not declared (exact mode only).
    Unexpected {
        /// Service id.
        service_id: String,
        /// The rule.
        rule: Rule,
    },
}

impl Difference {
    /// The service this difference belongs to.
    pub fn service_id(&self) -> &str {
        match self {
            Difference::Mismatch { service_id, .. }
            | Difference::Missing { service_id, .. }
            | Difference::Absent { service_id, .. }
            | Difference::Unexpected { service_id, .. } => service_id,
        }
    }

    /// The field path: a scalar name, `firewall`, or `missing`.
    pub fn field(&self) -> &'static str {
        match self {
            Difference::Mismatch { field, .. } => field,
            Difference::Missing { .. } => "missing",
            Difference::Absent { .. } | Difference::Unexpected { .. } => FIREWALL_FIELD,
        }
    }
}

/// Diff one service. `actual` is `None` when the API returned nothing for
/// it (R39). Output order follows R42.
pub fn diff_service(declared: &Declared, actual: Option<&Actual>) -> Vec<Difference> {
    let id = &declared.id;
    let Some(actual) = actual else {
        return vec![Difference::Missing {
            service_id: id.clone(),
            project: declared.project.clone(),
        }];
    };

    let mut out = Vec::new();

    // R37, R38: only declared fields are compared, in R42 order.
    let scalars: [(&'static str, &Option<String>, &Option<String>); 5] = [
        ("name", &declared.name, &actual.name),
        ("server_type", &declared.server_type, &actual.server_type),
        ("provider", &declared.provider, &actual.provider),
        ("datacenter", &declared.datacenter, &actual.datacenter),
        ("version", &declared.version, &actual.version),
    ];
    for (field, wanted, got) in scalars {
        if let Some(wanted) = wanted {
            if got.as_deref() != Some(wanted.as_str()) {
                out.push(Difference::Mismatch {
                    service_id: id.clone(),
                    field,
                    declared: wanted.clone(),
                    actual: got.clone(),
                });
            }
        }
    }

    // R40, R41: set comparison. BTreeSet gives sorted iteration, so the
    // absent and unexpected groups come out in R42 order for free.
    if let Some(declared_rules) = &declared.firewall {
        let wanted: BTreeSet<&Rule> = declared_rules.iter().collect();
        let got: BTreeSet<&Rule> = actual.firewall.iter().collect();
        for rule in wanted.difference(&got) {
            out.push(Difference::Absent {
                service_id: id.clone(),
                rule: (*rule).clone(),
            });
        }
        if declared.firewall_mode == FirewallMode::Exact {
            for rule in got.difference(&wanted) {
                out.push(Difference::Unexpected {
                    service_id: id.clone(),
                    rule: (*rule).clone(),
                });
            }
        }
    }

    out
}

/// Diff every declared service against `actual`, keyed by service id.
/// Services are reported in declared order (R42). An id absent from the
/// map is `Missing` (R39).
pub fn diff(declared: &[Declared], actual: &BTreeMap<String, Actual>) -> Vec<Difference> {
    declared
        .iter()
        .flat_map(|d| diff_service(d, actual.get(&d.id)))
        .collect()
}
