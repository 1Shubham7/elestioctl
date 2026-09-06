//! Data shapes returned by the API, and the normalised shapes this tool
//! exposes.
//!
//! The raw API objects are deliberately private. Field names, the
//! number-or-string `vmID`, and the `0`/`1` booleans are Elestio's concerns;
//! everything above this module sees the field names from `spec/SPEC.md`
//! section 1.1 and ordinary Rust types.
//!
//! Rust note: serde's `#[derive(Deserialize)]` fails on a type mismatch
//! (a number where a string was expected). The API sends `vmID` as either,
//! so those fields use a small custom deserializer instead of a plain
//! `String`. This is the Rust equivalent of the `FlexString` type in the Go
//! client.

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

/// A service as this tool presents it. Field names follow the spec's
/// mapping table (section 1.1), not the API's.
///
/// R25: serialising this yields exactly the nine keys the spec lists. The
/// extra fields are `skip`ped so the JSON contract stays fixed even if more
/// fields are added for human output later.
///
/// R28: `managedDBCLI` and `adminUser` are not fields here, so they cannot
/// be displayed by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Service {
    /// `vmID`, normalised to a string whether the API sent a number or a string.
    pub id: String,
    /// `displayName`.
    pub name: Option<String>,
    /// `templateName`.
    pub template: Option<String>,
    /// `selected_software_tag`.
    pub version: Option<String>,
    /// `provider`.
    pub provider: Option<String>,
    /// `datacenter`.
    pub datacenter: Option<String>,
    /// `serverType`.
    pub server_type: Option<String>,
    /// `status`, for example `running` or `off`.
    pub status: Option<String>,
    /// `deploymentStatus`, for example `Deployed` or `IN PROGRESS`.
    pub deployment_status: Option<String>,
    /// `isFirewallActivated` (R29). Not part of the JSON contract.
    #[serde(skip)]
    pub firewall_enabled: bool,
    /// `ipv4`. Not part of the JSON contract.
    #[serde(skip)]
    pub ipv4: Option<String>,
    /// `cname`. Not part of the JSON contract.
    #[serde(skip)]
    pub cname: Option<String>,
}

/// A firewall rule as the API returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    /// `INPUT` or `OUTPUT`. Named `rule_type` because `type` is a keyword.
    #[serde(rename = "type")]
    pub rule_type: String,
    /// A port (`"22"`) or a range (`"8000-9000"`).
    pub port: String,
    /// `tcp` or `udp`.
    pub protocol: String,
    /// CIDR blocks. The official CLI tolerates a bare string here, so we do too.
    #[serde(deserialize_with = "string_or_vec")]
    pub targets: Vec<String>,
}

/// The two wildcard targets the platform uses for "everyone" (R31).
pub const OPEN_TARGETS: [&str; 2] = ["0.0.0.0/0", "::/0"];

impl FirewallRule {
    /// R31: an `INPUT` rule with any wildcard target is open to the internet.
    /// `OUTPUT` rules are never flagged; egress is not exposure.
    pub fn open_to_internet(&self) -> bool {
        self.rule_type.eq_ignore_ascii_case("INPUT")
            && self
                .targets
                .iter()
                .any(|t| OPEN_TARGETS.contains(&t.as_str()))
    }
}

/// The raw service object from `getServices` and `getServerDetails`.
/// Every field except `vmID` is optional because the two endpoints do not
/// promise the same set and this tool must not panic on a missing one (R17).
#[derive(Deserialize)]
pub(crate) struct RawService {
    #[serde(rename = "vmID", deserialize_with = "string_or_number")]
    vm_id: String,
    #[serde(rename = "displayName", default)]
    display_name: Option<String>,
    #[serde(rename = "templateName", default)]
    template_name: Option<String>,
    #[serde(rename = "selected_software_tag", default)]
    selected_software_tag: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    datacenter: Option<String>,
    #[serde(rename = "serverType", default)]
    server_type: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(rename = "deploymentStatus", default)]
    deployment_status: Option<String>,
    #[serde(
        rename = "isFirewallActivated",
        default,
        deserialize_with = "number_as_bool"
    )]
    is_firewall_activated: bool,
    #[serde(default)]
    ipv4: Option<String>,
    #[serde(default)]
    cname: Option<String>,
}

impl From<RawService> for Service {
    fn from(raw: RawService) -> Self {
        Service {
            id: raw.vm_id,
            name: raw.display_name,
            template: raw.template_name,
            version: raw.selected_software_tag,
            provider: raw.provider,
            datacenter: raw.datacenter,
            server_type: raw.server_type,
            status: raw.status,
            deployment_status: raw.deployment_status,
            firewall_enabled: raw.is_firewall_activated,
            ipv4: raw.ipv4,
            cname: raw.cname,
        }
    }
}

/// Accept a JSON string or integer and produce a `String`.
fn string_or_number<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Flex {
        Str(String),
        Int(i64),
        Uint(u64),
    }
    Ok(match Flex::deserialize(d)? {
        Flex::Str(s) => s,
        Flex::Int(n) => n.to_string(),
        Flex::Uint(n) => n.to_string(),
    })
}

/// Accept `0`/`1`, `true`/`false`, or `"0"`/`"1"`/`"true"`/`"false"`.
/// The Go client documents this field as a number used as a boolean.
fn number_as_bool<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Flex {
        Bool(bool),
        Int(i64),
        Str(String),
    }
    match Option::<Flex>::deserialize(d)? {
        None => Ok(false),
        Some(Flex::Bool(b)) => Ok(b),
        Some(Flex::Int(n)) => Ok(n != 0),
        Some(Flex::Str(s)) => match s.as_str() {
            "1" | "true" | "TRUE" | "True" => Ok(true),
            "0" | "false" | "FALSE" | "False" | "" => Ok(false),
            other => Err(de::Error::custom(format!(
                "expected 0, 1, true or false, got {other:?}"
            ))),
        },
    }
}

/// Accept a JSON array of strings or a single string.
fn string_or_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Flex {
        Many(Vec<String>),
        One(String),
    }
    Ok(match Option::<Flex>::deserialize(d)? {
        None => Vec::new(),
        Some(Flex::Many(v)) => v,
        Some(Flex::One(s)) => vec![s],
    })
}
