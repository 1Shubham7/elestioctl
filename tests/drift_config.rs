//! R32 to R36: the drift TOML file.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use elestioctl::diff::{FirewallMode, Rule};
use elestioctl::drift_config::{self, DriftConfigError};

const SPEC_EXAMPLE: &str = r#"
# Optional. Falls back to --project, then defaultProject.
project = "112"

[[service]]
id            = "41928"        # required; string or integer
project       = "112"          # optional per-service override
name          = "prod-postgres"
server_type   = "MEDIUM-2C-4G"
provider      = "hetzner"
datacenter    = "hel1"
version       = "16"
firewall_mode = "subset"       # "subset" (default) or "exact"

  [[service.firewall]]
  type     = "INPUT"
  port     = "22"
  protocol = "tcp"
  targets  = ["0.0.0.0/0", "::/0"]
"#;

fn targets(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn r32_parses_the_spec_example() {
    let cfg = drift_config::parse(SPEC_EXAMPLE).expect("parses");
    assert_eq!(cfg.project.as_deref(), Some("112"));
    assert_eq!(cfg.services.len(), 1);
    let s = &cfg.services[0];
    assert_eq!(s.id, "41928");
    assert_eq!(s.project.as_deref(), Some("112"));
    assert_eq!(s.name.as_deref(), Some("prod-postgres"));
    assert_eq!(s.server_type.as_deref(), Some("MEDIUM-2C-4G"));
    assert_eq!(s.provider.as_deref(), Some("hetzner"));
    assert_eq!(s.datacenter.as_deref(), Some("hel1"));
    assert_eq!(s.version.as_deref(), Some("16"));
    assert_eq!(s.firewall_mode, FirewallMode::Subset);
    let rules = s.firewall.as_ref().expect("firewall declared");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule_type, "INPUT");
    assert_eq!(rules[0].port, "22");
    assert_eq!(rules[0].protocol, "tcp");
    assert_eq!(rules[0].targets, targets(&["0.0.0.0/0", "::/0"]));
}

#[test]
fn r32_id_may_be_an_integer() {
    let cfg = drift_config::parse("[[service]]\nid = 41928\n").expect("parses");
    assert_eq!(cfg.services[0].id, "41928");
}

#[test]
fn r32_id_may_be_a_string() {
    let cfg = drift_config::parse("[[service]]\nid = \"41928\"\n").expect("parses");
    assert_eq!(cfg.services[0].id, "41928");
}

#[test]
fn r32_firewall_mode_defaults_to_subset() {
    let cfg = drift_config::parse("[[service]]\nid = \"1\"\n").expect("parses");
    assert_eq!(cfg.services[0].firewall_mode, FirewallMode::Subset);
    assert_eq!(FirewallMode::default(), FirewallMode::Subset);
}

#[test]
fn r32_firewall_mode_exact_is_accepted() {
    let cfg = drift_config::parse("[[service]]\nid = \"1\"\nfirewall_mode = \"exact\"\n")
        .expect("parses");
    assert_eq!(cfg.services[0].firewall_mode, FirewallMode::Exact);
}

#[test]
fn r32_unknown_firewall_mode_is_rejected() {
    let err = drift_config::parse("[[service]]\nid = \"1\"\nfirewall_mode = \"fuzzy\"\n")
        .expect_err("must fail");
    assert!(matches!(err, DriftConfigError::Toml { .. }), "got {err:?}");
}

#[test]
fn r32_top_level_project_is_optional() {
    let cfg = drift_config::parse("[[service]]\nid = \"1\"\n").expect("parses");
    assert_eq!(cfg.project, None);
}

#[test]
fn r32_services_keep_file_order() {
    let text = "[[service]]\nid = \"3\"\n[[service]]\nid = \"1\"\n[[service]]\nid = \"2\"\n";
    let cfg = drift_config::parse(text).expect("parses");
    let ids: Vec<&str> = cfg.services.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, ["3", "1", "2"]);
}

#[test]
fn r32_resolve_project_precedence_per_service_then_top_level_then_fallback() {
    let text = r#"
project = "top"

[[service]]
id = "a"
project = "own"

[[service]]
id = "b"
"#;
    let cfg = drift_config::parse(text).expect("parses");
    let resolved = cfg.resolve(Some("fallback")).expect("resolves");
    assert_eq!(resolved[0].id, "a");
    assert_eq!(resolved[0].project, "own", "per-service override wins");
    assert_eq!(resolved[1].id, "b");
    assert_eq!(resolved[1].project, "top", "top-level next");

    let cfg = drift_config::parse("[[service]]\nid = \"c\"\n").expect("parses");
    let resolved = cfg.resolve(Some("fallback")).expect("resolves");
    assert_eq!(resolved[0].project, "fallback", "then the fallback");
}

#[test]
fn r22_resolve_without_any_project_names_the_service_and_the_fix() {
    let cfg = drift_config::parse("[[service]]\nid = \"orphan\"\n").expect("parses");
    let err = cfg.resolve(None).expect_err("must fail");
    assert!(
        matches!(err, DriftConfigError::NoProject { .. }),
        "got {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains("orphan"), "names the service: {msg}");
    assert!(msg.contains("--project"), "names --project: {msg}");
    assert!(
        msg.contains("elestio config --set-default-project"),
        "names the official command: {msg}"
    );
}

#[test]
fn r32_resolve_carries_every_declared_field() {
    let cfg = drift_config::parse(SPEC_EXAMPLE).expect("parses");
    let resolved = cfg.resolve(None).expect("resolves");
    let d = &resolved[0];
    assert_eq!(d.id, "41928");
    assert_eq!(d.project, "112");
    assert_eq!(d.name.as_deref(), Some("prod-postgres"));
    assert_eq!(d.server_type.as_deref(), Some("MEDIUM-2C-4G"));
    assert_eq!(d.provider.as_deref(), Some("hetzner"));
    assert_eq!(d.datacenter.as_deref(), Some("hel1"));
    assert_eq!(d.version.as_deref(), Some("16"));
    assert_eq!(d.firewall_mode, FirewallMode::Subset);
    assert_eq!(
        d.firewall,
        Some(vec![Rule::new(
            "INPUT",
            "22",
            "tcp",
            ["0.0.0.0/0".to_string(), "::/0".to_string()]
        )])
    );
}

#[test]
fn r33_every_field_except_id_is_optional() {
    let cfg = drift_config::parse("[[service]]\nid = \"1\"\n").expect("id alone is enough");
    let s = &cfg.services[0];
    assert_eq!(s.project, None);
    assert_eq!(s.name, None);
    assert_eq!(s.server_type, None);
    assert_eq!(s.provider, None);
    assert_eq!(s.datacenter, None);
    assert_eq!(s.version, None);
    assert_eq!(s.firewall, None, "absent firewall key means do not check");
}

#[test]
fn r33_explicit_empty_firewall_is_some_empty_not_none() {
    let cfg = drift_config::parse("[[service]]\nid = \"1\"\nfirewall = []\n").expect("parses");
    assert_eq!(cfg.services[0].firewall, Some(vec![]));
}

#[test]
fn r33_partial_declaration_leaves_other_fields_none() {
    let cfg = drift_config::parse("[[service]]\nid = \"1\"\nversion = \"16\"\n").expect("parses");
    let s = &cfg.services[0];
    assert_eq!(s.version.as_deref(), Some("16"));
    assert_eq!(s.name, None);
    assert_eq!(s.firewall, None);
}

#[test]
fn r34_malformed_toml_names_the_line() {
    // Line 1 is blank, line 2 is fine, line 3 is broken.
    let text = "\n[[service]]\nid = \"1\" oops this is not toml\n";
    let err = drift_config::parse(text).expect_err("must fail");
    assert!(matches!(err, DriftConfigError::Toml { .. }), "got {err:?}");
    let msg = err.to_string();
    assert!(
        msg.contains("line 3"),
        "parse error must name line 3: {msg}"
    );
}

#[test]
fn r34_unterminated_string_names_the_line() {
    let text = "project = \"112\"\n\n[[service]]\nid = \"1\nname = \"x\"\n";
    let err = drift_config::parse(text).expect_err("must fail");
    assert!(matches!(err, DriftConfigError::Toml { .. }), "got {err:?}");
    assert!(err.to_string().contains("line 4"), "{err}");
}

#[test]
fn r34_load_reports_a_missing_file_as_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.toml");
    let err = drift_config::load(&missing).expect_err("must fail");
    assert!(matches!(err, DriftConfigError::Io { .. }), "got {err:?}");
    assert!(
        err.to_string().contains("nope.toml"),
        "names the path: {err}"
    );
}

#[test]
fn r34_load_reads_a_file_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("drift.toml");
    std::fs::write(&p, SPEC_EXAMPLE).unwrap();
    let cfg = drift_config::load(&p).expect("loads");
    assert_eq!(cfg.services[0].id, "41928");
}

#[test]
fn r35_service_without_id_names_its_zero_based_index() {
    let text = r#"
[[service]]
id = "1"

[[service]]
id = "2"

[[service]]
name = "no-id-here"
"#;
    let err = drift_config::parse(text).expect_err("must fail");
    assert!(
        matches!(err, DriftConfigError::MissingId { .. }),
        "must be a validation error, not a TOML error: {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains('2'), "names index 2: {msg}");
    assert!(!msg.contains("index 3"), "zero-based, not one-based: {msg}");
}

#[test]
fn r35_first_service_without_id_is_index_zero() {
    let err = drift_config::parse("[[service]]\nname = \"x\"\n").expect_err("must fail");
    assert!(
        matches!(err, DriftConfigError::MissingId { .. }),
        "got {err:?}"
    );
    assert!(err.to_string().contains('0'), "{err}");
}

#[test]
fn r36_duplicate_ids_name_the_id() {
    let text = "[[service]]\nid = \"41928\"\n[[service]]\nid = \"7\"\n[[service]]\nid = 41928\n";
    let err = drift_config::parse(text).expect_err("must fail");
    assert!(
        matches!(err, DriftConfigError::DuplicateId { .. }),
        "got {err:?}"
    );
    assert!(err.to_string().contains("41928"), "names the id: {err}");
}

#[test]
fn r36_distinct_ids_are_fine() {
    let text = "[[service]]\nid = \"1\"\n[[service]]\nid = \"2\"\n";
    assert!(drift_config::parse(text).is_ok());
}

#[test]
fn r32_empty_file_is_a_valid_config_with_no_services() {
    let cfg = drift_config::parse("").expect("empty config parses");
    assert!(cfg.services.is_empty());
    assert_eq!(cfg.project, None);
    assert!(cfg.resolve(None).unwrap().is_empty());
}

#[test]
fn r40_declared_rules_are_canonicalised_on_parse() {
    let text = r#"
[[service]]
id = "1"
  [[service.firewall]]
  type = "input"
  port = "22"
  protocol = "TCP"
  targets = ["::/0", "0.0.0.0/0", "::/0"]
"#;
    let cfg = drift_config::parse(text).expect("parses");
    let rule = &cfg.services[0].firewall.as_ref().unwrap()[0];
    assert_eq!(rule.rule_type, "INPUT");
    assert_eq!(rule.protocol, "tcp");
    assert_eq!(rule.targets, targets(&["0.0.0.0/0", "::/0"]));
}
