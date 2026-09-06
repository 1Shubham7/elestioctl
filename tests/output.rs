//! R8, R19, R23, R24, R25, R28, R30, R31: human and JSON rendering of the
//! read-only commands, snapshotted with insta.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use elestioctl::commands::{AuthReport, FirewallReport};
use elestioctl::config::CredentialSource;
use elestioctl::model::{FirewallRule, Service, OPEN_TARGETS};
use elestioctl::output::{self, OPEN_MARKER};
use serde_json::json;

fn service(id: &str, name: &str) -> Service {
    Service {
        id: id.to_string(),
        name: Some(name.to_string()),
        template: Some("PostgreSQL".into()),
        version: Some("16".into()),
        provider: Some("hetzner".into()),
        datacenter: Some("hel1".into()),
        server_type: Some("MEDIUM-2C-4G".into()),
        status: Some("running".into()),
        deployment_status: Some("Deployed".into()),
        firewall_enabled: true,
        ipv4: Some("10.0.0.1".into()),
        cname: Some("prod-postgres.example.elest.io".into()),
    }
}

fn services() -> Vec<Service> {
    vec![
        service("41928", "prod-postgres"),
        Service {
            template: Some("Redis".into()),
            version: Some("7.2".into()),
            provider: Some("scaleway".into()),
            datacenter: Some("fr-par-1".into()),
            server_type: Some("SMALL-1C-2G".into()),
            status: Some("off".into()),
            deployment_status: Some("IN PROGRESS".into()),
            firewall_enabled: false,
            ..service("7", "cache")
        },
        Service {
            name: None,
            template: None,
            version: None,
            provider: None,
            datacenter: None,
            server_type: None,
            status: None,
            deployment_status: None,
            ipv4: None,
            cname: None,
            ..service("123456", "")
        },
    ]
}

fn rule(t: &str, port: &str, proto: &str, targets: &[&str]) -> FirewallRule {
    FirewallRule {
        rule_type: t.to_string(),
        port: port.to_string(),
        protocol: proto.to_string(),
        targets: targets.iter().map(|s| s.to_string()).collect(),
    }
}

fn rules() -> Vec<FirewallRule> {
    vec![
        rule("INPUT", "22", "tcp", &["0.0.0.0/0", "::/0"]),
        rule("INPUT", "5432", "tcp", &["10.0.0.0/8", "192.168.1.0/24"]),
        rule("INPUT", "8000-9000", "udp", &["10.0.0.0/8", "::/0"]),
        rule("OUTPUT", "443", "tcp", &["0.0.0.0/0"]),
    ]
}

fn no_ansi(s: &str) {
    assert!(!s.contains('\x1b'), "R8: ANSI escape found in {s:?}");
}

// --------------------------------------------------------------------- R19

#[test]
fn r19_auth_human_prints_the_email() {
    let r = AuthReport {
        authenticated: true,
        email: "qa@example.com".into(),
        source: CredentialSource::File,
    };
    let out = output::auth_human(&r);
    assert!(out.contains("qa@example.com"), "{out}");
    no_ansi(&out);
    insta::assert_snapshot!("r19_auth_human", out);
}

#[test]
fn r19_auth_json_has_authenticated_and_email() {
    let r = AuthReport {
        authenticated: true,
        email: "qa@example.com".into(),
        source: CredentialSource::Environment,
    };
    let v = output::auth_json(&r);
    assert_eq!(v["authenticated"], json!(true));
    assert_eq!(v["email"], json!("qa@example.com"));
}

// ---------------------------------------------------------------- R23, R24

#[test]
fn r23_services_human_column_order() {
    let out = output::services_human("112", &services());
    no_ansi(&out);
    let row = out
        .lines()
        .find(|l| l.contains("41928"))
        .expect("row for 41928");
    let cells = [
        "41928",
        "prod-postgres",
        "PostgreSQL",
        "16",
        "hetzner",
        "hel1",
        "MEDIUM-2C-4G",
        "running",
    ];
    let mut last = 0;
    for cell in cells {
        let pos = row[last..]
            .find(cell)
            .unwrap_or_else(|| panic!("{cell} missing or out of order in {row:?}"));
        last += pos + cell.len();
    }
    // The other rows are present too.
    assert!(out.contains("cache"));
    assert!(out.contains("scaleway"));
    assert!(out.contains("123456"));
}

#[test]
fn r8_services_human_columns_are_aligned_by_padding() {
    let out = output::services_human("112", &services());
    // Every data row starts its second column at the same offset: the id
    // column is padded to the widest id ("123456").
    let rows: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("41928") || l.starts_with("7 ") || l.starts_with("123456"))
        .collect();
    assert_eq!(rows.len(), 3, "{out}");
    let second_col: Vec<usize> = rows
        .iter()
        .map(|r| {
            let first_space = r.find(' ').unwrap();
            first_space + r[first_space..].len() - r[first_space..].trim_start().len()
        })
        .collect();
    assert!(
        second_col.iter().all(|c| *c == second_col[0]),
        "columns not aligned: {rows:?}"
    );
    assert!(!out.contains('\t'), "padding is spaces, not tabs");
}

#[test]
fn r23_services_human_snapshot() {
    insta::assert_snapshot!(
        "r23_services_human",
        output::services_human("112", &services())
    );
}

#[test]
fn r24_empty_service_list_is_reported_explicitly() {
    let out = output::services_human("112", &[]);
    assert!(!out.trim().is_empty(), "blank output is not allowed");
    assert!(
        out.to_lowercase().contains("no services"),
        "must say there are no services: {out:?}"
    );
    no_ansi(&out);
    insta::assert_snapshot!("r24_services_human_empty", out);
}

// --------------------------------------------------------------------- R25

#[test]
fn r25_services_json_has_exactly_the_nine_keys() {
    let v = output::services_json(&services());
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 3);
    for s in arr {
        let obj = s.as_object().expect("object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "datacenter",
                "deployment_status",
                "id",
                "name",
                "provider",
                "server_type",
                "status",
                "template",
                "version",
            ],
            "{s}"
        );
    }
    assert_eq!(
        arr[0],
        json!({
            "id": "41928",
            "name": "prod-postgres",
            "template": "PostgreSQL",
            "version": "16",
            "provider": "hetzner",
            "datacenter": "hel1",
            "server_type": "MEDIUM-2C-4G",
            "status": "running",
            "deployment_status": "Deployed"
        })
    );
    assert_eq!(arr[2]["id"], "123456");
    assert_eq!(arr[2]["name"], serde_json::Value::Null);
}

#[test]
fn r25_services_json_empty_is_empty_array() {
    assert_eq!(output::services_json(&[]), json!([]));
}

#[test]
fn r26_service_json_has_the_same_nine_keys() {
    let v = output::service_json(&service("41928", "prod-postgres"));
    let obj = v.as_object().expect("object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "datacenter",
            "deployment_status",
            "id",
            "name",
            "provider",
            "server_type",
            "status",
            "template",
            "version",
        ]
    );
    assert_eq!(v["id"], "41928");
}

#[test]
fn r26_service_human_shows_every_mapped_field() {
    let out = output::service_human(&service("41928", "prod-postgres"));
    no_ansi(&out);
    for needle in [
        "41928",
        "prod-postgres",
        "PostgreSQL",
        "16",
        "hetzner",
        "hel1",
        "MEDIUM-2C-4G",
        "running",
        "Deployed",
    ] {
        assert!(out.contains(needle), "{needle} missing from {out}");
    }
    insta::assert_snapshot!("r26_service_human", out);
}

#[test]
fn r28_secret_fields_never_appear_in_output() {
    // The model has no place for managedDBCLI or adminUser; the rendered
    // forms must not mention them either.
    let s = service("41928", "prod-postgres");
    let human = output::service_human(&s);
    let json = output::service_json(&s).to_string();
    let list_json = output::services_json(std::slice::from_ref(&s)).to_string();
    let list_human = output::services_human("112", std::slice::from_ref(&s));
    for text in [human, json, list_json, list_human] {
        assert!(!text.contains("managedDBCLI"), "{text}");
        assert!(!text.contains("adminUser"), "{text}");
        assert!(!text.contains("managed_db_cli"), "{text}");
        assert!(!text.contains("admin_user"), "{text}");
    }
}

// ---------------------------------------------------------------- R29 to R31

#[test]
fn r30_firewall_human_shows_type_port_protocol_and_joined_targets() {
    let report = FirewallReport {
        vm_id: "41928".into(),
        enabled: true,
        rules: rules(),
    };
    let out = output::firewall_human(&report);
    no_ansi(&out);
    let line = out
        .lines()
        .find(|l| l.contains("5432"))
        .expect("row for 5432");
    for needle in ["INPUT", "5432", "tcp", "10.0.0.0/8, 192.168.1.0/24"] {
        assert!(line.contains(needle), "{needle} missing from {line:?}");
    }
    let range = out
        .lines()
        .find(|l| l.contains("8000-9000"))
        .expect("row for range");
    assert!(range.contains("udp"));
    assert!(range.contains("10.0.0.0/8, ::/0"), "{range:?}");
}

#[test]
fn r30_firewall_human_snapshot() {
    let report = FirewallReport {
        vm_id: "41928".into(),
        enabled: true,
        rules: rules(),
    };
    insta::assert_snapshot!("r30_firewall_human", output::firewall_human(&report));
}

#[test]
fn r29_disabled_firewall_says_disabled_not_zero_rules() {
    let report = FirewallReport {
        vm_id: "41928".into(),
        enabled: false,
        rules: vec![],
    };
    let out = output::firewall_human(&report);
    assert!(
        out.to_lowercase().contains("disabled"),
        "must say the firewall is disabled: {out:?}"
    );
    no_ansi(&out);
    insta::assert_snapshot!("r29_firewall_human_disabled", out);

    let v = output::firewall_json(&report);
    assert_eq!(v["enabled"], json!(false));
}

#[test]
fn r31_open_to_internet_predicate() {
    assert_eq!(OPEN_TARGETS, ["0.0.0.0/0", "::/0"]);
    assert!(rule("INPUT", "22", "tcp", &["0.0.0.0/0"]).open_to_internet());
    assert!(rule("INPUT", "22", "tcp", &["::/0"]).open_to_internet());
    assert!(
        rule("INPUT", "22", "tcp", &["10.0.0.0/8", "::/0"]).open_to_internet(),
        "any open target is enough"
    );
    assert!(!rule("INPUT", "22", "tcp", &["10.0.0.0/8"]).open_to_internet());
    assert!(!rule("INPUT", "22", "tcp", &[]).open_to_internet());
    assert!(
        !rule("OUTPUT", "443", "tcp", &["0.0.0.0/0"]).open_to_internet(),
        "OUTPUT is never open"
    );
    assert!(
        !rule("INPUT", "22", "tcp", &["0.0.0.0/1"]).open_to_internet(),
        "targets compare exactly"
    );
}

#[test]
fn r31_open_rules_are_marked_in_human_output() {
    let report = FirewallReport {
        vm_id: "41928".into(),
        enabled: true,
        rules: rules(),
    };
    let out = output::firewall_human(&report);
    let line_for = |needle: &str| {
        out.lines()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("{needle} not in {out}"))
            .to_string()
    };
    assert!(line_for(" 22").contains(OPEN_MARKER), "{}", line_for(" 22"));
    assert!(
        line_for("8000-9000").contains(OPEN_MARKER),
        "mixed targets with ::/0 is open"
    );
    assert!(
        !line_for("5432").contains(OPEN_MARKER),
        "private targets are not marked"
    );
    assert!(
        !line_for("OUTPUT").contains(OPEN_MARKER),
        "OUTPUT with 0.0.0.0/0 is not marked"
    );
}

#[test]
fn r31_firewall_json_carries_open_to_internet_per_rule() {
    let report = FirewallReport {
        vm_id: "41928".into(),
        enabled: true,
        rules: rules(),
    };
    let v = output::firewall_json(&report);
    let arr = v["rules"].as_array().expect("rules array");
    assert_eq!(arr.len(), 4);
    assert_eq!(arr[0]["open_to_internet"], json!(true));
    assert_eq!(arr[1]["open_to_internet"], json!(false));
    assert_eq!(arr[2]["open_to_internet"], json!(true));
    assert_eq!(arr[3]["open_to_internet"], json!(false));
    for r in arr {
        assert!(r["open_to_internet"].is_boolean(), "{r}");
        assert!(r["type"].is_string(), "{r}");
        assert!(r["port"].is_string(), "{r}");
        assert!(r["protocol"].is_string(), "{r}");
        assert!(r["targets"].is_array(), "{r}");
    }
    assert_eq!(arr[1]["targets"], json!(["10.0.0.0/8", "192.168.1.0/24"]));
}

#[test]
fn r8_table_helper_pads_with_spaces_and_has_no_ansi() {
    let out = output::table(
        &["ID", "NAME"],
        &[
            vec!["1".into(), "a".into()],
            vec!["123456".into(), "bb".into()],
        ],
    );
    no_ansi(&out);
    assert!(!out.contains('\t'));
    let lines: Vec<&str> = out.lines().collect();
    let name_col = lines[0].find("NAME").unwrap();
    for l in lines
        .iter()
        .filter(|l| l.ends_with('a') || l.ends_with("bb"))
    {
        let col = l.find(['a', 'b']).unwrap();
        assert_eq!(col, name_col, "misaligned: {out}");
    }
}
