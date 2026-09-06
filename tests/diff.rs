//! R38 to R42: the pure diff engine, example-based. Properties live in
//! `diff_props.rs`.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use elestioctl::diff::{
    self, Actual, Declared, Difference, FirewallMode, Rule, FIREWALL_FIELD, SCALAR_FIELDS,
};
use elestioctl::model::FirewallRule;

fn rule(t: &str, port: &str, proto: &str, targets: &[&str]) -> Rule {
    Rule::new(t, port, proto, targets.iter().map(|s| s.to_string()))
}

fn actual() -> Actual {
    Actual {
        name: Some("prod-postgres".into()),
        server_type: Some("MEDIUM-2C-4G".into()),
        provider: Some("hetzner".into()),
        datacenter: Some("hel1".into()),
        version: Some("16".into()),
        firewall: vec![
            rule("INPUT", "22", "tcp", &["0.0.0.0/0", "::/0"]),
            rule("INPUT", "5432", "tcp", &["10.0.0.0/8"]),
            rule("OUTPUT", "443", "tcp", &["0.0.0.0/0"]),
        ],
    }
}

fn declared(id: &str) -> Declared {
    Declared {
        id: id.to_string(),
        project: "112".to_string(),
        ..Default::default()
    }
}

#[test]
fn r38_mismatch_carries_id_field_declared_and_actual() {
    let d = Declared {
        name: Some("staging-postgres".into()),
        ..declared("41928")
    };
    let out = diff::diff_service(&d, Some(&actual()));
    assert_eq!(
        out,
        vec![Difference::Mismatch {
            service_id: "41928".into(),
            field: "name",
            declared: "staging-postgres".into(),
            actual: Some("prod-postgres".into()),
        }]
    );
    assert_eq!(out[0].service_id(), "41928");
    assert_eq!(out[0].field(), "name");
}

#[test]
fn r38_declared_field_absent_in_actual_is_a_mismatch_with_none() {
    let d = Declared {
        version: Some("16".into()),
        ..declared("1")
    };
    let a = Actual {
        version: None,
        ..actual()
    };
    let out = diff::diff_service(&d, Some(&a));
    assert_eq!(
        out,
        vec![Difference::Mismatch {
            service_id: "1".into(),
            field: "version",
            declared: "16".into(),
            actual: None,
        }]
    );
}

#[test]
fn r38_only_declared_fields_are_compared() {
    // Declares only `provider`, which matches; every other actual field is
    // different from anything a user might expect, and none of it matters.
    let d = Declared {
        provider: Some("hetzner".into()),
        ..declared("1")
    };
    assert!(diff::diff_service(&d, Some(&actual())).is_empty());
}

#[test]
fn r39_missing_service_is_a_missing_difference() {
    let d = Declared {
        name: Some("x".into()),
        firewall: Some(vec![rule("INPUT", "22", "tcp", &["0.0.0.0/0"])]),
        ..declared("41928")
    };
    let out = diff::diff_service(&d, None);
    assert_eq!(
        out,
        vec![Difference::Missing {
            service_id: "41928".into(),
            project: "112".into(),
        }],
        "a missing service yields exactly one Missing, no field diffs"
    );
    assert_eq!(out[0].field(), "missing");
}

#[test]
fn r39_id_absent_from_actual_map_is_missing() {
    let declared = vec![declared("1"), declared("2")];
    let mut map = BTreeMap::new();
    map.insert("1".to_string(), actual());
    let out = diff::diff(&declared, &map);
    assert_eq!(
        out,
        vec![Difference::Missing {
            service_id: "2".into(),
            project: "112".into(),
        }]
    );
}

#[test]
fn r40_rule_order_does_not_matter() {
    let a = actual();
    let mut reversed: Vec<Rule> = a.firewall.clone();
    reversed.reverse();
    let d = Declared {
        firewall: Some(reversed),
        firewall_mode: FirewallMode::Exact,
        ..declared("1")
    };
    assert!(diff::diff_service(&d, Some(&a)).is_empty());
}

#[test]
fn r40_type_and_protocol_compare_case_insensitively() {
    let d = Declared {
        firewall: Some(vec![rule("input", "22", "TCP", &["0.0.0.0/0", "::/0"])]),
        ..declared("1")
    };
    assert!(diff::diff_service(&d, Some(&actual())).is_empty());
    let r = Rule::new("OuTpUt", "1", "UdP", std::iter::empty());
    assert_eq!(r.rule_type, "OUTPUT");
    assert_eq!(r.protocol, "udp");
}

#[test]
fn r40_port_compares_exactly() {
    let d = Declared {
        firewall: Some(vec![rule("INPUT", "022", "tcp", &["0.0.0.0/0", "::/0"])]),
        ..declared("1")
    };
    let out = diff::diff_service(&d, Some(&actual()));
    assert_eq!(out.len(), 1, "\"022\" is not \"22\": {out:?}");
    assert!(matches!(out[0], Difference::Absent { .. }));
}

#[test]
fn r40_targets_compare_exactly_and_as_a_set() {
    // Same targets, other order: equal.
    let d = Declared {
        firewall: Some(vec![rule("INPUT", "22", "tcp", &["::/0", "0.0.0.0/0"])]),
        ..declared("1")
    };
    assert!(diff::diff_service(&d, Some(&actual())).is_empty());

    // Superset of targets: a different rule.
    let d = Declared {
        firewall: Some(vec![rule(
            "INPUT",
            "22",
            "tcp",
            &["0.0.0.0/0", "::/0", "10.0.0.0/8"],
        )]),
        ..declared("1")
    };
    let out = diff::diff_service(&d, Some(&actual()));
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(matches!(out[0], Difference::Absent { .. }));

    // Textually different CIDR for the same range: exact compare, different.
    let d = Declared {
        firewall: Some(vec![rule("INPUT", "5432", "tcp", &["10.0.0.0/08"])]),
        ..declared("1")
    };
    assert_eq!(diff::diff_service(&d, Some(&actual())).len(), 1);
}

#[test]
fn r40_duplicate_rules_collapse_to_one() {
    let a = actual();
    let mut dup_declared = a.firewall.clone();
    dup_declared.push(a.firewall[0].clone());
    dup_declared.push(a.firewall[1].clone());
    let d = Declared {
        firewall: Some(dup_declared),
        firewall_mode: FirewallMode::Exact,
        ..declared("1")
    };
    assert!(
        diff::diff_service(&d, Some(&a)).is_empty(),
        "duplicate declared rules are one rule"
    );

    let mut dup_actual = a.clone();
    dup_actual.firewall.push(a.firewall[2].clone());
    let d = Declared {
        firewall: Some(a.firewall.clone()),
        firewall_mode: FirewallMode::Exact,
        ..declared("1")
    };
    assert!(
        diff::diff_service(&d, Some(&dup_actual)).is_empty(),
        "duplicate actual rules are one rule"
    );
}

#[test]
fn r40_duplicate_targets_collapse_to_one() {
    let r = rule("INPUT", "22", "tcp", &["::/0", "::/0", "0.0.0.0/0"]);
    assert_eq!(r.targets.len(), 2);
    assert_eq!(r, rule("INPUT", "22", "tcp", &["0.0.0.0/0", "::/0"]));
}

#[test]
fn r40_rule_from_api_model_is_canonical() {
    let api = FirewallRule {
        rule_type: "input".into(),
        port: "22".into(),
        protocol: "Tcp".into(),
        targets: vec!["::/0".into(), "0.0.0.0/0".into(), "::/0".into()],
    };
    let r = Rule::from(&api);
    assert_eq!(r, rule("INPUT", "22", "tcp", &["0.0.0.0/0", "::/0"]));
}

#[test]
fn r41_declared_rule_not_in_actual_is_absent() {
    let want = rule("INPUT", "8080", "tcp", &["0.0.0.0/0"]);
    let d = Declared {
        firewall: Some(vec![want.clone()]),
        ..declared("1")
    };
    let out = diff::diff_service(&d, Some(&actual()));
    assert_eq!(
        out,
        vec![Difference::Absent {
            service_id: "1".into(),
            rule: want,
        }]
    );
    assert_eq!(out[0].field(), FIREWALL_FIELD);
}

#[test]
fn r41_subset_mode_never_reports_unexpected() {
    let d = Declared {
        firewall: Some(vec![rule("INPUT", "22", "tcp", &["0.0.0.0/0", "::/0"])]),
        firewall_mode: FirewallMode::Subset,
        ..declared("1")
    };
    let out = diff::diff_service(&d, Some(&actual()));
    assert!(
        out.is_empty(),
        "two extra actual rules are ignored: {out:?}"
    );

    let d = Declared {
        firewall: Some(vec![]),
        firewall_mode: FirewallMode::Subset,
        ..declared("1")
    };
    assert!(diff::diff_service(&d, Some(&actual())).is_empty());
}

#[test]
fn r41_exact_mode_reports_unexpected() {
    let a = actual();
    let d = Declared {
        firewall: Some(vec![a.firewall[0].clone()]),
        firewall_mode: FirewallMode::Exact,
        ..declared("1")
    };
    let out = diff::diff_service(&d, Some(&a));
    assert_eq!(
        out,
        vec![
            Difference::Unexpected {
                service_id: "1".into(),
                rule: a.firewall[1].clone(),
            },
            Difference::Unexpected {
                service_id: "1".into(),
                rule: a.firewall[2].clone(),
            },
        ]
    );
}

#[test]
fn r41_exact_mode_with_empty_declaration_reports_every_actual_rule() {
    let a = actual();
    let d = Declared {
        firewall: Some(vec![]),
        firewall_mode: FirewallMode::Exact,
        ..declared("1")
    };
    let out = diff::diff_service(&d, Some(&a));
    assert_eq!(out.len(), 3);
    assert!(out
        .iter()
        .all(|d| matches!(d, Difference::Unexpected { .. })));
}

#[test]
fn r33_firewall_none_skips_the_firewall_check_entirely() {
    let d = Declared {
        firewall: None,
        firewall_mode: FirewallMode::Exact,
        ..declared("1")
    };
    assert!(diff::diff_service(&d, Some(&actual())).is_empty());
}

#[test]
fn r42_scalar_field_order_is_fixed() {
    assert_eq!(
        SCALAR_FIELDS,
        ["name", "server_type", "provider", "datacenter", "version"]
    );
    let d = Declared {
        // Declared in a deliberately scrambled order; every one differs.
        version: Some("v".into()),
        datacenter: Some("d".into()),
        provider: Some("p".into()),
        server_type: Some("s".into()),
        name: Some("n".into()),
        ..declared("1")
    };
    let out = diff::diff_service(&d, Some(&actual()));
    let fields: Vec<&str> = out.iter().map(Difference::field).collect();
    assert_eq!(
        fields,
        ["name", "server_type", "provider", "datacenter", "version"]
    );
}

#[test]
fn r42_fields_before_firewall_absent_before_unexpected_each_sorted() {
    let a = actual();
    let d = Declared {
        version: Some("15".into()),
        name: Some("other".into()),
        firewall: Some(vec![
            // Two absent rules, listed here in reverse of their sort order.
            rule("OUTPUT", "53", "udp", &["8.8.8.8/32"]),
            rule("INPUT", "9000", "tcp", &["0.0.0.0/0"]),
            rule("INPUT", "80", "tcp", &["0.0.0.0/0"]),
            // One that matches.
            a.firewall[0].clone(),
        ]),
        firewall_mode: FirewallMode::Exact,
        ..declared("1")
    };
    let out = diff::diff_service(&d, Some(&a));
    let kinds: Vec<&str> = out
        .iter()
        .map(|d| match d {
            Difference::Mismatch { field, .. } => field,
            Difference::Missing { .. } => "missing",
            Difference::Absent { .. } => "absent",
            Difference::Unexpected { .. } => "unexpected",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "name",
            "version",
            "absent",
            "absent",
            "absent",
            "unexpected",
            "unexpected"
        ],
        "{out:?}"
    );

    // Absent group sorted by (type, port, protocol, targets): string order,
    // so "80" sorts after "9000" and INPUT before OUTPUT.
    let absent: Vec<&Rule> = out
        .iter()
        .filter_map(|d| match d {
            Difference::Absent { rule, .. } => Some(rule),
            _ => None,
        })
        .collect();
    assert_eq!(absent[0], &rule("INPUT", "80", "tcp", &["0.0.0.0/0"]));
    assert_eq!(absent[1], &rule("INPUT", "9000", "tcp", &["0.0.0.0/0"]));
    assert_eq!(absent[2], &rule("OUTPUT", "53", "udp", &["8.8.8.8/32"]));
    assert!(absent.windows(2).all(|w| w[0] <= w[1]));

    let unexpected: Vec<&Rule> = out
        .iter()
        .filter_map(|d| match d {
            Difference::Unexpected { rule, .. } => Some(rule),
            _ => None,
        })
        .collect();
    assert_eq!(unexpected[0], &a.firewall[1]);
    assert_eq!(unexpected[1], &a.firewall[2]);
    assert!(unexpected.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn r42_rule_ord_is_type_port_protocol_targets() {
    let a = rule("INPUT", "22", "tcp", &["0.0.0.0/0"]);
    let b = rule("INPUT", "22", "udp", &["0.0.0.0/0"]);
    let c = rule("INPUT", "23", "tcp", &["0.0.0.0/0"]);
    let d = rule("OUTPUT", "1", "tcp", &["0.0.0.0/0"]);
    let e = rule("INPUT", "22", "tcp", &["10.0.0.0/8"]);
    assert!(a < b, "protocol after port");
    assert!(b < c, "port before protocol");
    assert!(c < d, "type first");
    assert!(a < e, "targets last");
}

#[test]
fn r42_services_reported_in_declared_order() {
    let declared = vec![
        Declared {
            name: Some("x".into()),
            ..declared("9")
        },
        declared("5"),
        Declared {
            name: Some("y".into()),
            ..declared("1")
        },
    ];
    let mut map = BTreeMap::new();
    map.insert("9".to_string(), actual());
    map.insert("1".to_string(), actual());
    let out = diff::diff(&declared, &map);
    let ids: Vec<&str> = out.iter().map(Difference::service_id).collect();
    assert_eq!(ids, ["9", "5", "1"], "declared order, not sorted: {out:?}");
    assert!(matches!(out[1], Difference::Missing { .. }));
}

#[test]
fn r43_declare_all_asserts_every_field_in_exact_mode() {
    let a = actual();
    let d = diff::declare_all("41928", "112", &a);
    assert_eq!(d.id, "41928");
    assert_eq!(d.project, "112");
    assert_eq!(d.name, a.name);
    assert_eq!(d.server_type, a.server_type);
    assert_eq!(d.provider, a.provider);
    assert_eq!(d.datacenter, a.datacenter);
    assert_eq!(d.version, a.version);
    assert_eq!(d.firewall_mode, FirewallMode::Exact);
    assert_eq!(d.firewall.as_deref(), Some(a.firewall.as_slice()));
    assert!(diff::diff_service(&d, Some(&a)).is_empty());
}

#[test]
fn r48_rule_render_format() {
    assert_eq!(
        rule("input", "22", "TCP", &["::/0", "0.0.0.0/0"]).render(),
        "INPUT 22/tcp [0.0.0.0/0, ::/0]"
    );
    assert_eq!(
        rule("OUTPUT", "8000-9000", "udp", &["10.0.0.0/8"]).render(),
        "OUTPUT 8000-9000/udp [10.0.0.0/8]"
    );
    assert_eq!(rule("INPUT", "1", "tcp", &[]).render(), "INPUT 1/tcp []");
}
