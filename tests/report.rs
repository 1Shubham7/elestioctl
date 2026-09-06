//! R48, R49, R50: drift rendering. Exact strings where the spec gives them,
//! insta snapshots for the whole report.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use elestioctl::diff::{Difference, Rule};
use elestioctl::report::{self, NO_DRIFT};
use serde_json::{json, Value};

fn rule(t: &str, port: &str, proto: &str, targets: &[&str]) -> Rule {
    Rule::new(t, port, proto, targets.iter().map(|s| s.to_string()))
}

fn sample() -> Vec<Difference> {
    vec![
        Difference::Mismatch {
            service_id: "41928".into(),
            field: "name",
            declared: "prod-postgres".into(),
            actual: Some("staging-postgres".into()),
        },
        Difference::Mismatch {
            service_id: "41928".into(),
            field: "version",
            declared: "16".into(),
            actual: None,
        },
        Difference::Absent {
            service_id: "41928".into(),
            rule: rule("INPUT", "22", "tcp", &["0.0.0.0/0", "::/0"]),
        },
        Difference::Unexpected {
            service_id: "41928".into(),
            rule: rule("OUTPUT", "8000-9000", "udp", &["10.0.0.0/8"]),
        },
        Difference::Missing {
            service_id: "555".into(),
            project: "112".into(),
        },
    ]
}

#[test]
fn r48_mismatch_line_format() {
    let d = Difference::Mismatch {
        service_id: "41928".into(),
        field: "server_type",
        declared: "MEDIUM-2C-4G".into(),
        actual: Some("SMALL-1C-2G".into()),
    };
    assert_eq!(
        report::render_line(&d),
        "41928 server_type: declared=MEDIUM-2C-4G actual=SMALL-1C-2G"
    );
}

#[test]
fn r48_missing_line_format() {
    let d = Difference::Missing {
        service_id: "41928".into(),
        project: "112".into(),
    };
    assert_eq!(
        report::render_line(&d),
        "41928 missing: service not found in project 112"
    );
}

#[test]
fn r48_firewall_absent_line_format() {
    let d = Difference::Absent {
        service_id: "41928".into(),
        rule: rule("input", "22", "TCP", &["::/0", "0.0.0.0/0"]),
    };
    assert_eq!(
        report::render_line(&d),
        "41928 firewall absent: INPUT 22/tcp [0.0.0.0/0, ::/0]"
    );
}

#[test]
fn r48_firewall_unexpected_line_format() {
    let d = Difference::Unexpected {
        service_id: "41928".into(),
        rule: rule("OUTPUT", "8000-9000", "udp", &["10.0.0.0/8"]),
    };
    assert_eq!(
        report::render_line(&d),
        "41928 firewall unexpected: OUTPUT 8000-9000/udp [10.0.0.0/8]"
    );
}

#[test]
fn r48_render_line_has_no_trailing_newline() {
    for d in sample() {
        let line = report::render_line(&d);
        assert!(!line.ends_with('\n'), "{line:?}");
        assert!(!line.contains('\n'), "one line per difference: {line:?}");
    }
}

#[test]
fn r48_render_human_is_one_line_per_difference_in_given_order() {
    let diffs = sample();
    let out = report::render_human(&diffs);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), diffs.len());
    for (line, d) in lines.iter().zip(diffs.iter()) {
        assert_eq!(*line, report::render_line(d));
    }
    assert!(
        !out.contains("No drift"),
        "a report with drift has no no-drift line"
    );
    assert!(!out.contains('\x1b'), "R8: no ANSI escape codes");
}

#[test]
fn r48_human_report_snapshot() {
    insta::assert_snapshot!("r48_human_report", report::render_human(&sample()));
}

#[test]
fn r50_no_drift_exact_string() {
    assert_eq!(NO_DRIFT, "No drift detected.");
    let out = report::render_human(&[]);
    assert_eq!(out.trim_end_matches('\n'), "No drift detected.");
    insta::assert_snapshot!("r50_no_drift", out);
}

#[test]
fn r49_json_shape() {
    let v = report::render_json(&sample());
    assert_eq!(v["drift_detected"], json!(true));
    let diffs = v["differences"].as_array().expect("array");
    assert_eq!(diffs.len(), 5);

    for d in diffs {
        let obj = d.as_object().expect("object");
        for key in ["kind", "service_id", "field", "declared", "actual"] {
            assert!(
                obj.contains_key(key),
                "every element carries the five spec keys, {key} missing: {d}"
            );
        }
        assert!(
            ["mismatch", "missing", "absent", "unexpected"].contains(&d["kind"].as_str().unwrap()),
            "{d}"
        );
    }

    assert_eq!(diffs[0]["kind"], "mismatch");
    assert_eq!(diffs[0]["service_id"], "41928");
    assert_eq!(diffs[0]["field"], "name");
    assert_eq!(diffs[0]["declared"], "prod-postgres");
    assert_eq!(diffs[0]["actual"], "staging-postgres");
    assert_eq!(diffs[1]["kind"], "mismatch");
    assert_eq!(diffs[1]["field"], "version");
    assert_eq!(diffs[1]["declared"], "16");
    assert_eq!(
        diffs[1]["actual"],
        Value::Null,
        "absent actual value is null"
    );

    assert_eq!(diffs[2]["kind"], "absent");
    assert_eq!(diffs[2]["service_id"], "41928");
    assert_eq!(diffs[2]["field"], "firewall");
    assert!(
        !diffs[2]["declared"].is_null(),
        "absent: the declared rule applies"
    );
    assert_eq!(diffs[2]["actual"], Value::Null);

    assert_eq!(diffs[3]["kind"], "unexpected");
    assert_eq!(diffs[3]["field"], "firewall");
    assert_eq!(diffs[3]["declared"], Value::Null);
    assert!(
        !diffs[3]["actual"].is_null(),
        "unexpected: the actual rule applies"
    );

    assert_eq!(diffs[4]["kind"], "missing");
    assert_eq!(diffs[4]["service_id"], "555");
    assert_eq!(diffs[4]["field"], "missing");
    assert_eq!(diffs[4]["declared"], Value::Null);
    assert_eq!(diffs[4]["actual"], Value::Null);
}

#[test]
fn r49_json_no_drift() {
    let v = report::render_json(&[]);
    assert_eq!(
        v,
        json!({ "drift_detected": false, "differences": [] }),
        "exactly the two keys, false and empty"
    );
}

#[test]
fn r49_json_snapshot() {
    let v = report::render_json(&sample());
    insta::assert_snapshot!("r49_json_report", serde_json::to_string_pretty(&v).unwrap());
}

#[test]
fn r47_rendering_is_deterministic() {
    let a = report::render_human(&sample());
    let b = report::render_human(&sample());
    assert_eq!(a.as_bytes(), b.as_bytes());
    assert_eq!(
        report::render_json(&sample()).to_string(),
        report::render_json(&sample()).to_string()
    );
}
