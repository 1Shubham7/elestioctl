//! Rendering of drift differences (R48, R49, R50). Pure: strings and JSON
//! values in, no printing.

use serde_json::{json, Value};

use crate::diff::Difference;

/// R50: the exact line printed when there is nothing to report.
pub const NO_DRIFT: &str = "No drift detected.";

/// Human form of one difference, without a trailing newline (R48).
pub fn render_line(d: &Difference) -> String {
    match d {
        Difference::Mismatch {
            service_id,
            field,
            declared,
            actual,
        } => format!(
            "{service_id} {field}: declared={declared} actual={}",
            actual.as_deref().unwrap_or("(absent)")
        ),
        Difference::Missing {
            service_id,
            project,
        } => format!("{service_id} missing: service not found in project {project}"),
        Difference::Absent { service_id, rule } => {
            format!("{service_id} firewall absent: {}", rule.render())
        }
        Difference::Unexpected { service_id, rule } => {
            format!("{service_id} firewall unexpected: {}", rule.render())
        }
    }
}

/// R48, R50: the whole human report. One line per difference in the order
/// given (which is R42 order when it came from `diff::diff`), or the
/// no-drift line.
pub fn render_human(differences: &[Difference]) -> String {
    if differences.is_empty() {
        return format!("{NO_DRIFT}\n");
    }
    let mut out = String::new();
    for d in differences {
        out.push_str(&render_line(d));
        out.push('\n');
    }
    out
}

/// R49: `{ "drift_detected": bool, "differences": [...] }`. Every element
/// carries `kind`, `service_id`, `field`, `declared` and `actual`, with
/// `declared` and `actual` `null` where they do not apply. The `missing`
/// kind additionally carries `project`, so a consumer can see where the
/// service was looked for.
pub fn render_json(differences: &[Difference]) -> Value {
    let items: Vec<Value> = differences.iter().map(difference_json).collect();
    json!({
        "drift_detected": !differences.is_empty(),
        "differences": items,
    })
}

fn difference_json(d: &Difference) -> Value {
    match d {
        Difference::Mismatch {
            service_id,
            field,
            declared,
            actual,
        } => json!({
            "kind": "mismatch",
            "service_id": service_id,
            "field": field,
            "declared": declared,
            "actual": actual,
        }),
        Difference::Missing {
            service_id,
            project,
        } => json!({
            "kind": "missing",
            "service_id": service_id,
            "field": "missing",
            "declared": null,
            "actual": null,
            "project": project,
        }),
        Difference::Absent { service_id, rule } => json!({
            "kind": "absent",
            "service_id": service_id,
            "field": "firewall",
            "declared": rule.render(),
            "actual": null,
        }),
        Difference::Unexpected { service_id, rule } => json!({
            "kind": "unexpected",
            "service_id": service_id,
            "field": "firewall",
            "declared": null,
            "actual": rule.render(),
        }),
    }
}
