//! Rendering: data in, text or JSON out. No I/O; callers print.
//!
//! R8: human output is aligned with spaces and never contains ANSI escape
//! codes. There is no colour path to get wrong, so the "not a TTY" clause
//! of R8 is satisfied by construction.

use serde_json::{json, Value};

use crate::commands::{AuthReport, FirewallReport};
use crate::model::{FirewallRule, Service};

/// Render rows as a padded table. Each column is as wide as its widest
/// cell; columns are separated by two spaces; a dashed rule follows the
/// header. This mirrors the official CLI's table layout.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let render_row = |cells: Vec<&str>| -> String {
        let mut line = String::new();
        for (i, cell) in cells.iter().enumerate().take(cols) {
            if i > 0 {
                line.push_str("  ");
            }
            line.push_str(cell);
            // Pad every column except the last so lines have no trailing spaces.
            if i + 1 < cols {
                let pad = widths[i].saturating_sub(cell.chars().count());
                line.extend(std::iter::repeat_n(' ', pad));
            }
        }
        line
    };
    let mut out = String::new();
    out.push_str(&render_row(headers.to_vec()));
    out.push('\n');
    let rule: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    out.push_str(&render_row(rule.iter().map(String::as_str).collect()));
    out.push('\n');
    for row in rows {
        out.push_str(&render_row(row.iter().map(String::as_str).collect()));
        out.push('\n');
    }
    out
}

/// What to show for an optional string in human output.
fn show(value: &Option<String>) -> String {
    match value {
        Some(v) if !v.is_empty() => v.clone(),
        _ => "-".to_string(),
    }
}

/// R19: human output for `auth test`.
pub fn auth_human(report: &AuthReport) -> String {
    format!("Authenticated as {}\n", report.email)
}

/// R19: JSON output for `auth test`.
pub fn auth_json(report: &AuthReport) -> Value {
    json!({
        "authenticated": report.authenticated,
        "email": report.email,
        "credential_source": match report.source {
            crate::config::CredentialSource::File => "file",
            crate::config::CredentialSource::Environment => "environment",
        },
    })
}

/// R23, R24: human output for `services`.
pub fn services_human(project: &str, services: &[Service]) -> String {
    if services.is_empty() {
        return format!("No services in project {project}.\n");
    }
    let headers = [
        "ID",
        "NAME",
        "TEMPLATE",
        "VERSION",
        "PROVIDER",
        "DATACENTER",
        "SERVER TYPE",
        "STATUS",
    ];
    let rows: Vec<Vec<String>> = services
        .iter()
        .map(|s| {
            vec![
                s.id.clone(),
                show(&s.name),
                show(&s.template),
                show(&s.version),
                show(&s.provider),
                show(&s.datacenter),
                show(&s.server_type),
                show(&s.status),
            ]
        })
        .collect();
    table(&headers, &rows)
}

/// R25: JSON output for `services`: an array of normalised objects.
pub fn services_json(services: &[Service]) -> Value {
    json!(services)
}

/// R26: human output for `service <vmID>`.
pub fn service_human(s: &Service) -> String {
    let pairs = [
        ("ID", s.id.clone()),
        ("Name", show(&s.name)),
        ("Template", show(&s.template)),
        ("Version", show(&s.version)),
        ("Provider", show(&s.provider)),
        ("Datacenter", show(&s.datacenter)),
        ("Server type", show(&s.server_type)),
        ("Status", show(&s.status)),
        ("Deployment", show(&s.deployment_status)),
        ("IPv4", show(&s.ipv4)),
        ("CNAME", show(&s.cname)),
        (
            "Firewall",
            if s.firewall_enabled {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            },
        ),
    ];
    let width = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (k, v) in pairs {
        out.push_str(&format!("{k:<width$}  {v}\n"));
    }
    out
}

/// R26: JSON output for `service <vmID>`: the same nine keys as R25.
pub fn service_json(s: &Service) -> Value {
    json!(s)
}

/// Marker appended to open rules in human output (R31).
pub const OPEN_MARKER: &str = "OPEN TO INTERNET";

/// R29, R30, R31: human output for `firewall get`.
pub fn firewall_human(report: &FirewallReport) -> String {
    if !report.enabled {
        return format!("Firewall is disabled for service {}.\n", report.vm_id);
    }
    if report.rules.is_empty() {
        return format!(
            "Firewall is enabled for service {} with no rules.\n",
            report.vm_id
        );
    }
    let headers = ["TYPE", "PORT", "PROTOCOL", "TARGETS", ""];
    let rows: Vec<Vec<String>> = report
        .rules
        .iter()
        .map(|r| {
            vec![
                r.rule_type.clone(),
                r.port.clone(),
                r.protocol.clone(),
                r.targets.join(", "),
                if r.open_to_internet() {
                    OPEN_MARKER.to_string()
                } else {
                    String::new()
                },
            ]
        })
        .collect();
    table(&headers, &rows)
}

/// R31: JSON output for `firewall get`: each rule carries `open_to_internet`.
pub fn firewall_json(report: &FirewallReport) -> Value {
    json!({
        "vm_id": report.vm_id,
        "enabled": report.enabled,
        "rules": report.rules.iter().map(firewall_rule_json).collect::<Vec<_>>(),
    })
}

fn firewall_rule_json(rule: &FirewallRule) -> Value {
    json!({
        "type": rule.rule_type,
        "port": rule.port,
        "protocol": rule.protocol,
        "targets": rule.targets,
        "open_to_internet": rule.open_to_internet(),
    })
}
