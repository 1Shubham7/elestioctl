//! Command layer against a wiremock server: R2, R9, R18 to R22, R26 to R29,
//! R33, R37, R39, R50, R51.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::SystemTime;

use elestioctl::client::ClientError;
use elestioctl::commands::{self, CommandError, SessionSource};
use elestioctl::config::CachedJwt;
use elestioctl::diff::{Declared, Difference, FirewallMode, Rule};
use elestioctl::secret::Secret;
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{
    body_json, client_for, mount_firewall_rules, mount_get_details, mount_get_services,
    mount_sign_in_ok, raw_rule, raw_service, requests_to, settings, signed_in_client, EMAIL,
    PATH_CHECK_TOKEN, PATH_DO_ACTION, PATH_GET_DETAILS, PATH_GET_SERVICES, PROJECT, VM_ID,
};

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn rule(t: &str, port: &str, proto: &str, targets: &[&str]) -> Rule {
    Rule::new(t, port, proto, targets.iter().map(|s| s.to_string()))
}

fn declared(id: &str) -> Declared {
    Declared {
        id: id.to_string(),
        project: PROJECT.to_string(),
        ..Default::default()
    }
}

// ------------------------------------------------------------- R2, R3, R18

#[tokio::test]
async fn r2_fresh_cached_jwt_is_used_without_signing_in() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;

    let mut s = settings();
    s.cached_jwt = Some(CachedJwt {
        jwt: Secret::new("cached-jwt-value"),
        expires_at_ms: now_ms() + 3_600_000,
    });
    let mut c = client_for(&server);
    let source = commands::ensure_session(&mut c, &s, SystemTime::now())
        .await
        .expect("ok");
    assert_eq!(source, SessionSource::Cached);
    assert!(c.is_signed_in());
    assert!(
        requests_to(&server, PATH_CHECK_TOKEN).await.is_empty(),
        "no sign-in request when the cache is fresh"
    );
}

#[tokio::test]
async fn r2_stale_cached_jwt_triggers_sign_in() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;

    let mut s = settings();
    s.cached_jwt = Some(CachedJwt {
        jwt: Secret::new("cached-jwt-value"),
        expires_at_ms: now_ms() + 60_000, // one minute left: not fresh
    });
    let mut c = client_for(&server);
    let source = commands::ensure_session(&mut c, &s, SystemTime::now())
        .await
        .expect("ok");
    assert_eq!(source, SessionSource::SignedIn);
    assert_eq!(requests_to(&server, PATH_CHECK_TOKEN).await.len(), 1);
}

#[tokio::test]
async fn r2_no_cached_jwt_triggers_sign_in() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;

    let s = settings();
    let mut c = client_for(&server);
    let source = commands::ensure_session(&mut c, &s, SystemTime::now())
        .await
        .expect("ok");
    assert_eq!(source, SessionSource::SignedIn);
    assert_eq!(requests_to(&server, PATH_CHECK_TOKEN).await.len(), 1);
}

#[tokio::test]
async fn r2_cached_jwt_is_the_one_sent_in_later_calls() {
    let server = MockServer::start().await;
    mount_get_services(&server, vec![]).await;

    let mut s = settings();
    s.cached_jwt = Some(CachedJwt {
        jwt: Secret::new("cached-jwt-value"),
        expires_at_ms: now_ms() + 3_600_000,
    });
    let mut c = client_for(&server);
    commands::ensure_session(&mut c, &s, SystemTime::now())
        .await
        .unwrap();
    commands::list_services(&c, PROJECT).await.unwrap();

    let reqs = requests_to(&server, PATH_GET_SERVICES).await;
    assert_eq!(body_json(&reqs[0])["jwt"], "cached-jwt-value");
}

#[tokio::test]
async fn r18_auth_test_always_signs_in_even_with_fresh_cache() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;

    let mut s = settings();
    s.cached_jwt = Some(CachedJwt {
        jwt: Secret::new("cached-jwt-value"),
        expires_at_ms: now_ms() + 3_600_000,
    });
    let mut c = client_for(&server);
    let report = commands::auth_test(&mut c, &s).await.expect("ok");
    assert!(report.authenticated);
    assert_eq!(report.email, EMAIL);

    let reqs = requests_to(&server, PATH_CHECK_TOKEN).await;
    assert_eq!(reqs.len(), 1, "auth test must hit checkAPIToken");
    assert_eq!(body_json(&reqs[0])["email"], EMAIL);
}

#[tokio::test]
async fn r19_auth_report_carries_the_authenticated_email() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;

    let mut s = settings();
    s.credentials.email = "someone.else@example.org".to_string();
    let mut c = client_for(&server);
    let report = commands::auth_test(&mut c, &s).await.expect("ok");
    assert_eq!(report.email, "someone.else@example.org");
    assert!(report.authenticated);
}

#[tokio::test]
async fn r20_auth_test_rejection_is_a_distinct_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "KO", "message": "Invalid token"
        })))
        .mount(&server)
        .await;

    let mut c = client_for(&server);
    let err = commands::auth_test(&mut c, &settings())
        .await
        .expect_err("rejected");
    match err {
        CommandError::Client(ClientError::AuthRejected { .. }) => {}
        other => panic!("expected AuthRejected, got {other:?}"),
    }
    let msg = err.to_string();
    assert!(
        !msg.contains("no credentials found"),
        "rejection must not read as missing credentials: {msg}"
    );
}

// ------------------------------------------------------------ R9, R21, R22

#[test]
fn r9_project_flag_overrides_default_project() {
    let s = settings(); // default_project = "112"
    assert_eq!(
        commands::resolve_project(Some("999"), &s).unwrap(),
        "999",
        "--project wins"
    );
    assert_eq!(commands::resolve_project(None, &s).unwrap(), PROJECT);
}

#[test]
fn r22_no_project_error_names_flag_and_official_command() {
    let mut s = settings();
    s.default_project = None;
    let err = commands::resolve_project(None, &s).expect_err("must fail");
    assert!(matches!(err, CommandError::NoProject), "got {err:?}");
    let msg = err.to_string();
    assert!(msg.contains("--project"), "must name --project: {msg}");
    assert!(
        msg.contains("elestio config --set-default-project"),
        "must name the official CLI command: {msg}"
    );
}

#[tokio::test]
async fn r21_list_services_returns_the_project_services() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .and(body_partial_json(json!({ "projectId": "77" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "servers": [ raw_service(1), raw_service(2) ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let list = commands::list_services(&c, "77").await.expect("ok");
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, "1");
    assert_eq!(list[1].id, "2");
    server.verify().await;
}

// ------------------------------------------------------------ R26, R27, R28

#[tokio::test]
async fn r26_get_service_returns_the_service() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![raw_service(41928)]).await;

    let c = signed_in_client(&server);
    let s = commands::get_service(&c, PROJECT, VM_ID).await.expect("ok");
    assert_eq!(s.id, VM_ID);
    assert_eq!(s.server_type.as_deref(), Some("MEDIUM-2C-4G"));

    let reqs = requests_to(&server, PATH_GET_DETAILS).await;
    assert_eq!(reqs.len(), 1);
    let body = body_json(&reqs[0]);
    assert_eq!(body["vmID"], VM_ID);
    assert_eq!(body["projectID"], PROJECT);
}

#[tokio::test]
async fn r27_not_found_error_names_vmid_and_project() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![]).await;

    let c = signed_in_client(&server);
    let err = commands::get_service(&c, "555", "999")
        .await
        .expect_err("not found");
    match &err {
        CommandError::NotFound { vm_id, project } => {
            assert_eq!(vm_id, "999");
            assert_eq!(project, "555");
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
    let msg = err.to_string();
    assert!(msg.contains("999"), "names the vmID: {msg}");
    assert!(msg.contains("555"), "names the project: {msg}");
    assert!(msg.to_lowercase().contains("not found"), "{msg}");
}

#[tokio::test]
async fn r27_network_failure_is_not_reported_as_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = commands::get_service(&c, PROJECT, VM_ID)
        .await
        .expect_err("fails");
    assert!(
        matches!(err, CommandError::Client(ClientError::HttpStatus { .. })),
        "a 502 is a client error, not NotFound: {err:?}"
    );
}

#[tokio::test]
async fn r28_secret_bearing_fields_are_dropped_from_the_model() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![raw_service(41928)]).await;

    let c = signed_in_client(&server);
    let s = commands::get_service(&c, PROJECT, VM_ID).await.expect("ok");
    let dbg = format!("{s:?}");
    assert!(
        !dbg.contains("SUPERSECRETPASS"),
        "managedDBCLI leaked: {dbg}"
    );
    assert!(
        !dbg.contains("admin-secret-user"),
        "adminUser leaked: {dbg}"
    );
    assert!(!dbg.contains("managedDBCLI"), "{dbg}");
    assert!(!dbg.contains("adminUser"), "{dbg}");
}

// --------------------------------------------------------------------- R29

#[tokio::test]
async fn r29_enabled_firewall_fetches_details_then_rules() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![raw_service(41928)]).await; // isFirewallActivated: 1
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"])],
    )
    .await;

    let c = signed_in_client(&server);
    let report = commands::firewall_get(&c, PROJECT, VM_ID)
        .await
        .expect("ok");
    assert_eq!(report.vm_id, VM_ID);
    assert!(report.enabled);
    assert_eq!(report.rules.len(), 1);
    assert_eq!(report.rules[0].port, "22");

    assert_eq!(requests_to(&server, PATH_GET_DETAILS).await.len(), 1);
    let actions = requests_to(&server, PATH_DO_ACTION).await;
    assert_eq!(actions.len(), 1);
    assert_eq!(body_json(&actions[0])["action"], "getFirewallRules");
    assert_eq!(body_json(&actions[0])["vmID"], VM_ID);
}

#[tokio::test]
async fn r29_disabled_firewall_is_reported_as_disabled() {
    let server = MockServer::start().await;
    let mut svc = raw_service(41928);
    svc["isFirewallActivated"] = json!(0);
    mount_get_details(&server, vec![svc]).await;
    // If the tool asks anyway, give it rules: they must not be reported.
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"])],
    )
    .await;

    let c = signed_in_client(&server);
    let report = commands::firewall_get(&c, PROJECT, VM_ID)
        .await
        .expect("ok");
    assert!(!report.enabled, "isFirewallActivated 0 means disabled");
    assert!(
        report.rules.is_empty(),
        "a disabled firewall lists no rules, got {:?}",
        report.rules
    );
    assert_eq!(requests_to(&server, PATH_GET_DETAILS).await.len(), 1);
}

#[tokio::test]
async fn r29_firewall_get_on_unknown_service_is_not_found() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![]).await;

    let c = signed_in_client(&server);
    let err = commands::firewall_get(&c, PROJECT, "999")
        .await
        .expect_err("fails");
    assert!(matches!(err, CommandError::NotFound { .. }), "got {err:?}");
    assert!(requests_to(&server, PATH_DO_ACTION).await.is_empty());
}

// --------------------------------------------------- R33, R37, R39, R50, R51

#[tokio::test]
async fn r37_drift_fetches_each_declared_service_in_its_project() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .and(body_partial_json(json!({ "vmID": "1", "projectID": "10" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "serviceInfos": [ raw_service(1) ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .and(body_partial_json(json!({ "vmID": "2", "projectID": "20" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "serviceInfos": [ raw_service(2) ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let d1 = Declared {
        id: "1".into(),
        project: "10".into(),
        name: Some("prod-postgres".into()),
        ..Default::default()
    };
    let d2 = Declared {
        id: "2".into(),
        project: "20".into(),
        server_type: Some("LARGE-4C-8G".into()), // actual is MEDIUM-2C-4G
        ..Default::default()
    };
    let c = signed_in_client(&server);
    let report = commands::drift(&c, &[d1, d2]).await.expect("ok");
    assert_eq!(report.declared_count, 2);
    assert!(report.drift_detected());
    assert_eq!(report.differences.len(), 1);
    match &report.differences[0] {
        Difference::Mismatch {
            service_id,
            field,
            declared,
            actual,
        } => {
            assert_eq!(service_id, "2");
            assert_eq!(*field, "server_type");
            assert_eq!(declared, "LARGE-4C-8G");
            assert_eq!(actual.as_deref(), Some("MEDIUM-2C-4G"));
        }
        other => panic!("expected Mismatch, got {other:?}"),
    }
    server.verify().await;
}

#[tokio::test]
async fn r37_fetch_error_aborts_the_whole_drift_command() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .and(body_partial_json(json!({ "vmID": "1" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "serviceInfos": [ raw_service(1) ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .and(body_partial_json(json!({ "vmID": "2" })))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let mut d1 = declared("1");
    d1.name = Some("wrong-name".into()); // would be drift if reported
    let d2 = declared("2");
    let c = signed_in_client(&server);
    let err = commands::drift(&c, &[d1, d2])
        .await
        .expect_err("must abort");
    assert!(
        matches!(err, CommandError::Client(ClientError::HttpStatus { .. })),
        "got {err:?}"
    );
    assert!(err.to_string().contains("500"), "{err}");
}

#[tokio::test]
async fn r37_ko_envelope_aborts_drift() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "KO", "message": "forbidden project"
        })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = commands::drift(&c, &[declared("1")])
        .await
        .expect_err("must abort");
    assert!(
        matches!(err, CommandError::Client(ClientError::Api { .. })),
        "{err:?}"
    );
}

#[tokio::test]
async fn r39_not_found_service_is_missing_not_an_error() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![]).await;

    let mut d = declared("41928");
    d.name = Some("anything".into());
    let c = signed_in_client(&server);
    let report = commands::drift(&c, &[d]).await.expect("not an error");
    assert!(report.drift_detected());
    assert_eq!(report.differences.len(), 1, "{:?}", report.differences);
    match &report.differences[0] {
        Difference::Missing {
            service_id,
            project,
        } => {
            assert_eq!(service_id, "41928");
            assert_eq!(project, PROJECT);
        }
        other => panic!("expected Missing, got {other:?}"),
    }
}

#[tokio::test]
async fn r33_absent_firewall_key_never_fetches_rules() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![raw_service(41928)]).await; // firewall enabled
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"])],
    )
    .await;

    let d = Declared {
        firewall: None,
        firewall_mode: FirewallMode::Exact,
        ..declared(VM_ID)
    };
    let c = signed_in_client(&server);
    let report = commands::drift(&c, &[d]).await.expect("ok");
    assert!(!report.drift_detected(), "{:?}", report.differences);
    assert!(
        requests_to(&server, PATH_DO_ACTION).await.is_empty(),
        "firewall not declared: rules must not be fetched"
    );
}

#[tokio::test]
async fn r33_empty_firewall_list_asserts_no_rules() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"])],
    )
    .await;

    // Exact mode with `firewall = []`: the one actual rule is Unexpected.
    let exact = Declared {
        firewall: Some(vec![]),
        firewall_mode: FirewallMode::Exact,
        ..declared(VM_ID)
    };
    let c = signed_in_client(&server);
    let report = commands::drift(&c, std::slice::from_ref(&exact))
        .await
        .expect("ok");
    assert_eq!(report.differences.len(), 1, "{:?}", report.differences);
    assert!(matches!(
        &report.differences[0],
        Difference::Unexpected { service_id, .. } if service_id == VM_ID
    ));
    assert_eq!(requests_to(&server, PATH_DO_ACTION).await.len(), 1);

    // Subset mode with `firewall = []`: nothing to look for, nothing reported.
    let subset = Declared {
        firewall: Some(vec![]),
        firewall_mode: FirewallMode::Subset,
        ..declared(VM_ID)
    };
    let report = commands::drift(&c, &[subset]).await.expect("ok");
    assert!(!report.drift_detected(), "{:?}", report.differences);
}

#[tokio::test]
async fn r29_disabled_firewall_means_declared_rules_are_absent() {
    let server = MockServer::start().await;
    let mut svc = raw_service(41928);
    svc["isFirewallActivated"] = json!(0);
    mount_get_details(&server, vec![svc]).await;
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"])],
    )
    .await;

    let d = Declared {
        firewall: Some(vec![rule("INPUT", "22", "tcp", &["0.0.0.0/0"])]),
        ..declared(VM_ID)
    };
    let c = signed_in_client(&server);
    let report = commands::drift(&c, &[d]).await.expect("ok");
    assert_eq!(report.differences.len(), 1, "{:?}", report.differences);
    assert!(
        matches!(&report.differences[0], Difference::Absent { .. }),
        "disabled firewall means the declared rule is absent: {:?}",
        report.differences
    );
}

#[tokio::test]
async fn r41_drift_subset_ignores_extra_actual_rules_and_reports_absent() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![
            raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"]),
            raw_rule("INPUT", "443", "tcp", &["0.0.0.0/0"]),
        ],
    )
    .await;

    let d = Declared {
        firewall: Some(vec![
            rule("input", "22", "TCP", &["0.0.0.0/0"]), // case-insensitive match
            rule("INPUT", "5432", "tcp", &["10.0.0.0/8"]), // absent
        ]),
        firewall_mode: FirewallMode::Subset,
        ..declared(VM_ID)
    };
    let c = signed_in_client(&server);
    let report = commands::drift(&c, &[d]).await.expect("ok");
    assert_eq!(report.differences.len(), 1, "{:?}", report.differences);
    match &report.differences[0] {
        Difference::Absent { service_id, rule } => {
            assert_eq!(service_id, VM_ID);
            assert_eq!(rule.port, "5432");
        }
        other => panic!("expected Absent, got {other:?}"),
    }
}

#[tokio::test]
async fn r50_no_differences_means_no_drift() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![raw_service(41928)]).await;

    let d = Declared {
        name: Some("prod-postgres".into()),
        provider: Some("hetzner".into()),
        ..declared(VM_ID)
    };
    let c = signed_in_client(&server);
    let report = commands::drift(&c, &[d]).await.expect("ok");
    assert!(report.differences.is_empty());
    assert!(!report.drift_detected());
    assert_eq!(report.declared_count, 1);
}

#[tokio::test]
async fn r50_zero_declared_services_is_not_an_error() {
    let server = MockServer::start().await;
    let c = signed_in_client(&server);
    let report = commands::drift(&c, &[]).await.expect("ok");
    assert_eq!(report.declared_count, 0);
    assert!(!report.drift_detected());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn r51_drift_detected_when_any_difference_exists() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![raw_service(41928)]).await;

    let d = Declared {
        datacenter: Some("fsn1".into()), // actual hel1
        ..declared(VM_ID)
    };
    let c = signed_in_client(&server);
    let report = commands::drift(&c, &[d]).await.expect("ok");
    assert!(report.drift_detected());
}

#[tokio::test]
async fn r15_drift_retries_a_flaky_details_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_get_details(&server, vec![raw_service(41928)]).await;

    let c = signed_in_client(&server);
    let report = commands::drift(&c, &[declared(VM_ID)]).await.expect("ok");
    assert!(!report.drift_detected());
    assert_eq!(requests_to(&server, PATH_GET_DETAILS).await.len(), 2);
}
