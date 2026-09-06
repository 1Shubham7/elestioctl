//! R6, R13 to R18, R20, R21, R26, R27, R29, R53: the API client against a
//! wiremock server. Every test asserts on what the mock received as well as
//! on the client's result.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use elestioctl::client::{
    self, ApiClient, ClientConfig, ClientError, Endpoint, DEFAULT_BASE_URL, DEFAULT_RETRY_BASE,
    DEFAULT_TIMEOUT, MAX_ATTEMPTS,
};
use elestioctl::config::CredentialSource;
use elestioctl::secret::Secret;
use serde_json::json;
use wiremock::matchers::{body_json, body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{
    body_json as req_body, client_for, client_with_timeout, mount_get_details, mount_get_services,
    mount_sign_in_ok, raw_rule, raw_service, requests_to, signed_in_client, EMAIL, JWT,
    PATH_CHECK_TOKEN, PATH_DO_ACTION, PATH_GET_DETAILS, PATH_GET_SERVICES, PROJECT, TOKEN, VM_ID,
};

// ---------------------------------------------------------------- R13, R14

#[test]
fn r13_default_base_url_is_production() {
    assert_eq!(DEFAULT_BASE_URL, "https://api.elest.io");
    assert_eq!(ClientConfig::default().base_url, DEFAULT_BASE_URL);
    assert_eq!(client::ENV_BASE_URL, "ELESTIO_API_URL");
}

#[tokio::test]
async fn r13_base_url_is_configurable() {
    let server = MockServer::start().await;
    let c = client_for(&server);
    assert_eq!(c.base_url(), server.uri());
}

#[test]
fn r14_default_timeout_is_thirty_seconds_and_overridable_by_env_name() {
    assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    assert_eq!(ClientConfig::default().timeout, Duration::from_secs(30));
    assert_eq!(client::ENV_TIMEOUT_SECS, "ELESTIO_TIMEOUT_SECS");
}

#[tokio::test]
async fn r14_per_attempt_timeout_is_enforced_and_timeouts_are_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "servers": [] }))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;

    let c = {
        let mut c = client_with_timeout(&server, Duration::from_millis(50));
        c.set_jwt(Secret::new(JWT));
        c
    };
    let started = Instant::now();
    let result = c.list_services(PROJECT).await;
    let elapsed = started.elapsed();

    assert!(result.is_err(), "a slow server must time out");
    assert!(
        elapsed < Duration::from_secs(3),
        "timeout must be per attempt, not 30 s: {elapsed:?}"
    );
    // R15: a timeout is a transport error, so it is retried up to 3 attempts.
    let reqs = requests_to(&server, PATH_GET_SERVICES).await;
    assert_eq!(reqs.len(), 3, "expected exactly 3 attempts on timeout");
}

// --------------------------------------------------------------------- R15

#[test]
fn r15_retry_constants_match_spec() {
    assert_eq!(MAX_ATTEMPTS, 3);
    assert_eq!(DEFAULT_RETRY_BASE, Duration::from_millis(500));
    assert_eq!(client::ENV_RETRY_BASE_MS, "ELESTIO_RETRY_BASE_MS");
}

#[test]
fn r15_retryable_status_set_is_exactly_408_429_and_5xx() {
    assert!(client::is_retryable_status(408));
    assert!(client::is_retryable_status(429));
    for code in 500..600u16 {
        assert!(client::is_retryable_status(code), "{code} must retry");
    }
    for code in [200u16, 201, 204, 301, 400, 401, 403, 404, 409, 410, 422] {
        assert!(!client::is_retryable_status(code), "{code} must not retry");
    }
}

#[tokio::test]
async fn r15_retries_5xx_three_times_in_total() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(503))
        .expect(3)
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c.list_services(PROJECT).await.expect_err("must fail");
    assert!(matches!(err, ClientError::HttpStatus { .. }), "got {err:?}");
    assert_eq!(requests_to(&server, PATH_GET_SERVICES).await.len(), 3);
    server.verify().await;
}

#[tokio::test]
async fn r15_retries_429_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_get_services(&server, vec![raw_service(1)]).await;

    let c = signed_in_client(&server);
    let services = c
        .list_services(PROJECT)
        .await
        .expect("second attempt succeeds");
    assert_eq!(services.len(), 1);
    assert_eq!(requests_to(&server, PATH_GET_SERVICES).await.len(), 2);
}

#[tokio::test]
async fn r15_retries_408_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(408))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    mount_get_services(&server, vec![]).await;

    let c = signed_in_client(&server);
    c.list_services(PROJECT)
        .await
        .expect("third attempt succeeds");
    assert_eq!(requests_to(&server, PATH_GET_SERVICES).await.len(), 3);
}

#[tokio::test]
async fn r15_transport_error_is_retried_three_times() {
    // Bind and release a socket so the port is free: connections are refused.
    // (A dropped wiremock server returns to a pool and keeps listening.)
    let uri = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };

    let mut c = ApiClient::new(ClientConfig {
        base_url: uri,
        timeout: Duration::from_secs(2),
        retry_base: Duration::from_millis(10),
    })
    .unwrap();
    c.set_jwt(Secret::new(JWT));

    let started = Instant::now();
    let err = c.list_services(PROJECT).await.expect_err("must fail");
    assert!(matches!(err, ClientError::Transport { .. }), "got {err:?}");
    // Two backoff delays (10 ms + 20 ms) must have elapsed for three attempts.
    assert!(
        started.elapsed() >= Duration::from_millis(30),
        "three attempts imply at least base + 2*base of backoff"
    );
}

#[tokio::test]
async fn r15_backoff_is_base_times_two_to_the_n_minus_one() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let mut c = ApiClient::new(ClientConfig {
        base_url: server.uri(),
        timeout: Duration::from_secs(5),
        retry_base: Duration::from_millis(100),
    })
    .unwrap();
    c.set_jwt(Secret::new(JWT));

    let started = Instant::now();
    let _ = c.list_services(PROJECT).await;
    let elapsed = started.elapsed();

    assert_eq!(requests_to(&server, PATH_GET_SERVICES).await.len(), 3);
    // retry 1 waits 100 ms, retry 2 waits 200 ms: 300 ms minimum in total.
    assert!(
        elapsed >= Duration::from_millis(300),
        "backoff too short: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2_000),
        "backoff far too long: {elapsed:?}"
    );
}

#[tokio::test]
async fn r15_other_4xx_is_not_retried() {
    for code in [400u16, 401, 403, 404, 422] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(PATH_GET_SERVICES))
            .respond_with(ResponseTemplate::new(code))
            .mount(&server)
            .await;

        let c = signed_in_client(&server);
        let err = c.list_services(PROJECT).await.expect_err("must fail");
        assert!(
            matches!(err, ClientError::HttpStatus { .. }),
            "{code}: {err:?}"
        );
        assert_eq!(
            requests_to(&server, PATH_GET_SERVICES).await.len(),
            1,
            "HTTP {code} must be sent exactly once"
        );
    }
}

#[tokio::test]
async fn r15_ko_envelope_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "KO",
            "message": "project does not exist"
        })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c.list_services(PROJECT).await.expect_err("KO is an error");
    assert!(matches!(err, ClientError::Api { .. }), "got {err:?}");
    assert_eq!(requests_to(&server, PATH_GET_SERVICES).await.len(), 1);
}

// --------------------------------------------------------------------- R16

#[tokio::test]
async fn r16_http_error_names_path_and_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c.list_services(PROJECT).await.expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains(PATH_GET_SERVICES), "must name the path: {msg}");
    assert!(msg.contains("403"), "must name the HTTP status: {msg}");
}

#[tokio::test]
async fn r16_ko_error_names_path_and_api_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "KO",
            "message": "you are not allowed to access this project"
        })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c.get_service(PROJECT, VM_ID).await.expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains(PATH_GET_DETAILS), "must name the path: {msg}");
    assert!(
        msg.contains("you are not allowed to access this project"),
        "must carry the API message: {msg}"
    );
}

#[tokio::test]
async fn r16_ko_without_message_still_names_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "KO" })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c.list_services(PROJECT).await.expect_err("must fail");
    assert!(err.to_string().contains(PATH_GET_SERVICES), "{err}");
}

// --------------------------------------------------------------------- R17

#[tokio::test]
async fn r17_non_json_body_is_a_parse_error_not_a_panic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>gateway</html>"))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c.list_services(PROJECT).await.expect_err("must fail");
    assert!(
        err.to_string().contains(PATH_GET_SERVICES),
        "parse error names the endpoint: {err}"
    );
    // R15 lists the retry triggers (429, 408, 5xx, transport error); a 200
    // whose body is not JSON is none of them, so it is sent once.
    assert_eq!(
        requests_to(&server, PATH_GET_SERVICES).await.len(),
        1,
        "a malformed 2xx body is a parse failure, not a transport error to retry"
    );
    assert!(
        matches!(err, ClientError::Parse { .. }),
        "R17: malformed JSON must be a parse error, got {err:?}"
    );
}

#[tokio::test]
async fn r17_wrong_field_type_names_the_json_path() {
    let server = MockServer::start().await;
    // `vmID` must be a number or string; an object cannot be normalised.
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "servers": [ raw_service(1), { "vmID": { "oops": true }, "displayName": "x" } ]
        })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c.list_services(PROJECT).await.expect_err("must fail");
    assert!(matches!(err, ClientError::Parse { .. }), "got {err:?}");
    let msg = err.to_string();
    // The path must locate the failing field: the element index and `vmID`.
    // "servers[1].vmID" and the array-relative "[1].vmID" both do.
    assert!(
        msg.contains("[1].vmID"),
        "must name the JSON path of the failing field: {msg}"
    );
    assert!(msg.contains(PATH_GET_SERVICES), "names the endpoint: {msg}");
}

#[tokio::test]
async fn r17_wrong_container_type_names_the_json_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "servers": "not-an-array" })),
        )
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c.list_services(PROJECT).await.expect_err("must fail");
    assert!(matches!(err, ClientError::Parse { .. }), "got {err:?}");
    assert!(err.to_string().contains("servers"), "{err}");
}

#[tokio::test]
async fn r17_firewall_rule_missing_required_field_names_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_DO_ACTION))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rules": [ { "type": "INPUT", "protocol": "tcp", "targets": ["0.0.0.0/0"] } ]
        })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c
        .get_firewall_rules(VM_ID)
        .await
        .expect_err("port is required");
    assert!(matches!(err, ClientError::Parse { .. }), "got {err:?}");
    let msg = err.to_string();
    assert!(
        msg.contains("[0]") && msg.contains("port"),
        "names the failing element and field: {msg}"
    );
    assert!(msg.contains(PATH_DO_ACTION), "names the endpoint: {msg}");
}

// ----------------------------------------------------------- R6, R18, R20

#[tokio::test]
async fn r18_sign_in_posts_email_and_token_to_check_api_token() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;

    let mut c = client_for(&server);
    assert!(!c.is_signed_in());
    c.sign_in(&common::credentials(CredentialSource::File))
        .await
        .expect("sign in ok");
    assert!(c.is_signed_in());

    let reqs = requests_to(&server, PATH_CHECK_TOKEN).await;
    assert_eq!(reqs.len(), 1);
    let body = req_body(&reqs[0]);
    assert_eq!(body["email"], EMAIL);
    assert_eq!(body["token"], TOKEN);
}

#[tokio::test]
async fn r20_sign_in_rejected_when_status_is_not_ok() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "KO",
            "message": "Invalid token"
        })))
        .mount(&server)
        .await;

    let mut c = client_for(&server);
    let err = c
        .sign_in(&common::credentials(CredentialSource::File))
        .await
        .expect_err("rejected");
    assert!(
        matches!(
            err,
            ClientError::AuthRejected { .. } | ClientError::Api { .. }
        ),
        "rejection must be distinguishable: {err:?}"
    );
    assert!(!c.is_signed_in());
    assert_eq!(requests_to(&server, PATH_CHECK_TOKEN).await.len(), 1);
}

#[tokio::test]
async fn r20_sign_in_rejected_when_ok_but_no_jwt() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "OK" })))
        .mount(&server)
        .await;

    let mut c = client_for(&server);
    let err = c
        .sign_in(&common::credentials(CredentialSource::File))
        .await
        .expect_err("no jwt is a rejection");
    assert!(
        matches!(err, ClientError::AuthRejected { .. }),
        "got {err:?}"
    );
    assert!(!c.is_signed_in());
}

#[tokio::test]
async fn r6_jwt_travels_in_the_json_body_never_the_url() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![]).await;
    mount_get_details(&server, vec![]).await;
    Mock::given(method("POST"))
        .and(path(PATH_DO_ACTION))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "rules": [] })))
        .mount(&server)
        .await;

    let mut c = client_for(&server);
    c.sign_in(&common::credentials(CredentialSource::File))
        .await
        .unwrap();
    c.list_services(PROJECT).await.unwrap();
    c.get_service(PROJECT, VM_ID).await.unwrap();
    c.get_firewall_rules(VM_ID).await.unwrap();

    let all = server.received_requests().await.unwrap();
    assert_eq!(all.len(), 4);
    for r in &all {
        let url = r.url.to_string();
        assert!(!url.contains(JWT), "JWT leaked into URL: {url}");
        assert!(!url.contains(TOKEN), "token leaked into URL: {url}");
        assert!(r.url.query().is_none(), "no query string at all: {url}");
        for (name, value) in r.headers.iter() {
            let v = value.to_str().unwrap_or("");
            assert!(!v.contains(JWT), "JWT leaked into header {name}");
        }
        if r.url.path() != PATH_CHECK_TOKEN {
            let body = req_body(r);
            assert_eq!(body["jwt"], JWT, "jwt must be a body member: {body}");
        }
    }
}

#[tokio::test]
async fn r6_api_client_debug_redacts_jwt() {
    let server = MockServer::start().await;
    let mut c = client_for(&server);
    c.set_jwt(Secret::new(JWT));
    let dbg = format!("{c:?}");
    let alt = format!("{c:#?}");
    assert!(!dbg.contains(JWT), "ApiClient Debug leaked JWT: {dbg}");
    assert!(!alt.contains(JWT), "ApiClient Debug leaked JWT: {alt}");
    assert!(dbg.contains("[REDACTED]"), "{dbg}");
}

#[tokio::test]
async fn r6_client_errors_do_not_echo_the_jwt_or_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let mut c = client_for(&server);
    let e1 = c
        .sign_in(&common::credentials(CredentialSource::File))
        .await
        .err()
        .unwrap();
    c.set_jwt(Secret::new(JWT));
    let e2 = c.list_services(PROJECT).await.err().unwrap();
    for e in [e1, e2] {
        let text = format!("{e}\n{e:?}\n{e:#?}");
        assert!(!text.contains(TOKEN), "error leaked token: {text}");
        assert!(!text.contains(JWT), "error leaked jwt: {text}");
    }
}

#[tokio::test]
async fn r6_calls_needing_a_jwt_fail_before_sending_when_not_signed_in() {
    let server = MockServer::start().await;
    mount_get_services(&server, vec![]).await;

    let c = client_for(&server);
    let err = c.list_services(PROJECT).await.expect_err("no jwt");
    assert!(matches!(err, ClientError::MissingJwt { .. }), "got {err:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

// ------------------------------------------------------------ R21, R26, R27

#[tokio::test]
async fn r21_list_services_sends_spec_body_and_normalises_vmid() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .and(body_json(json!({
            "appid": "Cloudxx",
            "projectId": PROJECT,
            "isActiveService": "true",
            "jwt": JWT
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "servers": [
                raw_service(41928),
                { "vmID": "555", "displayName": "as-string", "status": "off" }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let services = c.list_services(PROJECT).await.expect("ok");
    assert_eq!(services.len(), 2);
    assert_eq!(services[0].id, "41928", "numeric vmID normalised to string");
    assert_eq!(services[0].name.as_deref(), Some("prod-postgres"));
    assert_eq!(services[0].template.as_deref(), Some("PostgreSQL"));
    assert_eq!(services[0].version.as_deref(), Some("16"));
    assert_eq!(services[0].provider.as_deref(), Some("hetzner"));
    assert_eq!(services[0].datacenter.as_deref(), Some("hel1"));
    assert_eq!(services[0].server_type.as_deref(), Some("MEDIUM-2C-4G"));
    assert_eq!(services[0].status.as_deref(), Some("running"));
    assert_eq!(services[0].deployment_status.as_deref(), Some("Deployed"));
    assert!(services[0].firewall_enabled);
    assert_eq!(services[1].id, "555", "string vmID kept as is");
    assert_eq!(services[1].status.as_deref(), Some("off"));
    server.verify().await;
}

#[tokio::test]
async fn r26_get_service_sends_vmid_and_project_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .and(body_json(json!({
            "vmID": VM_ID,
            "projectID": PROJECT,
            "jwt": JWT
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "serviceInfos": [ raw_service(41928) ] })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let s = c
        .get_service(PROJECT, VM_ID)
        .await
        .expect("ok")
        .expect("found");
    assert_eq!(s.id, VM_ID);
    assert_eq!(s.name.as_deref(), Some("prod-postgres"));
    server.verify().await;
}

#[tokio::test]
async fn r27_empty_service_infos_is_none_not_an_error() {
    let server = MockServer::start().await;
    mount_get_details(&server, vec![]).await;

    let c = signed_in_client(&server);
    let s = c.get_service(PROJECT, "999").await.expect("no error");
    assert!(s.is_none());
    assert_eq!(requests_to(&server, PATH_GET_DETAILS).await.len(), 1);
}

#[tokio::test]
async fn r29_firewall_rules_use_the_get_firewall_rules_action() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_DO_ACTION))
        .and(body_json(json!({
            "vmID": VM_ID,
            "action": "getFirewallRules",
            "jwt": JWT
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rules": [ raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0", "::/0"]) ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let rules = c.get_firewall_rules(VM_ID).await.expect("ok");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule_type, "INPUT");
    assert_eq!(rules[0].port, "22");
    assert_eq!(rules[0].protocol, "tcp");
    assert_eq!(rules[0].targets, vec!["0.0.0.0/0", "::/0"]);
    server.verify().await;
}

#[tokio::test]
async fn r29_firewall_rules_accept_the_nested_data_rules_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_DO_ACTION))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "rules": [ raw_rule("OUTPUT", "443", "tcp", &["10.0.0.0/8"]) ] }
        })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let rules = c.get_firewall_rules(VM_ID).await.expect("ok");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule_type, "OUTPUT");
    assert_eq!(rules[0].port, "443");
}

#[tokio::test]
async fn r29_firewall_rule_targets_accept_a_bare_string() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_DO_ACTION))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rules": [ { "type": "INPUT", "port": "80", "protocol": "tcp", "targets": "0.0.0.0/0" } ]
        })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let rules = c.get_firewall_rules(VM_ID).await.expect("ok");
    assert_eq!(rules[0].targets, vec!["0.0.0.0/0"]);
}

// --------------------------------------------------------------------- R53

#[test]
fn r53_allowlist_holds_exactly_the_four_spec_triples() {
    assert!(client::is_allowed("POST", PATH_CHECK_TOKEN, None));
    assert!(client::is_allowed("POST", PATH_GET_SERVICES, None));
    assert!(client::is_allowed("POST", PATH_GET_DETAILS, None));
    assert!(client::is_allowed(
        "POST",
        PATH_DO_ACTION,
        Some("getFirewallRules")
    ));

    // Same path, wrong or missing action.
    assert!(!client::is_allowed("POST", PATH_DO_ACTION, None));
    assert!(!client::is_allowed("POST", PATH_DO_ACTION, Some("reboot")));
    assert!(!client::is_allowed("POST", PATH_DO_ACTION, Some("delete")));
    assert!(!client::is_allowed(
        "POST",
        PATH_DO_ACTION,
        Some("setFirewallRules")
    ));
    // Allowed paths with an unexpected action.
    assert!(!client::is_allowed(
        "POST",
        PATH_GET_SERVICES,
        Some("getFirewallRules")
    ));
    // Wrong method.
    assert!(!client::is_allowed("GET", PATH_GET_SERVICES, None));
    assert!(!client::is_allowed("DELETE", PATH_GET_DETAILS, None));
    // Credential-returning endpoints (R28) and anything that mutates.
    for p in [
        "/api/servers/getAppCredentials",
        "/api/servers/getServiceEnv",
        "/api/servers/deleteServer",
        "/api/servers/createServer",
        "/api/servers/getServicesX",
        "/api/servers/getServices/",
        "/api/auth/login",
        "",
        "/",
    ] {
        assert!(!client::is_allowed("POST", p, None), "{p} must be refused");
    }
}

#[test]
fn r53_endpoint_enum_matches_spec_paths() {
    assert_eq!(Endpoint::ALL.len(), 4);
    assert_eq!(Endpoint::CheckApiToken.path(), PATH_CHECK_TOKEN);
    assert_eq!(Endpoint::GetServices.path(), PATH_GET_SERVICES);
    assert_eq!(Endpoint::GetServerDetails.path(), PATH_GET_DETAILS);
    assert_eq!(Endpoint::GetFirewallRules.path(), PATH_DO_ACTION);
    assert_eq!(
        Endpoint::GetFirewallRules.action(),
        Some("getFirewallRules")
    );
    for e in [
        Endpoint::CheckApiToken,
        Endpoint::GetServices,
        Endpoint::GetServerDetails,
    ] {
        assert_eq!(e.action(), None);
    }
    assert!(!Endpoint::CheckApiToken.needs_jwt());
    assert!(Endpoint::GetServices.needs_jwt());
    assert!(Endpoint::GetServerDetails.needs_jwt());
    assert!(Endpoint::GetFirewallRules.needs_jwt());
    for e in Endpoint::ALL {
        assert!(client::is_allowed("POST", e.path(), e.action()));
    }
}

#[tokio::test]
async fn r53_call_off_the_allowlist_sends_zero_requests() {
    let server = MockServer::start().await;
    // Answer anything, so a leaked request would succeed and be recorded.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "OK" })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let err = c
        .request(
            "POST",
            "/api/servers/getAppCredentials",
            json!({ "vmID": VM_ID }),
        )
        .await
        .expect_err("must be refused");
    assert!(matches!(err, ClientError::NotAllowed { .. }), "got {err:?}");
    assert!(
        err.to_string().contains("/api/servers/getAppCredentials"),
        "names the refused path: {err}"
    );

    let received = server.received_requests().await.unwrap();
    assert!(
        received.is_empty(),
        "mock server must receive zero requests, got {}",
        received.len()
    );
}

#[tokio::test]
async fn r53_do_action_with_other_action_sends_zero_requests() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "OK" })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    for action in ["reboot", "deleteService", "setFirewallRules", ""] {
        let err = c
            .request(
                "POST",
                PATH_DO_ACTION,
                json!({ "vmID": VM_ID, "action": action }),
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("action {action:?} must be refused"));
        assert!(matches!(err, ClientError::NotAllowed { .. }), "got {err:?}");
    }
    // No action member at all.
    let err = c
        .request("POST", PATH_DO_ACTION, json!({ "vmID": VM_ID }))
        .await
        .expect_err("missing action must be refused");
    assert!(matches!(err, ClientError::NotAllowed { .. }), "got {err:?}");

    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn r53_wrong_method_on_allowed_path_sends_zero_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "servers": [] })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "servers": [] })))
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    for m in ["GET", "PUT", "DELETE", "PATCH", "post"] {
        let err = c
            .request(m, PATH_GET_SERVICES, json!({}))
            .await
            .err()
            .unwrap_or_else(|| panic!("method {m} must be refused"));
        assert!(
            matches!(err, ClientError::NotAllowed { .. }),
            "{m}: {err:?}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn r53_allowed_call_through_request_is_sent_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_DO_ACTION))
        .and(body_partial_json(json!({ "action": "getFirewallRules" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "rules": [] })))
        .expect(1)
        .mount(&server)
        .await;

    let c = signed_in_client(&server);
    let v = c
        .request(
            "POST",
            PATH_DO_ACTION,
            json!({ "vmID": VM_ID, "action": "getFirewallRules" }),
        )
        .await
        .expect("allowed");
    assert_eq!(v["rules"], json!([]));
    server.verify().await;
}
