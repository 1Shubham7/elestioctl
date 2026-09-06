//! Tests added after mutation testing of the API client.
//!
//! `cargo mutants` injected a bug into each of three areas and the existing
//! suite stayed green, so the behaviour the spec requires there was not
//! pinned by any test. Each test below is written from `spec/SPEC.md` and
//! `docs/API.md` only, and exists to kill one of those surviving mutants:
//!
//! - R53 and R12: a refused call's error must name the operation, including
//!   the offending `action` for the shared action endpoint.
//! - R20: sign-in with `status: OK` but a missing or empty `jwt` is a
//!   rejection, and the client stays signed out.
//! - R15: the backoff before retry `n` (1-based) is exactly `base * 2^(n-1)`.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use elestioctl::client::{backoff_delay, ClientError};
use elestioctl::config::CredentialSource;
use proptest::prelude::*;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{client_for, signed_in_client, PATH_CHECK_TOKEN, PATH_DO_ACTION, VM_ID};

// ---------------------------------------------------------------- R53, R12

/// Mount a catch-all so that any request that leaks past the allowlist would
/// succeed and be recorded by the mock, making a leak visible.
async fn mount_answer_anything(server: &MockServer) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "OK" })))
        .mount(server)
        .await;
}

// R12: the error names the operation, which for the action endpoint means
// both the path and the action string that was refused.
#[tokio::test]
async fn r53_refused_action_error_names_the_action_and_path_with_zero_requests() {
    let server = MockServer::start().await;
    mount_answer_anything(&server).await;

    let c = signed_in_client(&server);
    let err = c
        .request(
            "POST",
            PATH_DO_ACTION,
            json!({ "vmID": "1", "action": "reboot" }),
        )
        .await
        .expect_err("reboot is not on the allowlist");

    assert!(matches!(err, ClientError::NotAllowed { .. }), "got {err:?}");
    let text = format!("{err}");
    assert!(
        text.contains("reboot"),
        "error must name the refused action: {text}"
    );
    assert!(
        text.contains(PATH_DO_ACTION),
        "error must name the refused path: {text}"
    );

    let received = server.received_requests().await.unwrap();
    assert!(
        received.is_empty(),
        "mock server must receive zero requests, got {}",
        received.len()
    );
}

// R12: a refused path with no action still names the path.
#[tokio::test]
async fn r53_refused_path_without_action_error_names_the_path_with_zero_requests() {
    let server = MockServer::start().await;
    mount_answer_anything(&server).await;

    let refused = "/api/servers/deleteServer";
    let c = signed_in_client(&server);
    let err = c
        .request("POST", refused, json!({ "vmID": VM_ID }))
        .await
        .expect_err("deleteServer is not on the allowlist");

    assert!(matches!(err, ClientError::NotAllowed { .. }), "got {err:?}");
    let text = format!("{err}");
    assert!(
        text.contains(refused),
        "error must name the refused path: {text}"
    );

    let received = server.received_requests().await.unwrap();
    assert!(
        received.is_empty(),
        "mock server must receive zero requests, got {}",
        received.len()
    );
}

// --------------------------------------------------------------------- R20

// The missing-`jwt` variant is already pinned by
// `tests/client.rs::r20_sign_in_rejected_when_ok_but_no_jwt`; this covers the
// empty-string case, which the spec treats the same way ("no jwt").
#[tokio::test]
async fn r20_sign_in_rejected_when_ok_but_jwt_is_empty_string() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "OK",
            "jwt": ""
        })))
        .mount(&server)
        .await;

    let mut c = client_for(&server);
    assert!(!c.is_signed_in(), "fresh client starts signed out");
    let err = c
        .sign_in(&common::credentials(CredentialSource::File))
        .await
        .expect_err("an empty jwt is a rejection");
    assert!(
        matches!(err, ClientError::AuthRejected { .. }),
        "got {err:?}"
    );
    assert!(
        !c.is_signed_in(),
        "an empty jwt must not leave the client signed in"
    );
    assert_eq!(
        common::requests_to(&server, PATH_CHECK_TOKEN).await.len(),
        1,
        "sign-in is not retried on a rejection"
    );
}

// --------------------------------------------------------------------- R15

#[test]
fn r15_backoff_delay_exact_values_for_default_style_base() {
    let base = Duration::from_millis(500);
    assert_eq!(backoff_delay(base, 1), Duration::from_millis(500));
    assert_eq!(backoff_delay(base, 2), Duration::from_millis(1_000));
    assert_eq!(backoff_delay(base, 3), Duration::from_millis(2_000));
}

#[test]
fn r15_backoff_delay_first_retry_waits_exactly_base() {
    assert_eq!(
        backoff_delay(Duration::from_millis(7), 1),
        Duration::from_millis(7)
    );
}

#[test]
fn r15_backoff_delay_attempt_zero_does_not_panic_and_equals_base() {
    // Attempt numbers are 1-based; 0 is treated as 1 rather than underflowing.
    for ms in [1_u64, 7, 500, 1_000] {
        let base = Duration::from_millis(ms);
        assert_eq!(backoff_delay(base, 0), base, "base {ms} ms");
        assert_eq!(backoff_delay(base, 0), backoff_delay(base, 1));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // R15: each retry waits exactly twice as long as the one before it.
    #[test]
    fn r15_backoff_delay_doubles_between_consecutive_attempts(
        base_ms in 1_u64..=1_000,
        attempt in 1_u32..=6,
    ) {
        let base = Duration::from_millis(base_ms);
        prop_assert_eq!(
            backoff_delay(base, attempt + 1),
            backoff_delay(base, attempt) * 2
        );
    }

    // R15: closed form, so the doubling law cannot be satisfied by a wrong base.
    #[test]
    fn r15_backoff_delay_matches_closed_form(
        base_ms in 1_u64..=1_000,
        attempt in 1_u32..=6,
    ) {
        let base = Duration::from_millis(base_ms);
        let expected = base * 2_u32.pow(attempt - 1);
        prop_assert_eq!(backoff_delay(base, attempt), expected);
    }
}
