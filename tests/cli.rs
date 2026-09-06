//! The binary, end to end: exit codes (R11, R20, R22, R27, R50, R51), stderr
//! wording (R5, R12), `--json` on stdout (R7, R25, R49), no ANSI (R8), and
//! R54 (nothing written under HOME). Every test points HOME at a fresh
//! tempdir so the developer's real `~/.elestio` is never read, and every
//! test that needs the API starts its own wiremock server.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{
    body_json, mount_firewall_rules, mount_get_details, mount_get_services, mount_sign_in_ok,
    raw_rule, raw_service, requests_to, EMAIL, JWT, PATH_CHECK_TOKEN, PATH_DO_ACTION,
    PATH_GET_DETAILS, PATH_GET_SERVICES, PROJECT, TOKEN, VM_ID,
};

const ALL_ENV: [&str; 6] = [
    "ELESTIO_EMAIL",
    "ELESTIO_API_TOKEN",
    "ELESTIO_API_URL",
    "ELESTIO_TIMEOUT_SECS",
    "ELESTIO_RETRY_BASE_MS",
    "NO_COLOR",
];

/// The binary with HOME pointed at `home` and no ELESTIO_* variables.
fn bin(home: &Path) -> Command {
    let mut c = Command::cargo_bin("elestioctl").expect("binary built");
    c.env("HOME", home);
    c.env_remove("USERPROFILE");
    for v in ALL_ENV {
        c.env_remove(v);
    }
    // Make a colour-happy environment so any ANSI path would be exercised.
    c.env("TERM", "xterm-256color");
    c.env("CLICOLOR_FORCE", "1");
    c.env("FORCE_COLOR", "1");
    c
}

/// The binary with environment credentials pointed at `server`.
fn bin_with_api(home: &Path, server: &MockServer) -> Command {
    let mut c = bin(home);
    c.env("ELESTIO_API_URL", server.uri());
    c.env("ELESTIO_EMAIL", EMAIL);
    c.env("ELESTIO_API_TOKEN", TOKEN);
    c.env("ELESTIO_RETRY_BASE_MS", "1");
    c
}

fn write_credentials(home: &Path, email: &str, token: &str, mode: u32) {
    let dir = home.join(".elestio");
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join("credentials");
    fs::write(&p, json!({ "email": email, "apiToken": token }).to_string()).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
}

fn write_config(home: &Path, body: &Value) {
    let dir = home.join(".elestio");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.json"), body.to_string()).unwrap();
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn no_ansi() -> impl Predicate<str> {
    contains('\x1b').not()
}

fn stdout_of(out: &std::process::Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("utf8 stdout")
}

fn stderr_of(out: &std::process::Output) -> String {
    String::from_utf8(out.stderr.clone()).expect("utf8 stderr")
}

fn write_toml(dir: &Path, text: &str) -> std::path::PathBuf {
    let p = dir.join("drift.toml");
    fs::write(&p, text).unwrap();
    p
}

fn dir_is_empty(p: &Path) -> bool {
    fs::read_dir(p).unwrap().next().is_none()
}

// ------------------------------------------------------------- R5, R7, R11

#[test]
fn r5_no_credentials_exits_1_naming_path_and_both_env_vars() {
    let home = TempDir::new().unwrap();
    let expected_path = home.path().join(".elestio").join("credentials");
    let out = bin(home.path()).args(["auth", "test"]).assert().code(1);
    out.stdout(predicate::str::is_empty()) // R7: stdout empty on error
        .stderr(contains(expected_path.display().to_string()))
        .stderr(contains("ELESTIO_EMAIL"))
        .stderr(contains("ELESTIO_API_TOKEN"))
        .stderr(no_ansi());
}

#[test]
fn r5_services_without_credentials_also_exits_1() {
    let home = TempDir::new().unwrap();
    bin(home.path())
        .args(["--project", PROJECT, "services"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains("ELESTIO_EMAIL"))
        .stderr(contains("ELESTIO_API_TOKEN"));
}

#[test]
fn r11_argument_errors_exit_1_not_2() {
    let home = TempDir::new().unwrap();
    for args in [
        vec!["--bogus-flag"],
        vec!["no-such-command"],
        vec!["service"],               // missing VM_ID
        vec!["firewall"],              // missing subcommand
        vec!["firewall", "get"],       // missing VM_ID
        vec!["drift"],                 // missing --config
        vec!["auth"],                  // missing subcommand
        vec!["services", "--project"], // missing value
        vec![],                        // no subcommand
    ] {
        let out = bin(home.path()).args(&args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(1),
            "args {args:?} must exit 1, got {:?}\nstderr: {}",
            out.status.code(),
            stderr_of(&out)
        );
        assert!(
            stdout_of(&out).is_empty(),
            "R7: usage errors keep stdout empty: {args:?}"
        );
    }
}

#[tokio::test]
async fn r11_success_exits_0() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["auth", "test"])
        .assert()
        .code(0);
}

#[tokio::test]
async fn r11_network_error_exits_1() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "services"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
}

#[tokio::test]
async fn r7_json_success_is_a_single_json_document() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![raw_service(41928), raw_service(7)]).await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--json", "--project", PROJECT, "services"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let stdout = stdout_of(&out);
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {stdout:?}"));
    assert!(v.is_array());
    assert!(!stdout.contains('\x1b'));
}

#[tokio::test]
async fn r7_json_error_leaves_stdout_empty_and_stderr_plain_text() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--json", "--project", PROJECT, "services"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout_of(&out).is_empty(), "stdout must be empty on error");
    let stderr = stderr_of(&out);
    assert!(!stderr.is_empty());
    assert!(
        serde_json::from_str::<Value>(stderr.trim()).is_err(),
        "errors are plain text, not JSON: {stderr}"
    );
}

// ---------------------------------------------------------------- R8, R10

#[tokio::test]
async fn r8_no_ansi_escape_codes_anywhere() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![raw_service(41928)]).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"])],
    )
    .await;
    let home = TempDir::new().unwrap();

    let runs: Vec<Vec<&str>> = vec![
        vec!["auth", "test"],
        vec!["--project", PROJECT, "services"],
        vec!["--project", PROJECT, "service", VM_ID],
        vec!["--project", PROJECT, "firewall", "get", VM_ID],
        vec!["--project", PROJECT, "service", "999999"], // error path
        vec!["--bogus"],                                 // usage error path
    ];
    for args in runs {
        let out = bin_with_api(home.path(), &server)
            .args(&args)
            .output()
            .unwrap();
        let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            !text.contains('\x1b'),
            "ANSI in output of {args:?}: {text:?}"
        );
    }
}

#[tokio::test]
async fn r10_debug_prints_the_error_chain_one_cause_per_line() {
    // A port nothing listens on: a transport error with a cause chain. (A
    // dropped wiremock server goes back to a pool and keeps listening, so
    // bind and release a plain socket instead.)
    let uri = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let home = TempDir::new().unwrap();

    let plain = bin(home.path())
        .env("ELESTIO_API_URL", &uri)
        .env("ELESTIO_EMAIL", EMAIL)
        .env("ELESTIO_API_TOKEN", TOKEN)
        .env("ELESTIO_RETRY_BASE_MS", "1")
        .args(["auth", "test"])
        .output()
        .unwrap();
    assert_eq!(plain.status.code(), Some(1));
    let plain_err = stderr_of(&plain);
    let plain_lines: Vec<&str> = plain_err.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        plain_lines.len(),
        1,
        "without --debug the error is a single line: {plain_err:?}"
    );
    assert!(
        plain_lines[0].contains(PATH_CHECK_TOKEN) || plain_lines[0].to_lowercase().contains("sign"),
        "the line names what failed: {plain_err:?}"
    );

    let debug = bin(home.path())
        .env("ELESTIO_API_URL", &uri)
        .env("ELESTIO_EMAIL", EMAIL)
        .env("ELESTIO_API_TOKEN", TOKEN)
        .env("ELESTIO_RETRY_BASE_MS", "1")
        .args(["--debug", "auth", "test"])
        .output()
        .unwrap();
    assert_eq!(debug.status.code(), Some(1));
    let debug_err = stderr_of(&debug);
    let debug_lines: Vec<&str> = debug_err.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        debug_lines.len() > plain_lines.len(),
        "--debug must print the causes as extra lines:\nplain: {plain_err}\ndebug: {debug_err}"
    );
    // R6: neither form leaks the token.
    assert!(!plain_err.contains(TOKEN));
    assert!(!debug_err.contains(TOKEN));
}

// --------------------------------------------------------------------- R12

#[tokio::test]
async fn r12_error_names_the_operation_that_failed() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "service", VM_ID])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(VM_ID) || stderr.contains(PATH_GET_DETAILS),
        "must name the service or endpoint that failed: {stderr:?}"
    );
    assert!(
        stderr.contains("500"),
        "must say why (HTTP 500): {stderr:?}"
    );
    assert!(
        !stderr.trim().eq_ignore_ascii_case("request failed"),
        "bare 'Request failed' is not acceptable"
    );
}

#[tokio::test]
async fn r12_auth_failure_names_the_sign_in_operation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "services"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = stderr_of(&out).to_lowercase();
    assert!(
        stderr.contains("checkapitoken") || stderr.contains("sign") || stderr.contains("auth"),
        "must name the sign-in step: {stderr:?}"
    );
    assert!(stderr.contains("500"), "{stderr:?}");
}

// ------------------------------------------------------------- R13, R14, R15

#[tokio::test]
async fn r13_api_url_env_var_points_the_binary_at_the_mock() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["auth", "test"])
        .assert()
        .code(0);
    assert_eq!(requests_to(&server, PATH_CHECK_TOKEN).await.len(), 1);
}

#[tokio::test]
async fn r14_timeout_secs_env_var_bounds_each_attempt() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "status": "OK", "jwt": JWT }))
                .set_delay(Duration::from_secs(3)),
        )
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    let started = Instant::now();
    let out = bin_with_api(home.path(), &server)
        .env("ELESTIO_TIMEOUT_SECS", "1")
        .args(["auth", "test"])
        .output()
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    assert!(
        elapsed < Duration::from_secs(8),
        "three 1 s attempts must finish well under the 30 s default: {elapsed:?}"
    );
    assert_eq!(
        requests_to(&server, PATH_CHECK_TOKEN).await.len(),
        3,
        "R15: a timed-out attempt is retried, 3 attempts in total"
    );
}

#[tokio::test]
async fn r15_binary_retries_5xx_three_times_then_fails() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "services"])
        .assert()
        .code(1)
        .stderr(contains("502"));
    assert_eq!(requests_to(&server, PATH_GET_SERVICES).await.len(), 3);
}

#[tokio::test]
async fn r15_binary_recovers_after_a_transient_5xx() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    mount_get_services(&server, vec![raw_service(41928)]).await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "services"])
        .assert()
        .code(0)
        .stdout(contains("41928"));
    assert_eq!(requests_to(&server, PATH_GET_SERVICES).await.len(), 3);
}

// ------------------------------------------------------- R2, R3, R4 (binary)

#[tokio::test]
async fn r2_binary_uses_a_fresh_cached_jwt_without_signing_in() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![]).await;
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN, 0o600);
    write_config(
        home.path(),
        &json!({
            "defaultProject": PROJECT,
            "jwt": "cached-jwt-from-config",
            "jwtExpiry": now_ms() + 3_600_000
        }),
    );
    bin(home.path())
        .env("ELESTIO_API_URL", server.uri())
        .env("ELESTIO_RETRY_BASE_MS", "1")
        .arg("services")
        .assert()
        .code(0);
    assert!(
        requests_to(&server, PATH_CHECK_TOKEN).await.is_empty(),
        "fresh cached JWT: no sign-in"
    );
    let reqs = requests_to(&server, PATH_GET_SERVICES).await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(body_json(&reqs[0])["jwt"], "cached-jwt-from-config");
    assert_eq!(
        body_json(&reqs[0])["projectId"],
        PROJECT,
        "defaultProject used"
    );
}

#[tokio::test]
async fn r2_binary_signs_in_when_the_cached_jwt_is_about_to_expire() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![]).await;
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN, 0o600);
    let config = json!({
        "defaultProject": PROJECT,
        "jwt": "stale-jwt",
        "jwtExpiry": now_ms() + 2 * 60 * 1000 // two minutes left
    });
    write_config(home.path(), &config);
    bin(home.path())
        .env("ELESTIO_API_URL", server.uri())
        .env("ELESTIO_RETRY_BASE_MS", "1")
        .arg("services")
        .assert()
        .code(0);
    assert_eq!(requests_to(&server, PATH_CHECK_TOKEN).await.len(), 1);
    let reqs = requests_to(&server, PATH_GET_SERVICES).await;
    assert_eq!(body_json(&reqs[0])["jwt"], JWT, "the fresh JWT is used");

    // R54: the new JWT is not persisted; config.json is byte-identical.
    let after = fs::read_to_string(home.path().join(".elestio/config.json")).unwrap();
    assert_eq!(
        after,
        config.to_string(),
        "config.json must not be rewritten"
    );
    let entries: Vec<String> = fs::read_dir(home.path().join(".elestio"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let mut sorted = entries.clone();
    sorted.sort();
    assert_eq!(sorted, ["config.json", "credentials"], "no new files");
}

#[tokio::test]
async fn r3_binary_prefers_env_credentials_and_ignores_the_cache() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![]).await;
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), "file@example.com", "file-token", 0o600);
    write_config(
        home.path(),
        &json!({
            "defaultProject": PROJECT,
            "jwt": "cached-jwt-from-config",
            "jwtExpiry": now_ms() + 3_600_000
        }),
    );
    bin_with_api(home.path(), &server) // env: qa@example.com / TOKEN
        .arg("services")
        .assert()
        .code(0);
    let sign_ins = requests_to(&server, PATH_CHECK_TOKEN).await;
    assert_eq!(
        sign_ins.len(),
        1,
        "env credentials set: cache ignored, sign in"
    );
    let body = body_json(&sign_ins[0]);
    assert_eq!(body["email"], EMAIL, "env email wins over file");
    assert_eq!(body["token"], TOKEN, "env token wins over file");
}

#[tokio::test]
async fn r4_world_readable_credentials_file_warns_on_stderr_and_continues() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN, 0o644);
    let out = bin(home.path())
        .env("ELESTIO_API_URL", server.uri())
        .env("ELESTIO_RETRY_BASE_MS", "1")
        .args(["auth", "test"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "warn and continue");
    let stderr = stderr_of(&out);
    assert!(
        !stderr.trim().is_empty(),
        "a warning must be printed to stderr"
    );
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("credentials") || lower.contains("permission") || lower.contains("mode"),
        "the warning should be about the credentials file mode: {stderr:?}"
    );
    assert!(!stderr.contains(TOKEN), "R6");

    // Same run with 0600: nothing on stderr.
    fs::set_permissions(
        home.path().join(".elestio/credentials"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let quiet = bin(home.path())
        .env("ELESTIO_API_URL", server.uri())
        .env("ELESTIO_RETRY_BASE_MS", "1")
        .args(["auth", "test"])
        .output()
        .unwrap();
    assert!(
        stderr_of(&quiet).trim().is_empty(),
        "0600 must not warn: {:?}",
        stderr_of(&quiet)
    );
}

// --------------------------------------------------------------- R6 (binary)

#[tokio::test]
async fn r6_binary_never_prints_token_or_jwt_even_with_debug() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![raw_service(41928)]).await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "KO", "message": "boom"
        })))
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    for args in [
        vec!["--debug", "auth", "test"],
        vec!["--debug", "--project", PROJECT, "services"],
        vec!["--debug", "--json", "--project", PROJECT, "services"],
        vec!["--debug", "--project", PROJECT, "service", VM_ID], // error
        vec!["--debug", "--json", "auth", "test"],
    ] {
        let out = bin_with_api(home.path(), &server)
            .env("RUST_LOG", "trace")
            .env("ELESTIO_LOG", "trace")
            .args(&args)
            .output()
            .unwrap();
        let text = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(!text.contains(TOKEN), "{args:?} leaked the token: {text}");
        assert!(!text.contains(JWT), "{args:?} leaked the JWT: {text}");
    }
}

// ------------------------------------------------------------------ auth test

#[tokio::test]
async fn r19_auth_test_human_prints_the_email() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["auth", "test"])
        .assert()
        .code(0)
        .stdout(contains(EMAIL))
        .stdout(no_ansi());
}

#[tokio::test]
async fn r19_auth_test_json_has_authenticated_and_email() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--json", "auth", "test"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let v: Value = serde_json::from_str(&stdout_of(&out)).expect("json");
    assert_eq!(v["authenticated"], json!(true));
    assert_eq!(v["email"], json!(EMAIL));
}

#[tokio::test]
async fn r18_auth_test_ignores_a_fresh_cached_jwt() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN, 0o600);
    write_config(
        home.path(),
        &json!({ "jwt": "cached", "jwtExpiry": now_ms() + 3_600_000 }),
    );
    bin(home.path())
        .env("ELESTIO_API_URL", server.uri())
        .env("ELESTIO_RETRY_BASE_MS", "1")
        .args(["auth", "test"])
        .assert()
        .code(0);
    let reqs = requests_to(&server, PATH_CHECK_TOKEN).await;
    assert_eq!(reqs.len(), 1, "auth test must always call checkAPIToken");
    assert_eq!(body_json(&reqs[0])["email"], EMAIL);
    assert_eq!(body_json(&reqs[0])["token"], TOKEN);
}

#[tokio::test]
async fn r20_rejected_credentials_exit_1_and_are_not_confused_with_missing_ones() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "KO", "message": "Invalid API token"
        })))
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["auth", "test"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout_of(&out).is_empty(), "R7");
    let stderr = stderr_of(&out);
    assert!(
        !stderr.contains("no credentials found"),
        "rejection is not 'no credentials': {stderr:?}"
    );
    assert!(
        !stderr.contains("ELESTIO_EMAIL"),
        "rejection is not the R5 message: {stderr:?}"
    );
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("reject") || lower.contains("invalid api token"),
        "must say the API rejected the credentials: {stderr:?}"
    );
    assert_eq!(
        requests_to(&server, PATH_CHECK_TOKEN).await.len(),
        1,
        "KO not retried"
    );
}

#[tokio::test]
async fn r20_ok_without_jwt_is_also_a_rejection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "OK" })))
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["auth", "test"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains("no credentials found").not());
}

// ------------------------------------------------------------------- services

#[tokio::test]
async fn r22_no_project_exits_1_naming_flag_and_official_command() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let home = TempDir::new().unwrap();
    for args in [
        vec!["services"],
        vec!["service", VM_ID],
        vec!["firewall", "get", VM_ID],
    ] {
        let out = bin_with_api(home.path(), &server)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(stdout_of(&out).is_empty(), "R7 {args:?}");
        let stderr = stderr_of(&out);
        assert!(stderr.contains("--project"), "{args:?}: {stderr:?}");
        assert!(
            stderr.contains("elestio config --set-default-project"),
            "{args:?}: {stderr:?}"
        );
    }
}

#[tokio::test]
async fn r9_project_flag_overrides_default_project() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![]).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    let home = TempDir::new().unwrap();
    write_config(home.path(), &json!({ "defaultProject": "111" }));

    bin_with_api(home.path(), &server)
        .arg("services")
        .assert()
        .code(0);
    bin_with_api(home.path(), &server)
        .args(["--project", "222", "services"])
        .assert()
        .code(0);
    let reqs = requests_to(&server, PATH_GET_SERVICES).await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(body_json(&reqs[0])["projectId"], "111", "defaultProject");
    assert_eq!(body_json(&reqs[1])["projectId"], "222", "--project wins");

    bin_with_api(home.path(), &server)
        .args(["--project", "333", "service", VM_ID])
        .assert()
        .code(0);
    let details = requests_to(&server, PATH_GET_DETAILS).await;
    assert_eq!(body_json(&details[0])["projectID"], "333");
}

#[tokio::test]
async fn r21_services_lists_the_project() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![raw_service(41928), raw_service(7)]).await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "services"])
        .assert()
        .code(0)
        .stdout(contains("41928"))
        .stdout(contains("prod-postgres"));
    let reqs = requests_to(&server, PATH_GET_SERVICES).await;
    assert_eq!(reqs.len(), 1);
    let body = body_json(&reqs[0]);
    assert_eq!(body["appid"], "Cloudxx");
    assert_eq!(body["projectId"], PROJECT);
    assert_eq!(body["isActiveService"], "true");
    assert_eq!(body["jwt"], JWT);
}

#[tokio::test]
async fn r23_services_human_columns_in_spec_order() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![raw_service(41928)]).await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "services"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = stdout_of(&out);
    let row = stdout
        .lines()
        .find(|l| l.contains("41928"))
        .unwrap_or_else(|| panic!("no row for 41928 in {stdout:?}"));
    let mut last = 0;
    for cell in [
        "41928",
        "prod-postgres",
        "PostgreSQL",
        "16",
        "hetzner",
        "hel1",
        "MEDIUM-2C-4G",
        "running",
    ] {
        let pos = row[last..]
            .find(cell)
            .unwrap_or_else(|| panic!("{cell} missing or out of order in {row:?}"));
        last += pos + cell.len();
    }
}

#[tokio::test]
async fn r24_empty_service_list_is_reported_explicitly() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![]).await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "services"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = stdout_of(&out);
    assert!(!stdout.trim().is_empty(), "blank output is not allowed");
    assert!(
        stdout.to_lowercase().contains("no services"),
        "must say there are none: {stdout:?}"
    );
}

#[tokio::test]
async fn r25_services_json_is_an_array_with_exactly_nine_keys() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![raw_service(41928)]).await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--json", "--project", PROJECT, "services"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_str(&stdout_of(&out)).expect("json");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    let mut keys: Vec<&str> = arr[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
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
    assert_eq!(arr[0]["id"], "41928", "vmID number normalised to string");
    assert_eq!(arr[0]["deployment_status"], "Deployed");
}

#[tokio::test]
async fn r25_services_json_empty_is_an_empty_array() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![]).await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--json", "--project", PROJECT, "services"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_str(&stdout_of(&out)).expect("json");
    assert_eq!(v, json!([]));
}

// -------------------------------------------------------------------- service

#[tokio::test]
async fn r26_service_shows_details_for_one_id() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "service", VM_ID])
        .assert()
        .code(0)
        .stdout(contains("41928"))
        .stdout(contains("prod-postgres"))
        .stdout(contains("MEDIUM-2C-4G"));
    let reqs = requests_to(&server, PATH_GET_DETAILS).await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(body_json(&reqs[0])["vmID"], VM_ID);
    assert_eq!(body_json(&reqs[0])["projectID"], PROJECT);
}

#[tokio::test]
async fn r27_unknown_vmid_exits_1_with_not_found_naming_id_and_project() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![]).await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["--project", "555", "service", "999"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains("999"))
        .stderr(contains("555"))
        .stderr(predicate::function(|s: &str| {
            s.to_lowercase().contains("not found")
        }));
}

#[tokio::test]
async fn r28_service_output_omits_managed_db_cli_and_admin_user() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_get_services(&server, vec![raw_service(41928)]).await;
    let home = TempDir::new().unwrap();
    for args in [
        vec!["--project", PROJECT, "service", VM_ID],
        vec!["--json", "--project", PROJECT, "service", VM_ID],
        vec!["--project", PROJECT, "services"],
        vec!["--json", "--project", PROJECT, "services"],
    ] {
        let out = bin_with_api(home.path(), &server)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        let text = stdout_of(&out);
        assert!(!text.contains("SUPERSECRETPASS"), "{args:?}: {text}");
        assert!(!text.contains("admin-secret-user"), "{args:?}: {text}");
        assert!(!text.contains("managedDBCLI"), "{args:?}: {text}");
        assert!(!text.contains("adminUser"), "{args:?}: {text}");
    }
}

#[tokio::test]
async fn r28_show_secrets_flag_does_not_exist() {
    let home = TempDir::new().unwrap();
    bin(home.path())
        .args(["--show-secrets", "service", VM_ID])
        .assert()
        .code(1);
}

// --------------------------------------------------------------- firewall get

#[tokio::test]
async fn r29_firewall_get_fetches_details_then_rules() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![
            raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0", "::/0"]),
            raw_rule("INPUT", "5432", "tcp", &["10.0.0.0/8"]),
        ],
    )
    .await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "firewall", "get", VM_ID])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let stdout = stdout_of(&out);
    // R30: type, port, protocol, targets joined by ", ".
    let ssh = stdout
        .lines()
        .find(|l| l.contains("22"))
        .expect("ssh rule row");
    for needle in ["INPUT", "22", "tcp", "0.0.0.0/0, ::/0"] {
        assert!(ssh.contains(needle), "{needle} missing from {ssh:?}");
    }
    let pg = stdout
        .lines()
        .find(|l| l.contains("5432"))
        .expect("pg rule row");
    assert!(pg.contains("10.0.0.0/8"));
    // R31: the open rule is marked, the private one is not.
    assert!(
        ssh.contains(elestioctl::output::OPEN_MARKER),
        "the open rule must carry a visible marker: {ssh:?}"
    );
    assert!(
        !pg.contains(elestioctl::output::OPEN_MARKER),
        "a private rule is not marked: {pg:?}"
    );

    assert_eq!(requests_to(&server, PATH_GET_DETAILS).await.len(), 1);
    let actions = requests_to(&server, PATH_DO_ACTION).await;
    assert_eq!(actions.len(), 1);
    assert_eq!(body_json(&actions[0])["action"], "getFirewallRules");
    assert_eq!(body_json(&actions[0])["vmID"], VM_ID);
}

#[tokio::test]
async fn r29_disabled_firewall_says_disabled() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let mut svc = raw_service(41928);
    svc["isFirewallActivated"] = json!(0);
    mount_get_details(&server, vec![svc]).await;
    mount_firewall_rules(&server, vec![]).await;
    let home = TempDir::new().unwrap();
    bin_with_api(home.path(), &server)
        .args(["--project", PROJECT, "firewall", "get", VM_ID])
        .assert()
        .code(0)
        .stdout(predicate::function(|s: &str| {
            s.to_lowercase().contains("disabled")
        }));
}

#[tokio::test]
async fn r31_firewall_json_marks_open_to_internet() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![
            raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"]),
            raw_rule("INPUT", "443", "tcp", &["10.0.0.0/8", "::/0"]),
            raw_rule("INPUT", "5432", "tcp", &["10.0.0.0/8"]),
            raw_rule("OUTPUT", "80", "tcp", &["0.0.0.0/0"]),
        ],
    )
    .await;
    let home = TempDir::new().unwrap();
    let out = bin_with_api(home.path(), &server)
        .args(["--json", "--project", PROJECT, "firewall", "get", VM_ID])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let v: Value = serde_json::from_str(&stdout_of(&out)).expect("json");
    let rules = v["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 4);
    let open: Vec<bool> = rules
        .iter()
        .map(|r| r["open_to_internet"].as_bool().expect("boolean"))
        .collect();
    assert_eq!(open, [true, true, false, false]);
}

// ---------------------------------------------------------------------- drift

const DRIFT_TOML: &str = r#"
project = "112"

[[service]]
id            = "41928"
name          = "prod-postgres"
server_type   = "MEDIUM-2C-4G"
provider      = "hetzner"
datacenter    = "hel1"
version       = "16"

  [[service.firewall]]
  type     = "INPUT"
  port     = "22"
  protocol = "tcp"
  targets  = ["0.0.0.0/0", "::/0"]
"#;

async fn mount_details_for(server: &MockServer, vm_id: &str, infos: Vec<Value>) {
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .and(body_partial_json(json!({ "vmID": vm_id })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "serviceInfos": infos })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn r50_no_drift_prints_exact_line_and_exits_0() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![
            raw_rule("INPUT", "22", "tcp", &["::/0", "0.0.0.0/0"]), // other order
            raw_rule("INPUT", "5432", "tcp", &["10.0.0.0/8"]),      // extra, subset mode
        ],
    )
    .await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(home.path(), DRIFT_TOML);
    let out = bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert_eq!(stdout_of(&out).trim_end_matches('\n'), "No drift detected.");
}

#[tokio::test]
async fn r50_no_drift_json_has_drift_detected_false() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0", "::/0"])],
    )
    .await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(home.path(), DRIFT_TOML);
    let out = bin_with_api(home.path(), &server)
        .args(["--json", "drift", "--config", cfg.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let v: Value = serde_json::from_str(&stdout_of(&out)).expect("json");
    assert_eq!(v, json!({ "drift_detected": false, "differences": [] }));
}

#[tokio::test]
async fn r50_zero_services_is_not_an_error_prints_no_drift_and_warns() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(home.path(), "project = \"112\"\n");
    let out = bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert_eq!(stdout_of(&out).trim_end_matches('\n'), "No drift detected.");
    assert!(
        !stderr_of(&out).trim().is_empty(),
        "zero services must warn on stderr"
    );
    assert!(
        requests_to(&server, PATH_GET_DETAILS).await.is_empty(),
        "nothing to fetch"
    );
}

#[tokio::test]
async fn r51_drift_detected_exits_2_with_r48_lines() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let mut svc = raw_service(41928);
    svc["displayName"] = json!("staging-postgres");
    svc["serverType"] = json!("SMALL-1C-2G");
    mount_details_for(&server, "41928", vec![svc]).await;
    mount_details_for(&server, "555", vec![]).await;
    mount_firewall_rules(
        &server,
        vec![
            raw_rule("INPUT", "443", "tcp", &["0.0.0.0/0"]),
            raw_rule("OUTPUT", "53", "udp", &["8.8.8.8/32"]),
        ],
    )
    .await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(
        home.path(),
        r#"
project = "112"

[[service]]
id            = "41928"
name          = "prod-postgres"
server_type   = "MEDIUM-2C-4G"
provider      = "hetzner"
firewall_mode = "exact"

  [[service.firewall]]
  type     = "input"
  port     = "22"
  protocol = "TCP"
  targets  = ["::/0", "0.0.0.0/0"]

  [[service.firewall]]
  type     = "INPUT"
  port     = "443"
  protocol = "tcp"
  targets  = ["0.0.0.0/0"]

[[service]]
id = "555"
name = "gone"
"#,
    );
    let out = bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
    let stdout = stdout_of(&out);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "41928 name: declared=prod-postgres actual=staging-postgres",
            "41928 server_type: declared=MEDIUM-2C-4G actual=SMALL-1C-2G",
            "41928 firewall absent: INPUT 22/tcp [0.0.0.0/0, ::/0]",
            "41928 firewall unexpected: OUTPUT 53/udp [8.8.8.8/32]",
            "555 missing: service not found in project 112",
        ],
        "R42 order, R48 formats:\n{stdout}"
    );
    assert!(!stdout.contains('\x1b'), "R8");
}

#[tokio::test]
async fn r49_drift_json_shape() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let mut svc = raw_service(41928);
    svc["selected_software_tag"] = json!("15");
    mount_details_for(&server, "41928", vec![svc]).await;
    mount_details_for(&server, "555", vec![]).await;
    mount_firewall_rules(&server, vec![]).await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(
        home.path(),
        r#"
project = "112"

[[service]]
id      = "41928"
version = "16"

  [[service.firewall]]
  type     = "INPUT"
  port     = "22"
  protocol = "tcp"
  targets  = ["0.0.0.0/0"]

[[service]]
id = "555"
"#,
    );
    let out = bin_with_api(home.path(), &server)
        .args(["--json", "drift", "--config", cfg.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
    let v: Value = serde_json::from_str(&stdout_of(&out)).expect("single JSON document");
    assert_eq!(v["drift_detected"], json!(true));
    let diffs = v["differences"].as_array().expect("array");
    assert_eq!(diffs.len(), 3, "{v}");
    for d in diffs {
        let obj = d.as_object().unwrap();
        for key in ["kind", "service_id", "field", "declared", "actual"] {
            assert!(obj.contains_key(key), "{key} missing from {d}");
        }
    }
    assert_eq!(diffs[0]["kind"], "mismatch");
    assert_eq!(diffs[0]["service_id"], "41928");
    assert_eq!(diffs[0]["field"], "version");
    assert_eq!(diffs[0]["declared"], "16");
    assert_eq!(diffs[0]["actual"], "15");

    assert_eq!(diffs[1]["kind"], "absent");
    assert_eq!(diffs[1]["service_id"], "41928");
    assert_eq!(diffs[1]["field"], "firewall");
    assert_eq!(diffs[1]["actual"], Value::Null);

    assert_eq!(diffs[2]["kind"], "missing");
    assert_eq!(diffs[2]["service_id"], "555");
    assert_eq!(diffs[2]["field"], "missing");
    assert_eq!(diffs[2]["declared"], Value::Null);
    assert_eq!(diffs[2]["actual"], Value::Null);
}

#[tokio::test]
async fn r39_missing_service_is_reported_not_an_error() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![]).await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(
        home.path(),
        "project = \"112\"\n[[service]]\nid = \"41928\"\n",
    );
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .assert()
        .code(2)
        .stdout("41928 missing: service not found in project 112\n");
}

#[tokio::test]
async fn r37_fetch_error_exits_1_with_no_drift_output() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let mut svc = raw_service(1);
    svc["displayName"] = json!("wrong");
    mount_details_for(&server, "1", vec![svc]).await;
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .and(body_partial_json(json!({ "vmID": "2" })))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(
        home.path(),
        "project = \"112\"\n[[service]]\nid = \"1\"\nname = \"right\"\n[[service]]\nid = \"2\"\n",
    );
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains("500"));
}

#[tokio::test]
async fn r32_drift_project_falls_back_to_flag_then_default_project() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    let home = TempDir::new().unwrap();
    write_config(home.path(), &json!({ "defaultProject": "default-p" }));
    let cfg = write_toml(home.path(), "[[service]]\nid = \"41928\"\n");

    bin_with_api(home.path(), &server)
        .args([
            "--project",
            "flag-p",
            "drift",
            "--config",
            cfg.to_str().unwrap(),
        ])
        .assert()
        .code(0);
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .assert()
        .code(0);
    let reqs = requests_to(&server, PATH_GET_DETAILS).await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(body_json(&reqs[0])["projectID"], "flag-p");
    assert_eq!(body_json(&reqs[1])["projectID"], "default-p");

    // Per-service project beats everything.
    let cfg2 = write_toml(
        home.path(),
        "project = \"top-p\"\n[[service]]\nid = \"41928\"\nproject = \"own-p\"\n",
    );
    bin_with_api(home.path(), &server)
        .args([
            "--project",
            "flag-p",
            "drift",
            "--config",
            cfg2.to_str().unwrap(),
        ])
        .assert()
        .code(0);
    let reqs = requests_to(&server, PATH_GET_DETAILS).await;
    assert_eq!(body_json(&reqs[2])["projectID"], "own-p");
}

#[tokio::test]
async fn r22_drift_without_any_project_exits_1() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(home.path(), "[[service]]\nid = \"41928\"\n");
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains("--project"))
        .stderr(contains("elestio config --set-default-project"));
    assert!(requests_to(&server, PATH_GET_DETAILS).await.is_empty());
}

#[tokio::test]
async fn r34_malformed_toml_exits_1_naming_the_line() {
    let server = MockServer::start().await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(
        home.path(),
        "project = \"112\"\n\n[[service]]\nid = \"41928\" this is not toml\n",
    );
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains("line 4"));
}

#[tokio::test]
async fn r34_missing_config_file_exits_1_naming_the_path() {
    let server = MockServer::start().await;
    let home = TempDir::new().unwrap();
    let missing = home.path().join("does-not-exist.toml");
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", missing.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains("does-not-exist.toml"));
}

#[tokio::test]
async fn r35_service_without_id_exits_1_naming_the_index() {
    let server = MockServer::start().await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(
        home.path(),
        "project = \"112\"\n[[service]]\nid = \"1\"\n[[service]]\nname = \"no-id\"\n",
    );
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains('1'));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn r36_duplicate_ids_exit_1_naming_the_id() {
    let server = MockServer::start().await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(
        home.path(),
        "project = \"112\"\n[[service]]\nid = \"41928\"\n[[service]]\nid = 41928\n",
    );
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains("41928"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn r33_undeclared_fields_and_firewall_are_not_checked() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"])],
    )
    .await;
    let home = TempDir::new().unwrap();
    // Only `provider` is asserted; everything else in the actual state is
    // irrelevant, and the firewall must not even be fetched.
    let cfg = write_toml(
        home.path(),
        "project = \"112\"\n[[service]]\nid = \"41928\"\nprovider = \"hetzner\"\n",
    );
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .assert()
        .code(0)
        .stdout("No drift detected.\n");
    assert!(
        requests_to(&server, PATH_DO_ACTION).await.is_empty(),
        "firewall key absent: rules not fetched"
    );
}

#[tokio::test]
async fn r33_explicit_empty_firewall_in_exact_mode_flags_every_actual_rule() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"])],
    )
    .await;
    let home = TempDir::new().unwrap();
    let cfg = write_toml(
        home.path(),
        "project = \"112\"\n[[service]]\nid = \"41928\"\nfirewall_mode = \"exact\"\nfirewall = []\n",
    );
    bin_with_api(home.path(), &server)
        .args(["drift", "--config", cfg.to_str().unwrap()])
        .assert()
        .code(2)
        .stdout("41928 firewall unexpected: INPUT 22/tcp [0.0.0.0/0]\n");
}

// ---------------------------------------------------------------------- R54

#[tokio::test]
async fn r54_binary_writes_nothing_under_an_empty_home() {
    let server = MockServer::start().await;
    mount_sign_in_ok(&server).await;
    mount_get_services(&server, vec![raw_service(41928)]).await;
    mount_get_details(&server, vec![raw_service(41928)]).await;
    mount_firewall_rules(
        &server,
        vec![raw_rule("INPUT", "22", "tcp", &["0.0.0.0/0"])],
    )
    .await;

    let home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let cfg = write_toml(work.path(), DRIFT_TOML);
    assert!(dir_is_empty(home.path()));

    let runs: Vec<Vec<String>> = vec![
        vec!["auth".into(), "test".into()],
        vec!["--project".into(), PROJECT.into(), "services".into()],
        vec![
            "--project".into(),
            PROJECT.into(),
            "service".into(),
            VM_ID.into(),
        ],
        vec![
            "--project".into(),
            PROJECT.into(),
            "firewall".into(),
            "get".into(),
            VM_ID.into(),
        ],
        vec![
            "drift".into(),
            "--config".into(),
            cfg.to_str().unwrap().into(),
        ],
        vec!["--json".into(), "auth".into(), "test".into()],
        vec![
            "--debug".into(),
            "--project".into(),
            PROJECT.into(),
            "service".into(),
            "9".into(),
        ],
    ];
    for args in runs {
        let out = bin_with_api(home.path(), &server)
            .current_dir(work.path())
            .args(&args)
            .output()
            .unwrap();
        assert!(out.status.code().is_some(), "{args:?} did not exit cleanly");
        assert!(
            dir_is_empty(home.path()),
            "{args:?} created something under HOME: {:?}",
            fs::read_dir(home.path())
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect::<Vec<_>>()
        );
    }
    // The working directory gained nothing but the config we wrote.
    let work_entries: Vec<_> = fs::read_dir(work.path()).unwrap().collect();
    assert_eq!(work_entries.len(), 1, "no files written next to the config");
}

#[test]
fn r54_no_credentials_path_writes_nothing_either() {
    let home = TempDir::new().unwrap();
    bin(home.path()).args(["auth", "test"]).assert().code(1);
    bin(home.path()).args(["--bogus"]).assert().code(1);
    assert!(dir_is_empty(home.path()));
}
