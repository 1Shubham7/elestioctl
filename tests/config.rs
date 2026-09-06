//! R1 to R6: credentials and config loading, from files in a temp home.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use elestioctl::config::{
    self, CachedJwt, ConfigError, CredentialSource, EnvOverrides, CONFIG_DIR, CONFIG_FILE,
    CREDENTIALS_FILE, ENV_API_TOKEN, ENV_EMAIL,
};
use elestioctl::secret::Secret;
use tempfile::TempDir;

use common::{EMAIL, JWT, TOKEN};

fn write_credentials(home: &Path, email: &str, token: &str) -> PathBuf {
    let dir = home.join(CONFIG_DIR);
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join(CREDENTIALS_FILE);
    fs::write(
        &p,
        serde_json::json!({ "email": email, "apiToken": token }).to_string(),
    )
    .unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn write_config(home: &Path, body: &serde_json::Value) -> PathBuf {
    let dir = home.join(CONFIG_DIR);
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join(CONFIG_FILE);
    fs::write(&p, body.to_string()).unwrap();
    p
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

fn no_env() -> EnvOverrides {
    EnvOverrides::default()
}

#[test]
fn r1_reads_credentials_from_dot_elestio_credentials() {
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN);

    let s = config::load(home.path(), &no_env()).expect("loads");
    assert_eq!(s.credentials.email, EMAIL);
    assert_eq!(s.credentials.api_token.expose(), TOKEN);
    assert_eq!(s.credentials.source, CredentialSource::File);
}

#[test]
fn r1_config_dir_is_dot_elestio_under_home() {
    let home = Path::new("/home/someone");
    assert_eq!(config::config_dir(home), home.join(".elestio"));
    assert_eq!(CONFIG_DIR, ".elestio");
    assert_eq!(CREDENTIALS_FILE, "credentials");
    assert_eq!(CONFIG_FILE, "config.json");
}

#[test]
fn r1_malformed_credentials_file_is_an_error_not_a_panic() {
    let home = TempDir::new().unwrap();
    let dir = home.path().join(CONFIG_DIR);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(CREDENTIALS_FILE), "{ not json").unwrap();

    let err = config::load(home.path(), &no_env()).expect_err("error");
    assert!(
        matches!(err, ConfigError::MalformedCredentials { .. }),
        "got {err:?}"
    );
}

#[test]
fn r2_reads_default_project_jwt_and_expiry_from_config_json() {
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN);
    let expiry = now_ms() + 60 * 60 * 1000;
    write_config(
        home.path(),
        &serde_json::json!({
            "defaultProject": "112",
            "jwt": JWT,
            "jwtExpiry": expiry,
            "someUnknownField": { "nested": true },
            "apiUrl": "ignored"
        }),
    );

    let s = config::load(home.path(), &no_env()).expect("loads");
    assert_eq!(s.default_project.as_deref(), Some("112"));
    let cached = s.cached_jwt.expect("cached jwt present");
    assert_eq!(cached.jwt.expose(), JWT);
    assert_eq!(cached.expires_at_ms, expiry);
}

#[test]
fn r2_missing_config_json_is_not_an_error() {
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN);

    let s = config::load(home.path(), &no_env()).expect("loads without config.json");
    assert_eq!(s.default_project, None);
    assert!(s.cached_jwt.is_none());
}

#[test]
fn r2_config_json_without_jwt_yields_no_cached_jwt() {
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN);
    write_config(home.path(), &serde_json::json!({ "defaultProject": "7" }));

    let s = config::load(home.path(), &no_env()).expect("loads");
    assert_eq!(s.default_project.as_deref(), Some("7"));
    assert!(s.cached_jwt.is_none());
}

#[test]
fn r2_cached_jwt_is_fresh_only_when_more_than_five_minutes_remain() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let now_ms = 1_700_000_000_000u64;
    let five_min = 5 * 60 * 1000;

    let fresh = CachedJwt {
        jwt: Secret::new(JWT),
        expires_at_ms: now_ms + five_min + 1,
    };
    assert!(fresh.is_fresh_at(now), "5 minutes + 1 ms ahead is fresh");

    let boundary = CachedJwt {
        jwt: Secret::new(JWT),
        expires_at_ms: now_ms + five_min,
    };
    assert!(
        !boundary.is_fresh_at(now),
        "exactly 5 minutes ahead is not 'more than' 5 minutes"
    );

    let stale = CachedJwt {
        jwt: Secret::new(JWT),
        expires_at_ms: now_ms + 1000,
    };
    assert!(!stale.is_fresh_at(now));

    let expired = CachedJwt {
        jwt: Secret::new(JWT),
        expires_at_ms: now_ms - 1000,
    };
    assert!(!expired.is_fresh_at(now));
}

#[test]
fn r3_environment_overrides_file_credentials() {
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), "file@example.com", "file-token");

    let env = EnvOverrides {
        email: Some("env@example.com".to_string()),
        api_token: Some(Secret::new("env-token")),
    };
    let s = config::load(home.path(), &env).expect("loads");
    assert_eq!(s.credentials.email, "env@example.com");
    assert_eq!(s.credentials.api_token.expose(), "env-token");
    assert_eq!(s.credentials.source, CredentialSource::Environment);
}

#[test]
fn r3_environment_credentials_work_without_any_file() {
    let home = TempDir::new().unwrap();
    let s = config::load(home.path(), &common::env_overrides()).expect("loads from env alone");
    assert_eq!(s.credentials.email, EMAIL);
    assert_eq!(s.credentials.api_token.expose(), TOKEN);
    assert_eq!(s.credentials.source, CredentialSource::Environment);
}

#[test]
fn r3_environment_credentials_ignore_cached_jwt() {
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN);
    write_config(
        home.path(),
        &serde_json::json!({
            "defaultProject": "112",
            "jwt": JWT,
            "jwtExpiry": now_ms() + 3_600_000
        }),
    );

    let s = config::load(home.path(), &common::env_overrides()).expect("loads");
    assert!(
        s.cached_jwt.is_none(),
        "cached JWT must be ignored when env credentials are set"
    );
    // The default project is not a credential and still applies.
    assert_eq!(s.default_project.as_deref(), Some("112"));
}

#[test]
fn r3_either_env_variable_alone_disables_cached_jwt() {
    let home = TempDir::new().unwrap();
    write_credentials(home.path(), EMAIL, TOKEN);
    write_config(
        home.path(),
        &serde_json::json!({ "jwt": JWT, "jwtExpiry": now_ms() + 3_600_000 }),
    );

    let only_token = EnvOverrides {
        email: None,
        api_token: Some(Secret::new("other-token")),
    };
    if let Ok(s) = config::load(home.path(), &only_token) {
        assert!(s.cached_jwt.is_none(), "token override set: cache ignored");
    }

    let only_email = EnvOverrides {
        email: Some("other@example.com".to_string()),
        api_token: None,
    };
    if let Ok(s) = config::load(home.path(), &only_email) {
        assert!(s.cached_jwt.is_none(), "email override set: cache ignored");
    }
}

#[test]
fn r3_env_constant_names_match_terraform_provider() {
    assert_eq!(ENV_EMAIL, "ELESTIO_EMAIL");
    assert_eq!(ENV_API_TOKEN, "ELESTIO_API_TOKEN");
}

#[test]
fn r4_group_or_other_readable_credentials_file_warns() {
    let home = TempDir::new().unwrap();
    let p = write_credentials(home.path(), EMAIL, TOKEN);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();

    let s = config::load(home.path(), &no_env()).expect("still loads");
    assert!(
        !s.warnings.is_empty(),
        "mode 0644 must produce a warning, got none"
    );
    assert_eq!(s.credentials.email, EMAIL, "and the tool continues");
}

#[test]
fn r4_group_only_bit_also_warns() {
    let home = TempDir::new().unwrap();
    let p = write_credentials(home.path(), EMAIL, TOKEN);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();

    let s = config::load(home.path(), &no_env()).expect("still loads");
    assert!(!s.warnings.is_empty(), "mode 0640 has 0o077 bits set");
}

#[test]
fn r4_owner_only_credentials_file_does_not_warn() {
    let home = TempDir::new().unwrap();
    let p = write_credentials(home.path(), EMAIL, TOKEN);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();

    let s = config::load(home.path(), &no_env()).expect("loads");
    assert!(
        s.warnings.is_empty(),
        "mode 0600 must not warn, got {:?}",
        s.warnings
    );
}

#[test]
fn r5_no_credentials_error_names_path_and_both_env_vars() {
    let home = TempDir::new().unwrap();
    let err = config::load(home.path(), &no_env()).expect_err("must fail");
    assert!(
        matches!(err, ConfigError::NoCredentials { .. }),
        "got {err:?}"
    );

    let msg = err.to_string();
    let expected_path = home.path().join(CONFIG_DIR).join(CREDENTIALS_FILE);
    assert!(
        msg.contains(&expected_path.display().to_string()),
        "message must name the credentials path {}: {msg}",
        expected_path.display()
    );
    assert!(
        msg.contains("ELESTIO_EMAIL"),
        "must name ELESTIO_EMAIL: {msg}"
    );
    assert!(
        msg.contains("ELESTIO_API_TOKEN"),
        "must name ELESTIO_API_TOKEN: {msg}"
    );
}

#[test]
fn r5_empty_dot_elestio_directory_is_still_no_credentials() {
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(CONFIG_DIR)).unwrap();
    let err = config::load(home.path(), &no_env()).expect_err("must fail");
    assert!(
        matches!(err, ConfigError::NoCredentials { .. }),
        "got {err:?}"
    );
}

#[test]
fn r6_secret_debug_is_redacted() {
    let s = Secret::new(TOKEN);
    let dbg = format!("{s:?}");
    assert!(!dbg.contains(TOKEN), "Debug leaked the secret: {dbg}");
    assert!(
        dbg.contains("[REDACTED]"),
        "Debug must say [REDACTED]: {dbg}"
    );
    assert_eq!(s.expose(), TOKEN, "expose() is the only way out");
    assert!(!s.is_empty());
    assert!(Secret::new("").is_empty());
}

#[test]
fn r6_credentials_debug_redacts_token() {
    let c = common::credentials(CredentialSource::File);
    let dbg = format!("{c:?}");
    assert!(
        !dbg.contains(TOKEN),
        "Credentials Debug leaked token: {dbg}"
    );
    assert!(dbg.contains("[REDACTED]"), "{dbg}");
    assert!(
        dbg.contains(EMAIL),
        "email is not a secret and may be shown"
    );
}

#[test]
fn r6_settings_debug_redacts_token_and_jwt() {
    let mut s = common::settings();
    s.cached_jwt = Some(CachedJwt {
        jwt: Secret::new(JWT),
        expires_at_ms: 1,
    });
    let dbg = format!("{s:?}");
    let alt = format!("{s:#?}");
    for out in [dbg, alt] {
        assert!(!out.contains(TOKEN), "Settings Debug leaked token: {out}");
        assert!(!out.contains(JWT), "Settings Debug leaked jwt: {out}");
        assert!(out.contains("[REDACTED]"), "{out}");
    }
}

#[test]
fn r6_cached_jwt_debug_redacts_jwt() {
    let c = CachedJwt {
        jwt: Secret::new(JWT),
        expires_at_ms: 42,
    };
    let dbg = format!("{c:?}");
    assert!(!dbg.contains(JWT), "{dbg}");
    assert!(dbg.contains("[REDACTED]"), "{dbg}");
}

#[test]
fn r6_env_overrides_debug_redacts_token() {
    let e = common::env_overrides();
    let dbg = format!("{e:?}");
    assert!(!dbg.contains(TOKEN), "{dbg}");
    assert!(dbg.contains("[REDACTED]"), "{dbg}");
}

#[test]
fn r6_config_error_messages_never_contain_secrets() {
    // A malformed credentials file whose raw text holds a token-like string:
    // the error must describe the problem without echoing the contents.
    let home = TempDir::new().unwrap();
    let dir = home.path().join(CONFIG_DIR);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(CREDENTIALS_FILE),
        format!("{{ \"email\": \"{EMAIL}\", \"apiToken\": \"{TOKEN}\" "),
    )
    .unwrap();
    let err = config::load(home.path(), &no_env()).expect_err("error");
    let text = format!("{err} {err:?}");
    assert!(!text.contains(TOKEN), "error leaked the token: {text}");
}

#[test]
fn r54_loading_config_creates_nothing_in_home() {
    let home = TempDir::new().unwrap();
    let _ = config::load(home.path(), &no_env());
    let _ = config::load(home.path(), &common::env_overrides());
    let entries: Vec<_> = fs::read_dir(home.path()).unwrap().collect();
    assert!(
        entries.is_empty(),
        "config::load must not write: {entries:?}"
    );
}
