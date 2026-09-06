//! Shared fixtures for the black-box suite. Each integration test file is its
//! own crate, so not every helper is used from every file.
#![allow(dead_code)]
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use elestioctl::client::{ApiClient, ClientConfig};
use elestioctl::config::{CredentialSource, Credentials, EnvOverrides, Settings};
use elestioctl::secret::Secret;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const EMAIL: &str = "qa@example.com";
pub const TOKEN: &str = "api-token-secret-abc123";
pub const JWT: &str = "jwt-secret-xyz789";
pub const PROJECT: &str = "112";
pub const VM_ID: &str = "41928";

pub const PATH_CHECK_TOKEN: &str = "/api/auth/checkAPIToken";
pub const PATH_GET_SERVICES: &str = "/api/servers/getServices";
pub const PATH_GET_DETAILS: &str = "/api/servers/getServerDetails";
pub const PATH_DO_ACTION: &str = "/api/servers/DoActionOnServer";

/// A client pointed at `server` with a tiny backoff so retries do not sleep.
pub fn client_for(server: &MockServer) -> ApiClient {
    client_with_timeout(server, Duration::from_secs(5))
}

pub fn client_with_timeout(server: &MockServer, timeout: Duration) -> ApiClient {
    ApiClient::new(ClientConfig {
        base_url: server.uri(),
        timeout,
        retry_base: Duration::from_millis(2),
    })
    .expect("client builds")
}

/// A client that already holds a JWT, so calls other than sign-in can be made.
pub fn signed_in_client(server: &MockServer) -> ApiClient {
    let mut c = client_for(server);
    c.set_jwt(Secret::new(JWT));
    c
}

pub fn credentials(source: CredentialSource) -> Credentials {
    Credentials {
        email: EMAIL.to_string(),
        api_token: Secret::new(TOKEN),
        source,
    }
}

pub fn settings() -> Settings {
    Settings {
        credentials: credentials(CredentialSource::File),
        default_project: Some(PROJECT.to_string()),
        cached_jwt: None,
        warnings: Vec::new(),
    }
}

pub fn env_overrides() -> EnvOverrides {
    EnvOverrides {
        email: Some(EMAIL.to_string()),
        api_token: Some(Secret::new(TOKEN)),
    }
}

/// Mount a successful sign-in.
pub async fn mount_sign_in_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(PATH_CHECK_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "OK",
            "jwt": JWT
        })))
        .mount(server)
        .await;
}

/// A raw service object as the API returns it, with `vmID` as a number and
/// the two secret-bearing fields present so tests can assert they are dropped.
pub fn raw_service(vm_id: u64) -> Value {
    json!({
        "vmID": vm_id,
        "displayName": "prod-postgres",
        "templateName": "PostgreSQL",
        "selected_software_tag": "16",
        "provider": "hetzner",
        "datacenter": "hel1",
        "serverType": "MEDIUM-2C-4G",
        "status": "running",
        "deploymentStatus": "Deployed",
        "isFirewallActivated": 1,
        "ipv4": "10.0.0.1",
        "cname": "prod-postgres.example.elest.io",
        "managedDBCLI": "psql postgres://admin:SUPERSECRETPASS@host/db",
        "adminUser": "admin-secret-user"
    })
}

pub async fn mount_get_services(server: &MockServer, servers: Vec<Value>) {
    Mock::given(method("POST"))
        .and(path(PATH_GET_SERVICES))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "servers": servers })))
        .mount(server)
        .await;
}

pub async fn mount_get_details(server: &MockServer, infos: Vec<Value>) {
    Mock::given(method("POST"))
        .and(path(PATH_GET_DETAILS))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "serviceInfos": infos })))
        .mount(server)
        .await;
}

pub fn raw_rule(rule_type: &str, port: &str, protocol: &str, targets: &[&str]) -> Value {
    json!({
        "type": rule_type,
        "port": port,
        "protocol": protocol,
        "targets": targets,
    })
}

pub async fn mount_firewall_rules(server: &MockServer, rules: Vec<Value>) {
    Mock::given(method("POST"))
        .and(path(PATH_DO_ACTION))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "rules": rules })))
        .mount(server)
        .await;
}

/// Requests the mock received on `p`.
pub async fn requests_to(server: &MockServer, p: &str) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == p)
        .collect()
}

pub fn body_json(req: &wiremock::Request) -> Value {
    serde_json::from_slice(&req.body).expect("request body is JSON")
}
