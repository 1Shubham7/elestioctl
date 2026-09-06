# Public API surface of the `elestioctl` library

Generated from `src/` by signature extraction: every `pub` item with its doc
comment. Function bodies are deliberately absent. This is the whole of what
QA knows about the implementation. Requirement IDs in doc comments refer to
`spec/SPEC.md`.

Binary: `elestioctl` (target/debug/elestioctl after `cargo build`).
Global flags: `--json`, `--debug`, `--project <ID>`.
Subcommands: `auth test`, `services`, `service <VM_ID>`, `firewall get <VM_ID>`,
`drift --config <PATH>`.

## `src/lib.rs`

> `elestioctl`: a read-only command line client for the Elestio platform,
> plus a drift-detection command that compares declared TOML state against
> what the API reports.
> 
> The crate is split into a library (this file and its modules) and a thin
> binary in `src/main.rs`. The library holds everything testable: config
> loading, the HTTP client, data models, and the pure diff engine. The binary
> only parses arguments, calls into the library, and maps results to exit
> codes.
> 
> Requirement identifiers (`R1` to `R60`) refer to `spec/SPEC.md`.

```rust
pub mod client;
```

```rust
pub mod commands;
```

```rust
pub mod config;
```

```rust
pub mod diff;
```

```rust
pub mod drift_config;
```

```rust
pub mod model;
```

```rust
pub mod output;
```

```rust
pub mod report;
```

```rust
pub mod secret;
```

<!-- doc -->
/// Crate version, taken from `Cargo.toml` at compile time.
```rust
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```


## `src/secret.rs`

> A string that refuses to be printed.
> 
> R6: the API token and the JWT must never appear in any output, including
> `--debug` output and error messages. The cheapest way to make that true
> everywhere at once is to make the *type* that holds them incapable of
> displaying its contents. `Secret` implements `Debug` by printing
> `[REDACTED]`, does not implement `Display` at all, and only gives the raw
> value back through an explicitly named method. A reviewer grepping for
> `.expose()` sees every place the value leaves the wrapper.
> 
> Rust note: `#[derive(Debug)]` on a struct holding a `String` would print
> the string. Writing `Debug` by hand is the whole point of this type.

<!-- doc -->
/// A credential value (API token or JWT) that redacts itself in `Debug`.
/// `#[derive(Clone, PartialEq, Eq)]`
```rust
pub struct Secret(String);
```

```rust
impl Secret
```

    <!-- doc -->
    /// Wrap a raw credential.
    ```rust
    pub fn new(value: impl Into<String>) -> Self
    ```

    <!-- doc -->
    /// Return the raw value. The name is deliberately loud.
    ```rust
    pub fn expose(&self) -> &str
    ```

    <!-- doc -->
    /// True when the wrapped value is the empty string.
    ```rust
    pub fn is_empty(&self) -> bool
    ```

```rust
impl fmt::Debug for Secret
```


## `src/config.rs`

> Credentials and defaults, read from the same files the official CLI
> writes (R1, R2) with environment overrides (R3).
> 
> Nothing in this module writes to disk (R54). The `home` argument on the
> loader exists so tests can point it at a temporary directory instead of
> the real `~/.elestio`.

<!-- doc -->
/// Environment variable holding the account email (R3).
```rust
pub const ENV_EMAIL: &str = "ELESTIO_EMAIL";
```

<!-- doc -->
/// Environment variable holding the API token (R3).
```rust
pub const ENV_API_TOKEN: &str = "ELESTIO_API_TOKEN";
```

<!-- doc -->
/// Directory under `$HOME` that the official CLI uses.
```rust
pub const CONFIG_DIR: &str = ".elestio";
```

<!-- doc -->
/// Credentials file name inside [`CONFIG_DIR`] (R1).
```rust
pub const CREDENTIALS_FILE: &str = "credentials";
```

<!-- doc -->
/// Defaults file name inside [`CONFIG_DIR`] (R2).
```rust
pub const CONFIG_FILE: &str = "config.json";
```

<!-- doc -->
/// Where the credentials came from. Reported in `auth test` output and used
/// to decide whether a cached JWT may be trusted (R3).
/// `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`
```rust
pub enum CredentialSource
```

    <!-- doc -->
    /// Read from `~/.elestio/credentials`.
    ```rust
    File,
    ```

    <!-- doc -->
    /// Read from `ELESTIO_EMAIL` and `ELESTIO_API_TOKEN`.
    ```rust
    Environment,
    ```

<!-- doc -->
/// Account email plus API token. `Debug` redacts the token (R6).
/// `#[derive(Debug, Clone)]`
```rust
pub struct Credentials
```

    <!-- doc -->
    /// Account email.
    ```rust
    pub email: String,
    ```

    <!-- doc -->
    /// API token; redacted in `Debug`.
    ```rust
    pub api_token: Secret,
    ```

    <!-- doc -->
    /// Where these came from.
    ```rust
    pub source: CredentialSource,
    ```

<!-- doc -->
/// A JWT read from `config.json` together with its expiry (R2).
/// `#[derive(Debug, Clone)]`
```rust
pub struct CachedJwt
```

    <!-- doc -->
    /// The token; redacted in `Debug`.
    ```rust
    pub jwt: Secret,
    ```

    <!-- doc -->
    /// Expiry as milliseconds since the Unix epoch, as the official CLI stores it.
    ```rust
    pub expires_at_ms: u64,
    ```

```rust
impl CachedJwt
```

    <!-- doc -->
    /// True when the token expires more than five minutes after `now` (R2).
    ```rust
    pub fn is_fresh_at(&self, now: SystemTime) -> bool
    ```

<!-- doc -->
/// Everything the tool knows before it talks to the API.
/// `#[derive(Debug, Clone)]`
```rust
pub struct Settings
```

    <!-- doc -->
    /// Resolved credentials.
    ```rust
    pub credentials: Credentials,
    ```

    <!-- doc -->
    /// `defaultProject` from `config.json`, if any (R2).
    ```rust
    pub default_project: Option<String>,
    ```

    <!-- doc -->
    /// Cached JWT from `config.json`, if present and if the credentials came
    /// from the file. Environment credentials always ignore the cache (R3).
    ```rust
    pub cached_jwt: Option<CachedJwt>,
    ```

    <!-- doc -->
    /// Warnings to print to stderr (R4). Collected rather than printed so the
    /// loader stays free of I/O other than reading files.
    ```rust
    pub warnings: Vec<String>,
    ```

<!-- doc -->
/// Errors from loading configuration. Every variant names the path or
/// variable involved (R5, R12).
/// `#[derive(Debug, thiserror::Error)]`
```rust
pub enum ConfigError
```

    <!-- doc -->
    /// No credentials in the file or the environment (R5).
    ```rust
        "no credentials found: looked for {path} and the environment variables {env_email} and {env_token}"
    ```

    ```rust
    )]
    NoCredentials
    ```

    <!-- doc -->
    /// The credentials file exists but is not the JSON shape the official CLI writes.
    ```rust
    MalformedCredentials
    ```

    <!-- doc -->
    /// `config.json` exists but is not valid JSON.
    ```rust
    MalformedConfig
    ```

    <!-- doc -->
    /// A file could not be read for a reason other than not existing.
    ```rust
    Io
    ```

```rust
impl fmt::Display for JsonStringOrNumber
```

<!-- doc -->
/// Environment values, passed in explicitly so tests do not have to mutate
/// the process environment (which is racy across threads).
/// `#[derive(Debug, Default, Clone)]`
```rust
pub struct EnvOverrides
```

    <!-- doc -->
    /// Value of `ELESTIO_EMAIL`, if set.
    ```rust
    pub email: Option<String>,
    ```

    <!-- doc -->
    /// Value of `ELESTIO_API_TOKEN`, if set; redacted in `Debug`.
    ```rust
    pub api_token: Option<Secret>,
    ```

```rust
impl EnvOverrides
```

    <!-- doc -->
    /// Read the overrides from the real process environment. Empty strings
    /// count as unset.
    ```rust
    pub fn from_process_env() -> Self
    ```

<!-- doc -->
/// Path of the config directory under `home`.
```rust
pub fn config_dir(home: &Path) -> PathBuf { ... }
```

<!-- doc -->
/// Resolve the user's home directory from `HOME` (or `USERPROFILE` on
/// Windows). Returns `None` when neither is set.
```rust
pub fn home_dir() -> Option<PathBuf> { ... }
```

<!-- doc -->
/// Load settings from `home/.elestio/*` and the given environment overrides.
/// 
/// Precedence (R3): environment credentials win over the file. When the
/// environment supplies either value, the cached JWT is ignored because it
/// may belong to a different account.
```rust
pub fn load(home: &Path, env: &EnvOverrides) -> Result<Settings, ConfigError> { ... }
```


## `src/client.rs`

> HTTP client for the Elestio API.
> 
> Everything that leaves this process goes through [`ApiClient::request`].
> That single funnel is where the read-only allowlist (R53), the JWT
> injection (R6), the per-attempt timeout (R14), the retry policy (R15),
> the envelope check (R16), and the path-naming parse errors (R17) live.
> The typed methods below it (`sign_in`, `list_services`, ...) only build a
> body and pick fields out of the result.
> 
> Rust note: this module is `async`. The alternative, `reqwest::blocking`,
> would read more simply, but the test mock server (`wiremock`) is
> async-native and mixing the two means running the blocking client on a
> separate thread inside every test. A `current_thread` tokio runtime in
> `main` costs nothing measurable for a CLI that makes a handful of
> sequential requests.

<!-- doc -->
/// Production API (R13).
```rust
pub const DEFAULT_BASE_URL: &str = "https://api.elest.io";
```

<!-- doc -->
/// Environment variable overriding the base URL (R13).
```rust
pub const ENV_BASE_URL: &str = "ELESTIO_API_URL";
```

<!-- doc -->
/// Environment variable overriding the per-attempt timeout in seconds (R14).
```rust
pub const ENV_TIMEOUT_SECS: &str = "ELESTIO_TIMEOUT_SECS";
```

<!-- doc -->
/// Environment variable overriding the retry backoff base in milliseconds (R15).
```rust
pub const ENV_RETRY_BASE_MS: &str = "ELESTIO_RETRY_BASE_MS";
```

<!-- doc -->
/// Default per-attempt timeout (R14).
```rust
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
```

<!-- doc -->
/// Default backoff base: retry 1 waits this long, retry 2 waits double (R15).
```rust
pub const DEFAULT_RETRY_BASE: Duration = Duration::from_millis(500);
```

<!-- doc -->
/// Total requests per call, including the first (R15).
```rust
pub const MAX_ATTEMPTS: u32 = 3;
```

<!-- doc -->
/// The closed set of calls this tool may make (R53).
/// 
/// Each variant is one row of the allowlist. There is no variant for
/// anything that mutates, and no way to construct a request for a path that
/// is not here except through [`ApiClient::request`], which checks
/// [`is_allowed`] first.
/// `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`
```rust
pub enum Endpoint
```

    <!-- doc -->
    /// `POST /api/auth/checkAPIToken`: exchange email and API token for a JWT.
    ```rust
    CheckApiToken,
    ```

    <!-- doc -->
    /// `POST /api/servers/getServices`: list services in a project.
    ```rust
    GetServices,
    ```

    <!-- doc -->
    /// `POST /api/servers/getServerDetails`: one service by `vmID`.
    ```rust
    GetServerDetails,
    ```

    <!-- doc -->
    /// `POST /api/servers/DoActionOnServer` with `action = "getFirewallRules"`.
    ```rust
    GetFirewallRules,
    ```

```rust
impl Endpoint
```

    <!-- doc -->
    /// URL path.
    ```rust
    pub fn path(self) -> &'static str
    ```

    <!-- doc -->
    /// The `action` body member, for the shared action endpoint.
    ```rust
    pub fn action(self) -> Option<&'static str>
    ```

    <!-- doc -->
    /// Whether the call needs a JWT in the body. Only sign-in does not.
    ```rust
    pub fn needs_jwt(self) -> bool
    ```

    <!-- doc -->
    /// Every allowed endpoint, in a fixed order.
    ```rust
    pub const ALL: [Endpoint; 4] = [
        Endpoint::CheckApiToken,
    ```

<!-- doc -->
/// R53: true only for the exact (method, path, action) triples in the spec.
/// 
/// `action` is the value of the request body's `action` member, or `None`
/// when the body has none. The shared action endpoint is allowed only with
/// `getFirewallRules`; the same path with any other action, or with no
/// action, is refused.
```rust
pub fn is_allowed(method: &str, path: &str, action: Option<&str>) -> bool { ... }
```

<!-- doc -->
/// Errors from the client. Each variant names the path involved (R12, R16).
/// `#[derive(Debug, thiserror::Error)]`
```rust
pub enum ClientError
```

<!-- doc -->
/// Tunables for [`ApiClient`].
/// `#[derive(Debug, Clone)]`
```rust
pub struct ClientConfig
```

    <!-- doc -->
    /// Base URL without a trailing slash (R13).
    ```rust
    pub base_url: String,
    ```

    <!-- doc -->
    /// Per-attempt timeout (R14).
    ```rust
    pub timeout: Duration,
    ```

    <!-- doc -->
    /// Backoff base (R15).
    ```rust
    pub retry_base: Duration,
    ```

```rust
impl Default for ClientConfig
```

```rust
impl ClientConfig
```

    <!-- doc -->
    /// Read overrides from the process environment (R13, R14, R15).
    /// Unset or empty variables keep the defaults; unparsable ones are errors.
    ```rust
    pub fn from_env() -> Result<Self, ClientError>
    ```

<!-- doc -->
/// The API client. Holds the JWT once signed in; `Debug` redacts it (R6).
```rust
pub struct ApiClient
```

```rust
impl fmt::Debug for ApiClient
```

```rust
impl ApiClient
```

    <!-- doc -->
    /// Build a client. The timeout applies to every request the client makes (R14).
    ```rust
    pub fn new(config: ClientConfig) -> Result<Self, ClientError>
    ```

    <!-- doc -->
    /// The configured base URL.
    ```rust
    pub fn base_url(&self) -> &str
    ```

    <!-- doc -->
    /// Install a JWT obtained elsewhere (the cached one from `config.json`, R2).
    ```rust
    pub fn set_jwt(&mut self, jwt: Secret)
    ```

    <!-- doc -->
    /// True once a JWT is available.
    ```rust
    pub fn is_signed_in(&self) -> bool
    ```

    <!-- doc -->
    /// R18, R20: exchange credentials for a JWT and keep it in the client.
    ```rust
    pub async fn sign_in(&mut self, creds: &Credentials) -> Result<(), ClientError>
    ```

    <!-- doc -->
    /// R21: services in a project.
    ```rust
    pub async fn list_services(&self, project: &str) -> Result<Vec<Service>, ClientError>
    ```

    <!-- doc -->
    /// R26, R27: one service, or `None` when the API returns an empty
    /// `serviceInfos` for the id in that project.
    ```rust
    pub async fn get_service(
        &self,
        project: &str,
        vm_id: &str,
    ) -> Result<Option<Service>, ClientError>
    ```

    <!-- doc -->
    /// R29: firewall rules for a service. The caller decides what a disabled
    /// firewall means; this just returns what the API lists.
    ```rust
    pub async fn get_firewall_rules(&self, vm_id: &str) -> Result<Vec<FirewallRule>, ClientError>
    ```

    <!-- doc -->
    /// The single funnel every request goes through.
    /// 
    /// Order of checks: allowlist (R53, nothing is sent on failure), JWT
    /// presence and injection into the body (R6: never the URL), then up to
    /// [`MAX_ATTEMPTS`] attempts with exponential backoff (R15), each bounded
    /// by the client timeout (R14). A 2xx body is parsed as JSON and its
    /// `status` checked for `KO` (R16).
    /// 
    /// `body` must be a JSON object. Its `action` member, if any, is what the
    /// allowlist checks against.
    ```rust
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        mut body: Value,
    ) -> Result<Value, ClientError>
    ```

<!-- doc -->
/// R15: 408, 429, and every 5xx are retried. Nothing else is.
```rust
pub fn is_retryable_status(code: u16) -> bool { ... }
```


## `src/model.rs`

> Data shapes returned by the API, and the normalised shapes this tool
> exposes.
> 
> The raw API objects are deliberately private. Field names, the
> number-or-string `vmID`, and the `0`/`1` booleans are Elestio's concerns;
> everything above this module sees the field names from `spec/SPEC.md`
> section 1.1 and ordinary Rust types.
> 
> Rust note: serde's `#[derive(Deserialize)]` fails on a type mismatch
> (a number where a string was expected). The API sends `vmID` as either,
> so those fields use a small custom deserializer instead of a plain
> `String`. This is the Rust equivalent of the `FlexString` type in the Go
> client.

<!-- doc -->
/// A service as this tool presents it. Field names follow the spec's
/// mapping table (section 1.1), not the API's.
/// 
/// R25: serialising this yields exactly the nine keys the spec lists. The
/// extra fields are `skip`ped so the JSON contract stays fixed even if more
/// fields are added for human output later.
/// 
/// R28: `managedDBCLI` and `adminUser` are not fields here, so they cannot
/// be displayed by accident.
/// `#[derive(Debug, Clone, PartialEq, Eq, Serialize)]`
```rust
pub struct Service
```

    <!-- doc -->
    /// `vmID`, normalised to a string whether the API sent a number or a string.
    ```rust
    pub id: String,
    ```

    <!-- doc -->
    /// `displayName`.
    ```rust
    pub name: Option<String>,
    ```

    <!-- doc -->
    /// `templateName`.
    ```rust
    pub template: Option<String>,
    ```

    <!-- doc -->
    /// `selected_software_tag`.
    ```rust
    pub version: Option<String>,
    ```

    <!-- doc -->
    /// `provider`.
    ```rust
    pub provider: Option<String>,
    ```

    <!-- doc -->
    /// `datacenter`.
    ```rust
    pub datacenter: Option<String>,
    ```

    <!-- doc -->
    /// `serverType`.
    ```rust
    pub server_type: Option<String>,
    ```

    <!-- doc -->
    /// `status`, for example `running` or `off`.
    ```rust
    pub status: Option<String>,
    ```

    <!-- doc -->
    /// `deploymentStatus`, for example `Deployed` or `IN PROGRESS`.
    ```rust
    pub deployment_status: Option<String>,
    ```

    <!-- doc -->
    /// `isFirewallActivated` (R29). Not part of the JSON contract.
    /// `#[serde(skip)]`
    ```rust
    pub firewall_enabled: bool,
    ```

    <!-- doc -->
    /// `ipv4`. Not part of the JSON contract.
    /// `#[serde(skip)]`
    ```rust
    pub ipv4: Option<String>,
    ```

    <!-- doc -->
    /// `cname`. Not part of the JSON contract.
    /// `#[serde(skip)]`
    ```rust
    pub cname: Option<String>,
    ```

<!-- doc -->
/// A firewall rule as the API returns it.
/// `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]`
```rust
pub struct FirewallRule
```

    <!-- doc -->
    /// `INPUT` or `OUTPUT`. Named `rule_type` because `type` is a keyword.
    /// `#[serde(rename = "type")]`
    ```rust
    pub rule_type: String,
    ```

    <!-- doc -->
    /// A port (`"22"`) or a range (`"8000-9000"`).
    ```rust
    pub port: String,
    ```

    <!-- doc -->
    /// `tcp` or `udp`.
    ```rust
    pub protocol: String,
    ```

    <!-- doc -->
    /// CIDR blocks. The official CLI tolerates a bare string here, so we do too.
    /// `#[serde(deserialize_with = "string_or_vec")]`
    ```rust
    pub targets: Vec<String>,
    ```

<!-- doc -->
/// The two wildcard targets the platform uses for "everyone" (R31).
```rust
pub const OPEN_TARGETS: [&str; 2] = ["0.0.0.0/0", "::/0"];
```

```rust
impl FirewallRule
```

    <!-- doc -->
    /// R31: an `INPUT` rule with any wildcard target is open to the internet.
    /// `OUTPUT` rules are never flagged; egress is not exposure.
    ```rust
    pub fn open_to_internet(&self) -> bool
    ```

```rust
impl From<RawService> for Service
```


## `src/commands.rs`

> Command logic, independent of argument parsing and printing.
> 
> Each command is an `async fn` that takes a client and settings and returns
> plain data. `src/main.rs` turns arguments into these calls and
> `src/output.rs` turns the results into text. Keeping the three apart means
> QA can drive a command against a mock server without spawning the binary,
> and can snapshot the rendering without a server at all.

<!-- doc -->
/// Errors a command can produce beyond what the client reports.
/// `#[derive(Debug, thiserror::Error)]`
```rust
pub enum CommandError
```

    <!-- doc -->
    /// R22: no `--project`, no `defaultProject`.
    ```rust
        "no project selected: pass --project <id> or set a default with `elestio config --set-default-project <id>`"
    )]
    NoProject,
    ```

    <!-- doc -->
    /// R27: the API returned no service for this id in this project.
    ```rust
    NotFound
    ```

    <!-- doc -->
    /// Anything the client reported (network, auth, parse, allowlist).
    ```rust
    Client(#[from] ClientError),
    ```

<!-- doc -->
/// How the client came to hold a JWT.
/// `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`
```rust
pub enum SessionSource
```

    <!-- doc -->
    /// A fresh `checkAPIToken` call was made.
    ```rust
    SignedIn,
    ```

    <!-- doc -->
    /// The cached JWT from `config.json` was used (R2).
    ```rust
    Cached,
    ```

<!-- doc -->
/// Make sure `client` holds a JWT, preferring the cached one when it is
/// fresh at `now` (R2) and signing in otherwise. Nothing is written back to
/// disk either way (R54).
```rust
pub async fn ensure_session(
    client: &mut ApiClient,
    settings: &Settings,
    now: SystemTime,
) -> Result<SessionSource, ClientError> { ... }
```

<!-- doc -->
/// R9, R21, R22: the project to operate on. The flag wins; otherwise the
/// config default; otherwise an error that says how to set one.
```rust
pub fn resolve_project(flag: Option<&str>, settings: &Settings) -> Result<String, CommandError> { ... }
```

<!-- doc -->
/// Result of `auth test`.
/// `#[derive(Debug, Clone, PartialEq, Eq)]`
```rust
pub struct AuthReport
```

<!-- doc -->
/// R18: always sign in afresh, ignoring any cached JWT, and report the
/// identity that authenticated (R19). A rejection surfaces as
/// [`ClientError::AuthRejected`], distinct from the "no credentials" error
/// raised earlier by config loading (R20).
```rust
pub async fn auth_test(
    client: &mut ApiClient,
    settings: &Settings,
) -> Result<AuthReport, CommandError> { ... }
```

<!-- doc -->
/// R21: list services in `project`.
```rust
pub async fn list_services(
    client: &ApiClient,
    project: &str,
) -> Result<Vec<Service>, CommandError> { ... }
```

<!-- doc -->
/// R26, R27: one service, or a `NotFound` error that names the id and
/// project and is a different variant from any network failure.
```rust
pub async fn get_service(
    client: &ApiClient,
    project: &str,
    vm_id: &str,
) -> Result<Service, CommandError> { ... }
```

<!-- doc -->
/// Result of `firewall get`.
/// `#[derive(Debug, Clone, PartialEq, Eq)]`
```rust
pub struct FirewallReport
```

<!-- doc -->
/// R29: fetch the service first to learn whether the firewall is enabled,
/// then the rules. A disabled firewall short-circuits to an empty rule list
/// rather than asking the action endpoint for rules that do not apply.
```rust
pub async fn firewall_get(
    client: &ApiClient,
    project: &str,
    vm_id: &str,
) -> Result<FirewallReport, CommandError> { ... }
```

<!-- doc -->
/// Result of `drift`: the resolved declarations and everything the API
/// reported, ready for the pure engine and the renderer.
/// `#[derive(Debug, Clone, PartialEq, Eq)]`
```rust
pub struct DriftReport
```

```rust
impl DriftReport
```

    <!-- doc -->
    /// R51: whether the process should exit 2.
    ```rust
    pub fn drift_detected(&self) -> bool
    ```

<!-- doc -->
/// R37: fetch actual state for every declared service and diff it.
/// 
/// For each declared service, `getServerDetails` is called in its resolved
/// project. An empty result becomes `None`, which the engine reports as
/// `Missing` (R39). Firewall rules are fetched only when the declaration
/// has a `firewall` key (R33) and the service says its firewall is enabled;
/// a disabled firewall means an empty actual rule set (R29). Any fetch
/// error aborts the whole command (R37): a partial report that exits 1
/// would be ambiguous to a CI gate.
```rust
pub async fn drift(
    client: &ApiClient,
    declared: &[crate::diff::Declared],
) -> Result<DriftReport, CommandError> { ... }
```


## `src/output.rs`

> Rendering: data in, text or JSON out. No I/O; callers print.
> 
> R8: human output is aligned with spaces and never contains ANSI escape
> codes. There is no colour path to get wrong, so the "not a TTY" clause
> of R8 is satisfied by construction.

<!-- doc -->
/// Render rows as a padded table. Each column is as wide as its widest
/// cell; columns are separated by two spaces; a dashed rule follows the
/// header. This mirrors the official CLI's table layout.
```rust
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String { ... }
```

<!-- doc -->
/// R19: human output for `auth test`.
```rust
pub fn auth_human(report: &AuthReport) -> String { ... }
```

<!-- doc -->
/// R19: JSON output for `auth test`.
```rust
pub fn auth_json(report: &AuthReport) -> Value { ... }
```

<!-- doc -->
/// R23, R24: human output for `services`.
```rust
pub fn services_human(project: &str, services: &[Service]) -> String { ... }
```

<!-- doc -->
/// R25: JSON output for `services`: an array of normalised objects.
```rust
pub fn services_json(services: &[Service]) -> Value { ... }
```

<!-- doc -->
/// R26: human output for `service <vmID>`.
```rust
pub fn service_human(s: &Service) -> String { ... }
```

<!-- doc -->
/// R26: JSON output for `service <vmID>`: the same nine keys as R25.
```rust
pub fn service_json(s: &Service) -> Value { ... }
```

<!-- doc -->
/// Marker appended to open rules in human output (R31).
```rust
pub const OPEN_MARKER: &str = "OPEN TO INTERNET";
```

<!-- doc -->
/// R29, R30, R31: human output for `firewall get`.
```rust
pub fn firewall_human(report: &FirewallReport) -> String { ... }
```

<!-- doc -->
/// R31: JSON output for `firewall get`: each rule carries `open_to_internet`.
```rust
pub fn firewall_json(report: &FirewallReport) -> Value { ... }
```


## `src/diff.rs`

> The drift engine: pure functions from declared and actual state to a
> list of differences (R37 to R47).
> 
> There is no I/O in this module. No HTTP, no filesystem, no clock, no
> environment, no logging. Functions take values and return values. That
> is what makes it property-testable (feed it generated inputs and assert
> invariants) and mutation-testable (flip an operator and see whether a
> test notices) without a mock server in the way.
> 
> Rust note on ownership: every function here borrows its inputs (`&`) and
> returns freshly allocated output. Nothing is mutated in place. This keeps
> the call sites free to reuse the declared config after diffing, and it
> means a `Difference` owns its strings and can outlive both inputs, which
> the report renderer relies on.

<!-- doc -->
/// How declared firewall rules compare with actual ones (R32, R41).
/// `#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]`
/// `#[serde(rename_all = "lowercase")]`
```rust
pub enum FirewallMode
```

    <!-- doc -->
    /// Every declared rule must exist; extra actual rules are ignored.
    ```rust
    Subset,
    ```

    <!-- doc -->
    /// The declared set must equal the actual set.
    ```rust
    Exact,
    ```

<!-- doc -->
/// A firewall rule in canonical form (R40).
/// 
/// `rule_type` is upper-cased and `protocol` lower-cased on construction so
/// that `input`/`INPUT` and `TCP`/`tcp` compare equal. `targets` is a
/// `BTreeSet`, so order and duplicates do not matter and iteration is
/// sorted. `port` and each target are compared exactly.
/// 
/// The derived `Ord` compares fields in declaration order: type, port,
/// protocol, targets. That is exactly the sort order R42 asks for, so the
/// engine never writes a comparator by hand.
/// `#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]`
```rust
pub struct Rule
```

    <!-- doc -->
    /// `INPUT` or `OUTPUT`, upper-cased.
    ```rust
    pub rule_type: String,
    ```

    <!-- doc -->
    /// Port or range, exact.
    ```rust
    pub port: String,
    ```

    <!-- doc -->
    /// `tcp` or `udp`, lower-cased.
    ```rust
    pub protocol: String,
    ```

    <!-- doc -->
    /// CIDR targets as a set.
    ```rust
    pub targets: BTreeSet<String>,
    ```

```rust
impl Rule
```

    <!-- doc -->
    /// Build a canonical rule from raw parts.
    ```rust
    pub fn new(
        rule_type: &str,
        port: &str,
        protocol: &str,
        targets: impl IntoIterator<Item = String>,
    ) -> Rule
    ```

    <!-- doc -->
    /// R48: `INPUT 22/tcp [0.0.0.0/0, ::/0]`.
    ```rust
    pub fn render(&self) -> String
    ```

```rust
impl From<&FirewallRule> for Rule
```

<!-- doc -->
/// What the user asserted about one service (R32, R33). `None` means "not
/// declared, do not check".
/// `#[derive(Debug, Clone, PartialEq, Eq, Default)]`
```rust
pub struct Declared
```

    <!-- doc -->
    /// The service's `vmID`.
    ```rust
    pub id: String,
    ```

    <!-- doc -->
    /// The project the service is expected in, already resolved.
    ```rust
    pub project: String,
    ```

    <!-- doc -->
    /// Declared `displayName`.
    ```rust
    pub name: Option<String>,
    ```

    <!-- doc -->
    /// Declared `serverType`.
    ```rust
    pub server_type: Option<String>,
    ```

    <!-- doc -->
    /// Declared `provider`.
    ```rust
    pub provider: Option<String>,
    ```

    <!-- doc -->
    /// Declared `datacenter`.
    ```rust
    pub datacenter: Option<String>,
    ```

    <!-- doc -->
    /// Declared `selected_software_tag`.
    ```rust
    pub version: Option<String>,
    ```

    <!-- doc -->
    /// How to compare `firewall`.
    ```rust
    pub firewall_mode: FirewallMode,
    ```

    <!-- doc -->
    /// Declared rules. `None` skips the check; `Some(vec![])` asserts there
    /// are none (R33).
    ```rust
    pub firewall: Option<Vec<Rule>>,
    ```

<!-- doc -->
/// What the API reported for one service, reduced to the comparable fields.
/// `#[derive(Debug, Clone, PartialEq, Eq, Default)]`
```rust
pub struct Actual
```

    <!-- doc -->
    /// `displayName`.
    ```rust
    pub name: Option<String>,
    ```

    <!-- doc -->
    /// `serverType`.
    ```rust
    pub server_type: Option<String>,
    ```

    <!-- doc -->
    /// `provider`.
    ```rust
    pub provider: Option<String>,
    ```

    <!-- doc -->
    /// `datacenter`.
    ```rust
    pub datacenter: Option<String>,
    ```

    <!-- doc -->
    /// `selected_software_tag`.
    ```rust
    pub version: Option<String>,
    ```

    <!-- doc -->
    /// Firewall rules. Empty when the firewall is disabled (R29).
    ```rust
    pub firewall: Vec<Rule>,
    ```

<!-- doc -->
/// R43: the declaration that asserts every field of `actual`, in exact mode.
```rust
pub fn declare_all(id: &str, project: &str, actual: &Actual) -> Declared { ... }
```

<!-- doc -->
/// Scalar field names in report order (R42).
```rust
pub const SCALAR_FIELDS: [&str; 5] = ["name", "server_type", "provider", "datacenter", "version"];
```

<!-- doc -->
/// The field name used for every firewall difference (R45).
```rust
pub const FIREWALL_FIELD: &str = "firewall";
```

<!-- doc -->
/// One reported difference (R38, R39, R41).
/// `#[derive(Debug, Clone, PartialEq, Eq)]`
```rust
pub enum Difference
```

```rust
impl Difference
```

    <!-- doc -->
    /// The service this difference belongs to.
    ```rust
    pub fn service_id(&self) -> &str
    ```

    <!-- doc -->
    /// The field path: a scalar name, `firewall`, or `missing`.
    ```rust
    pub fn field(&self) -> &'static str
    ```

<!-- doc -->
/// Diff one service. `actual` is `None` when the API returned nothing for
/// it (R39). Output order follows R42.
```rust
pub fn diff_service(declared: &Declared, actual: Option<&Actual>) -> Vec<Difference> { ... }
```

<!-- doc -->
/// Diff every declared service against `actual`, keyed by service id.
/// Services are reported in declared order (R42). An id absent from the
/// map is `Missing` (R39).
```rust
pub fn diff(declared: &[Declared], actual: &BTreeMap<String, Actual>) -> Vec<Difference> { ... }
```


## `src/drift_config.rs`

> Declared state: the drift TOML file (R32 to R36).
> 
> Parsing happens in two stages on purpose. Stage one is serde: the TOML
> text becomes raw structs where `id` is optional. Stage two is
> validation: missing ids (R35) and duplicate ids (R36) are checked in
> plain Rust. If `id` were a required field in the serde struct, a missing
> one would surface as a TOML parse error with a line number, and the spec
> asks for a validation error naming the entry's index instead.

<!-- doc -->
/// Errors from reading or validating a drift config.
/// `#[derive(Debug, thiserror::Error)]`
```rust
pub enum DriftConfigError
```

    <!-- doc -->
    /// The file could not be read.
    ```rust
    Io
    ```

    <!-- doc -->
    /// R34: not valid TOML, or valid TOML of the wrong shape.
    ```rust
    Toml
    ```

    <!-- doc -->
    /// R35: a `[[service]]` entry without an `id`.
    ```rust
    MissingId
    ```

    <!-- doc -->
    /// R36: the same id declared twice.
    ```rust
    DuplicateId
    ```

    <!-- doc -->
    /// R22, R32: a service with no project from any source.
    ```rust
        "service {id}: no project declared; set `project` in the config, pass --project, or set a default with `elestio config --set-default-project <id>`"
    ```

    ```rust
    )]
    NoProject
    ```

```rust
impl StringOrInt
```

<!-- doc -->
/// One `[[service]]` entry after validation, before project resolution.
/// `#[derive(Debug, Clone, PartialEq, Eq)]`
```rust
pub struct DeclaredEntry
```

    <!-- doc -->
    /// The service's `vmID`.
    ```rust
    pub id: String,
    ```

    <!-- doc -->
    /// Per-service project override, if any.
    ```rust
    pub project: Option<String>,
    ```

    <!-- doc -->
    /// Declared `displayName`.
    ```rust
    pub name: Option<String>,
    ```

    <!-- doc -->
    /// Declared `serverType`.
    ```rust
    pub server_type: Option<String>,
    ```

    <!-- doc -->
    /// Declared `provider`.
    ```rust
    pub provider: Option<String>,
    ```

    <!-- doc -->
    /// Declared `datacenter`.
    ```rust
    pub datacenter: Option<String>,
    ```

    <!-- doc -->
    /// Declared `selected_software_tag`.
    ```rust
    pub version: Option<String>,
    ```

    <!-- doc -->
    /// Firewall comparison mode; defaults to subset.
    ```rust
    pub firewall_mode: FirewallMode,
    ```

    <!-- doc -->
    /// Declared rules, canonicalised. `None` when the key is absent (R33).
    ```rust
    pub firewall: Option<Vec<Rule>>,
    ```

<!-- doc -->
/// A parsed and validated drift config.
/// `#[derive(Debug, Clone, PartialEq, Eq)]`
```rust
pub struct DriftConfig
```

    <!-- doc -->
    /// Top-level `project`, if any.
    ```rust
    pub project: Option<String>,
    ```

    <!-- doc -->
    /// Services in file order.
    ```rust
    pub services: Vec<DeclaredEntry>,
    ```

```rust
impl DriftConfig
```

    <!-- doc -->
    /// Resolve each service's project: per-service, then top-level, then the
    /// fallback (from `--project` or `defaultProject`). Fails naming the
    /// first service that has none.
    ```rust
    pub fn resolve(&self, fallback: Option<&str>) -> Result<Vec<Declared>, DriftConfigError>
    ```

<!-- doc -->
/// Read and parse a drift config file (R32, R34).
```rust
pub fn load(path: &Path) -> Result<DriftConfig, DriftConfigError> { ... }
```

<!-- doc -->
/// Parse drift config text (R32 to R36).
```rust
pub fn parse(text: &str) -> Result<DriftConfig, DriftConfigError> { ... }
```


## `src/report.rs`

> Rendering of drift differences (R48, R49, R50). Pure: strings and JSON
> values in, no printing.

<!-- doc -->
/// R50: the exact line printed when there is nothing to report.
```rust
pub const NO_DRIFT: &str = "No drift detected.";
```

<!-- doc -->
/// Human form of one difference, without a trailing newline (R48).
```rust
pub fn render_line(d: &Difference) -> String { ... }
```

<!-- doc -->
/// R48, R50: the whole human report. One line per difference in the order
/// given (which is R42 order when it came from `diff::diff`), or the
/// no-drift line.
```rust
pub fn render_human(differences: &[Difference]) -> String { ... }
```

<!-- doc -->
/// R49: `{ "drift_detected": bool, "differences": [...] }`. Every element
/// carries `kind`, `service_id`, `field`, `declared` and `actual`, with
/// `declared` and `actual` `null` where they do not apply. The `missing`
/// kind additionally carries `project`, so a consumer can see where the
/// service was looked for.
```rust
pub fn render_json(differences: &[Difference]) -> Value { ... }
```

