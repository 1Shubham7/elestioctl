# elestioctl - Specification

A read-only Rust CLI for the Elestio platform, plus a drift-detection command
the official CLI does not have.

**Status:** v0.2 spec. v0.1 was reviewed against the reference repositories
before any code was written; the findings are in `docs/SPEC-REVIEW.md` and
every change from v0.1 is listed in section 12. Requirement numbers are
stable: a number means the same thing in v0.1 and v0.2, only the wording was
tightened. Tests reference requirement IDs.

---

## 0. Context and rationale

Elestio ships an official CLI (`elestio`, npm, MIT, Node >= 18, zero npm
dependencies). It is comprehensive: deploy, services, templates, firewall,
SSL, backups, snapshots, CI/CD, billing.

This project is **not** a replacement. It is:

1. **A narrow read-only subset in Rust**, to compare a single static binary
   with no runtime against a global npm install requiring Node 18+.
2. **A drift-detection command they do not have**: declare desired service
   state in TOML, fetch actual state from the API, report differences.
   Read-only; it never applies anything.

The drift command is the reason this project exists. Elestio's platform has
a feature called Cluster Resynchronization that detects and resolves node
config, replication, and service state inconsistencies. This is the same
idea applied to service-level configuration: detect divergence between
declared intent and actual state.

**Non-goals for v0.1:** no mutations of any kind. No deploy, delete, resize,
reboot, firewall write, or backup operations. Read-only is a safety
property, not a limitation.

---

## 1. Scope: commands in v0.1

| Command | Purpose | Takes `--project` |
| --- | --- | --- |
| `elestioctl auth test` | Verify stored credentials against the API | no |
| `elestioctl services` | List services in a project | yes |
| `elestioctl service <vmID>` | Show details for one service | yes |
| `elestioctl firewall get <vmID>` | Show firewall rules for one service | yes |
| `elestioctl drift --config <path>` | Compare declared TOML state to actual | yes (fallback only, see R32) |

### 1.1 API facts this spec relies on

Taken from `elestio-go-api-client` and `elestio-cli`. Nothing else may be
assumed about the API.

| Operation | Method and path | Request body (besides `jwt`) | Response |
| --- | --- | --- | --- |
| Sign in | `POST /api/auth/checkAPIToken` | `{ "email", "token" }` | `{ "status": "OK", "jwt": "..." }` or `status != "OK"` with `message` |
| List services | `POST /api/servers/getServices` | `{ "appid": "Cloudxx", "projectId": "<id>", "isActiveService": "true" }` | `{ "servers": [ Service ] }` |
| Service details | `POST /api/servers/getServerDetails` | `{ "vmID": "<id>", "projectID": "<id>" }` | `{ "serviceInfos": [ Service ] }`, empty array when not found |
| Firewall rules | `POST /api/servers/DoActionOnServer` | `{ "vmID": "<id>", "action": "getFirewallRules" }` | `{ "rules": [ Rule ] }` or `{ "data": { "rules": [ Rule ] } }` |

Every response may instead be `{ "status": "KO", "message": "..." }` with
HTTP 200. The JWT is sent as a `jwt` member of the JSON body on every call.

Service field mapping (declared name on the left, API JSON name on the right):

| Declared / displayed | API field | Notes |
| --- | --- | --- |
| `id` | `vmID` | Arrives as a JSON number or string. Normalised to a string. |
| `name` | `displayName` | |
| `template` | `templateName` | |
| `version` | `selected_software_tag` | |
| `provider` | `provider` | Exact string as returned by the API. |
| `datacenter` | `datacenter` | |
| `server_type` | `serverType` | |
| `status` | `status` | Values seen: `running`, `off`, `deleting`, `migrating`. |
| `deployment_status` | `deploymentStatus` | Values seen: `Deployed`, `IN PROGRESS`. |
| firewall enabled | `isFirewallActivated` | JSON number `0` or `1`. |

Firewall rule: `{ "type": "INPUT" | "OUTPUT", "port": "<n>" | "<a>-<b>",
"protocol": "tcp" | "udp", "targets": [ "<cidr>" ] }`.

---

## 2. Configuration and credentials

**R1** The tool MUST read credentials from `~/.elestio/credentials`, the
same file the official CLI writes. It is JSON: `{ "email": "...",
"apiToken": "..." }`. The tool MUST NOT require its own login flow in v0.1.

**R2** The tool MUST read `~/.elestio/config.json` when present, using these
fields and ignoring all others: `defaultProject` (string), `jwt` (string),
`jwtExpiry` (epoch milliseconds). A missing file is not an error. A cached
`jwt` MAY be used instead of signing in when `jwtExpiry` is more than five
minutes in the future; otherwise the tool signs in and does not persist the
result (see R54).

**R3** Credentials MAY be overridden by environment variables
`ELESTIO_EMAIL` and `ELESTIO_API_TOKEN` (the names the Terraform provider
uses). Environment takes precedence over file. When either variable is set,
any cached `jwt` in `config.json` MUST be ignored, because it may belong to
a different account.

**R4** On Unix, if the credentials file exists and has any group or other
permission bit set (mode `& 0o077 != 0`), the tool MUST emit a warning to
stderr and continue. On non-Unix platforms the check is skipped.

**R5** If no credentials are found by any means, the tool MUST exit with
code 1 and a message naming both the file path and both environment
variable names it looked for.

**R6** The tool MUST NOT print the API token or the JWT in any output,
including `--debug` output and error messages. Any struct holding either
MUST have a `Debug` implementation that redacts it. The JWT MUST be sent in
the JSON request body, never in the URL, so that request logging cannot
leak it.

---

## 3. Global behaviour

**R7** `--json` MUST cause all successful command output to be a single
valid JSON document on stdout, with no human-readable decoration. Errors are
always plain text on stderr; on error, stdout MUST be empty.

**R8** Without `--json`, output MUST be human-readable with columns aligned
by padding. The tool MUST NOT emit ANSI escape codes at all in v0.1.

**R9** `--project <id>` MUST override `defaultProject` from `config.json`
for `services`, `service`, `firewall get`, and `drift`.

**R10** `--debug` MUST cause full error chains to be printed to stderr, one
cause per line. Without it, errors MUST be a single line naming what failed
and why.

**R11** Exit codes MUST be:
  - `0`: success, and for `drift` specifically, no drift detected
  - `1`: error (network, auth, parse, invalid input, invalid arguments)
  - `2`: `drift` only: the command succeeded and drift WAS detected

  Argument parsing errors MUST exit 1, overriding clap's default of 2. This
  mirrors `terraform plan -detailed-exitcode` and makes the tool usable as a
  CI gate.

**R12** All errors written to stderr MUST name the operation that failed.
"Request failed" is not acceptable; "failed to fetch service 41928" is.

---

## 4. API client

**R13** The API base URL MUST be configurable via `ELESTIO_API_URL`,
defaulting to `https://api.elest.io`. This exists so tests can point at a
mock server.

**R14** Every HTTP request MUST have a per-attempt timeout. Default 30
seconds, overridable via `ELESTIO_TIMEOUT_SECS`.

**R15** A request MUST be retried when the response is HTTP 429, HTTP 408,
HTTP 5xx, or a transport error (connection refused, timeout). At most 3
requests are made in total. The delay before retry `n` (1-based) is
`base * 2^(n-1)` with a default base of 500 ms; the base MUST be overridable
so tests do not sleep. Other 4xx responses and 2xx responses carrying
`"status": "KO"` MUST NOT be retried. Retrying is safe because every request
in scope is an idempotent read, even though the method is POST.

**R16** A failed response that is not retried MUST produce an error naming
the endpoint path and either the HTTP status or, for a 2xx `KO` envelope,
the API's `message`.

**R17** Malformed or unexpected JSON in a response MUST produce a parse
error naming the JSON path of the field that failed, not a panic.

---

## 5. `auth test`

**R18** MUST call `checkAPIToken` with the resolved credentials, ignoring
any cached JWT, and report success or failure.

**R19** On success without `--json`, MUST print the email that
authenticated. On success with `--json`, MUST emit an object with at least
`{ "authenticated": true, "email": "..." }`.

**R20** On authentication failure MUST exit 1 and distinguish "no
credentials found" (R5) from "credentials rejected by the API" (`status`
not `OK` or no `jwt` in the response).

---

## 6. `services`

**R21** MUST list services for the resolved project (`--project`, else
`defaultProject`).

**R22** If no project can be resolved, MUST exit 1 with a message that
names `--project` and the official CLI command
`elestio config --set-default-project <id>`.

**R23** Human output MUST include, per service, in this column order: id,
name, template, version, provider, datacenter, server type, status.

**R24** An empty list MUST be reported explicitly, not as blank output.

**R25** `--json` output MUST be an array of normalised service objects with
exactly the keys `id`, `name`, `template`, `version`, `provider`,
`datacenter`, `server_type`, `status`, `deployment_status`; empty array
when there are none.

---

## 7. `service <vmID>`

**R26** MUST fetch and display details for a single service by ID in the
resolved project (R9, R22).

**R27** A vmID that the API does not return (empty `serviceInfos`) MUST
produce a "not found" error naming the vmID and the project, and exit 1,
distinguishable from a network failure.

**R28** The tool MUST NOT call `getAppCredentials`, `getServiceEnv`, or any
other endpoint that returns credentials (enforced by R53). In addition, the
raw fields `managedDBCLI` and `adminUser` MUST be omitted from both human
and `--json` output. There is no `--show-secrets` flag in v0.1.

---

## 8. `firewall get <vmID>`

**R29** MUST fetch and display firewall rules for a service. When the
service reports `isFirewallActivated` as `0`, the tool MUST say the
firewall is disabled rather than listing zero rules. Fetching details first
to learn this is part of the command.

**R30** Human output MUST show, per rule: type, port, protocol, and
targets joined by `, `.

**R31** A rule is open to the internet when its type is `INPUT` and any
target equals `0.0.0.0/0` or `::/0`. Such rules MUST be visually marked in
human output. In `--json` output each rule MUST carry a boolean
`open_to_internet`.

---

## 9. `drift --config <path>`: the core feature

### 9.1 Declared state format

**R32** The config file MUST be TOML. Its shape:

```toml
# Optional. Falls back to --project, then defaultProject.
project = "112"

[[service]]
id            = "41928"        # required; string or integer
project       = "112"          # optional per-service override
name          = "prod-postgres"
server_type   = "MEDIUM-2C-4G"
provider      = "hetzner"
datacenter    = "hel1"
version       = "16"
firewall_mode = "subset"       # "subset" (default) or "exact"

  [[service.firewall]]
  type     = "INPUT"
  port     = "22"
  protocol = "tcp"
  targets  = ["0.0.0.0/0", "::/0"]
```

`firewall_mode = "subset"` means every declared rule must exist and extra
actual rules are ignored. `"exact"` means the declared set must equal the
actual set. Subset is the default because the platform injects system and
tool rules the user never declared (see `docs/SPEC-REVIEW.md` finding 6).

**R33** Every field except `id` MUST be optional. An absent field means
"not declared, do not check". An absent `firewall` key means firewall rules
are not checked; an explicit `firewall = []` declares that there are no
rules. This is the central design decision: the tool checks only what you
assert, never everything it can see.

**R34** A malformed TOML file MUST produce a parse error naming the line,
and exit 1.

**R35** A `[[service]]` entry without an `id` MUST be a validation error
naming the zero-based index of the offending entry. This is a validation
error after parsing, not a TOML parse error.

**R36** Duplicate service IDs in one config MUST be a validation error
naming the ID.

### 9.2 Diff semantics

**R37** For each declared service, the tool MUST fetch actual state and
compare only the declared fields. If any fetch fails with an error (as
opposed to not-found), the command MUST exit 1 with no drift output.

**R38** A field difference MUST be reported as a `Difference` carrying:
service id, field path, declared value, actual value.

**R39** A declared service that the API does not return in its resolved
project MUST be reported as a `Missing` difference, not an error. A service
that exists in a different project is `Missing`; there is no cross-project
search.

**R40** Firewall rules MUST be compared as a **set**, not a list. Rule
ordering MUST NOT produce a difference. Two rules are equal when type,
port, protocol, and the *set* of targets are all equal. `type` and
`protocol` compare case-insensitively; `port` and each target compare
exactly. Duplicate rules in either list collapse to one.

**R41** A declared rule not present in actual MUST be reported as `Absent`.
In `exact` mode, an actual rule not declared MUST be reported as
`Unexpected`. In `subset` mode `Unexpected` is never reported.

**R42** The diff MUST be deterministic and ordered: services in declared
order; within a service, field differences in the order `name`,
`server_type`, `provider`, `datacenter`, `version`; then firewall
differences with all `Absent` before all `Unexpected`, each group sorted by
(type, port, protocol, targets).

### 9.3 Diff invariants (property-tested)

These are asserted with `proptest` over generated inputs, not just examples.
`declare_all(A)` denotes the declared state that asserts every field of an
actual state `A`, with `firewall_mode = "exact"`.

**R43** *Reflexivity*: for any actual state `A`, `diff(declare_all(A), A)`
yields no differences.

**R44** *Emptiness*: a declared config with no services, or whose services
declare only `id` for services that exist, yields no differences regardless
of actual state.

**R45** *Detection*: if any declared scalar field is changed to a different
value, the diff MUST contain a difference naming that field. If any
declared firewall rule is changed, the diff MUST contain a difference on the
`firewall` field.

**R46** *Set semantics*: for any firewall rule list, diffing it against any
permutation of itself, including permutations of each rule's targets,
yields no differences.

**R47** *Determinism*: diffing the same inputs twice yields equal
difference lists and byte-identical rendered output.

### 9.4 Output

**R48** Without `--json`, drift MUST be reported one difference per line,
grouped by service in R42 order, in these forms:

```text
<id> <field>: declared=<x> actual=<y>
<id> missing: service not found in project <project>
<id> firewall absent: <TYPE> <port>/<protocol> [<targets joined by ", ">]
<id> firewall unexpected: <TYPE> <port>/<protocol> [<targets joined by ", ">]
```

**R49** With `--json`, output MUST be an object `{ "drift_detected": bool,
"differences": [...] }`. Each element has `kind` (`"mismatch"`,
`"missing"`, `"absent"`, `"unexpected"`), `service_id`, `field`, and
`declared` and `actual`, which are `null` where they do not apply.

**R50** When no drift is found the tool MUST print `No drift detected.`
(or emit `drift_detected: false`) and exit 0. A config with zero services
is not an error: it prints the same and warns on stderr.

**R51** When drift is found the tool MUST exit 2 (see R11).

---

## 10. Safety properties

**R52** The crate MUST declare `#![forbid(unsafe_code)]` at the root.

**R53** The client layer MUST hold a closed allowlist of permitted calls,
each a (method, path, `action`) triple, and MUST refuse to send anything
else:

```text
POST /api/auth/checkAPIToken        no action
POST /api/servers/getServices       no action
POST /api/servers/getServerDetails  no action
POST /api/servers/DoActionOnServer  action = "getFirewallRules"
```

A call to any other path, or to `DoActionOnServer` with any other action,
MUST return an error before any request is sent. This MUST be enforced in
the client layer, not merely by convention, and MUST be covered by a test
that confirms the mock server received zero requests.

**R54** The tool MUST NOT write to any path outside its own config
directory. v0.1 writes nothing at all, including the JWT it obtains.

---

## 11. Quality gates

**R55** `cargo fmt --check` MUST pass.

**R56** `cargo clippy --all-targets -- -D warnings` MUST pass with zero
warnings.

**R57** `cargo audit` MUST report no known vulnerabilities.

**R58** `cargo deny check` MUST pass for licences and advisories.

**R59** Every requirement R1 to R54 MUST be referenced by at least one test,
by ID, in a comment or test name. A requirement with no test is a gap and
MUST be listed as such in `docs/TRACEABILITY.md`. R52 is tested by reading
the crate root source; R54 is tested by running the binary with `HOME` set
to an empty directory and asserting nothing was created.

**R60** `cargo mutants` MUST be run against the diff engine module. The
surviving-mutant count MUST be recorded before and after test improvement in
`docs/NOTES.md`.

---

## 12. Changes from v0.1

Numbers refer to findings in `docs/SPEC-REVIEW.md`.

- R53 rewritten from "GET only" to a call allowlist (finding 1).
- R2 now names `jwt` and `jwtExpiry`; cached JWT used when fresh (2).
- R6 extended to the JWT; JWT goes in the body, never the URL (2).
- R9, R26 name which commands take `--project`; R32 gains `project` (3).
- R11 states that argument errors exit 1 (4).
- R16, R27, R39, R15 defined in terms of the `KO` envelope (5).
- R32, R41 gain `firewall_mode`, default `subset` (6).
- R28 drops `--show-secrets`; secrets are blocked at the endpoint (7).
- Section 1.1 pins the field mapping (8).
- R15 fixes attempts, backoff, and transport retries; R14 per attempt (9).
- R40 defines case handling and duplicates (10).
- R31 defines mixed targets and INPUT-only (11).
- R48, R49 define all four kinds (12).
- R42 defines the order (13).
- R43, R45 restated over `declare_all` (14).
- R33 distinguishes absent from empty (15).
- R35 made a post-parse validation (16).
- R37 aborts on fetch error (17).
- R29 handles a disabled firewall (18).
- R19 identity is the email (19).
- R17 allows a path-tracking deserialiser (20).
- R3 uses `ELESTIO_API_TOKEN` (21). R4 Unix-only (22). R8 no ANSI (23).
- R7 error shape (24). R2 drops unused defaults (25). R22 wording (26).
- R50 zero services (27). R59 notes R52 and R54 (28). R56 `--all-targets` (29).
- Spec moved to `spec/SPEC.md` (30).
