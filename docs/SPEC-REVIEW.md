# Spec review: elestioctl v0.1

Phase 0 output. This document lists problems found in `Spec.md` before any
code was written. Every finding was checked against the four reference repos
cloned at `../`. Where a finding rests on reference code, the file is named so
it can be re-checked.

Severity scale:

- **Blocking**: the requirement cannot be implemented or tested as written.
- **Decision**: the requirement is implementable in more than one materially
  different way and the spec must pick one.
- **Ambiguity**: a careful reader could reasonably build two different things.
- **Minor**: wording, naming, or housekeeping.

Summary:

| # | Req | Severity | One line |
| --- | --- | --- | --- |
| 1 | R53 | Blocking | The Elestio API has no GET endpoints for anything in scope. Every read is a POST. |
| 2 | R1, R54, R6 | Blocking | Every call needs a JWT obtained by POST; the official CLI caches it to disk, which R54 forbids. |
| 3 | R26, R32, R37, R9 | Blocking | Fetching a service requires a project ID, and neither `service <vmID>` nor the drift TOML has one. |
| 4 | R11 | Blocking | clap exits 2 on usage errors, colliding with the drift-detected exit code. |
| 5 | R16, R27, R39, R15 | Decision | "Not found" and most API errors arrive as HTTP 200 with an envelope, not as HTTP status codes. |
| 6 | R41 | Decision | The platform injects firewall rules the user never declared, so strict `Unexpected` fires on every real service. |
| 7 | R28, R25 | Decision | What counts as a secret, and whether R28 applies to `--json`. |
| 8 | R23, R32 | Decision | The TOML field names need a pinned mapping to API JSON field names. |
| 9 | R15, R14 | Ambiguity | "3 attempts", backoff constants, what else is retried, per-attempt vs total timeout. |
| 10 | R40, R46 | Ambiguity | Case normalisation of `type` and `protocol`, duplicates under set semantics, port ranges. |
| 11 | R31 | Ambiguity | Mixed targets, OUTPUT rules, and the exact wildcard strings. |
| 12 | R48, R49, R38 | Ambiguity | Human and JSON formats are only defined for one of the four difference kinds. |
| 13 | R42, R47 | Ambiguity | "Stable order" is not defined. |
| 14 | R43, R45 | Ambiguity | Declared and actual are different types, so "diff a state against itself" needs a conversion. |
| 15 | R33 | Ambiguity | Absent `firewall` versus empty `firewall = []`. |
| 16 | R35, R34 | Ambiguity | A missing `id` is a parse error under serde unless the field is optional at parse time. |
| 17 | R37 | Ambiguity | Partial failure across several declared services. |
| 18 | R29 | Ambiguity | What `firewall get` shows when the firewall is disabled or the service is not yet deployed. |
| 19 | R19, R18 | Ambiguity | What "authenticated identity" is when the auth response only carries a JWT. |
| 20 | R17 | Ambiguity | "Naming the field" needs a path-tracking deserialiser. |
| 21 | R3 | Minor | Env var name diverges from the Terraform provider's `ELESTIO_API_TOKEN`. |
| 22 | R4 | Minor | Permission check is Unix-only and "more permissive than 0600" needs a definition. |
| 23 | R8 | Minor | "Aligned" is untestable as written; colour may not be wanted at all. |
| 24 | R7, R10 | Minor | Error output shape under `--json` is unspecified. |
| 25 | R2 | Minor | Provider and datacenter defaults are read but no v0.1 command uses them. |
| 26 | R22 | Minor | "How to set one" must point at the official CLI since we cannot write config. |
| 27 | R44 | Minor | A config with zero services: success or validation error. |
| 28 | R59, R52, R54 | Minor | R52 and R54 need unusual tests; say what counts. |
| 29 | R56 | Minor | Spec says `cargo clippy`, Makefile says `--all-targets`. |
| 30 | Spec | Minor | Spec lives at `Spec.md`; the workflow and hooks reference `spec/SPEC.md`. |

---

## Blocking

### 1. R53: GET-only is unimplementable against this API

R53 says the tool MUST NOT issue any HTTP method other than GET, enforced in
code and tested. The reference clients show that every endpoint in scope is a
POST:

| Operation | Method | Path | Evidence |
| --- | --- | --- | --- |
| Sign in (get JWT) | POST | `/api/auth/checkAPIToken` | `elestio-go-api-client/auth.go`, `elestio-cli/src/api.js` |
| List projects | POST | `/api/projects/getList` | `elestio-go-api-client/project.go` |
| List services | POST | `/api/servers/getServices` | `service.go` `GetList`, `elestio-cli/src/commands/services.js` |
| Service details | POST | `/api/servers/getServerDetails` | `service.go` `Get` |
| Firewall rules | POST | `/api/servers/DoActionOnServer` with `action: "getFirewallRules"` | `service.go` `GetServiceFirewallRules`, `elestio-cli/src/commands/actions.js` |

The only GET in the Go client is `getTemplates`, which is out of scope. The
Node CLI's `apiRequest` defaults to POST and puts the JWT in the JSON body.

Note also that the firewall read shares its endpoint with every mutation
(reboot, delete, resize, enableFirewall) and is distinguished only by the
`action` string in the body. "Read-only" therefore cannot be a property of the
HTTP method at all.

**Proposed rewrite of R53.** Read-only is an allowlist property. The client
layer MUST hold a closed list of permitted calls, each a `(method, path,
action)` triple:

```text
POST /api/auth/checkAPIToken        (no action)
POST /api/projects/getList          (no action)
POST /api/servers/getServices       (no action)
POST /api/servers/getServerDetails  (no action)
POST /api/servers/DoActionOnServer  action = "getFirewallRules"
```

Any request not on the list MUST be rejected before it is sent. The test: a
call to any other path, or to `DoActionOnServer` with any other action, MUST
return an error and the mock server MUST record zero requests. This is
stronger than the original R53, because it also blocks read endpoints that
return secrets (see finding 7).

### 2. R1, R54, R6: the JWT round trip and where it lives

The credentials file holds `{ "email", "apiToken" }` only
(`elestio-cli/src/config.js`). The API token is not usable directly. Both
reference clients first POST it to `checkAPIToken` and receive a JWT, then send
the JWT on every call. The official CLI caches the JWT and a 23 hour expiry in
`config.json` (`jwt`, `jwtExpiry`), refreshing with a 5 minute buffer.

R54 says v0.1 writes nothing. So the spec silently implies one of:

- (a) Sign in on every invocation. One extra round trip per command. Simple,
  and harmless for a read-only tool.
- (b) Read the cached `jwt` and `jwtExpiry` from `config.json` when present and
  unexpired, else sign in and do not persist. R2 only mentions defaults, not
  the JWT, so this is currently out of spec.

**Recommendation.** (b) with (a) as fallback, because it plays well with the
official CLI already on the machine and makes `auth test` meaningful as a
freshness check. R2 should list `jwt` and `jwtExpiry` as fields the tool reads,
and R18 should say `auth test` always calls `checkAPIToken` regardless of any
cached JWT.

Two consequences for R6 either way:

- The JWT is a bearer credential and MUST be covered by the same redaction as
  the API token. R6 only says "API token".
- The Go client appends `?jwt=...` to every URL as a "temporary fix waiting api
  handle jwt in authorization header" (`api.go`). The Node CLI sends it in the
  JSON body. If we put it in the URL, any `--debug` request logging leaks it.
  R6 should state: the JWT MUST NOT be placed in the URL; send it in the JSON
  body as the Node CLI does. Whether the `Authorization: Bearer` header alone
  works is not confirmed by either client, so the body is the only path with
  evidence.

### 3. R26, R32, R37, R9: every service read needs a project ID

`getServerDetails` requires both `vmID` and `projectID` (`service.go` `Get`,
`services.js` `getServiceDetails`). `getFirewallRules` needs only `vmID`, but
drift needs details first for the field comparison. Yet:

- R26 says `service <vmID>` fetches "by ID".
- R32's TOML has no project field anywhere.
- R9 says `--project` applies to "commands that take a project" without saying
  which commands those are.

The official CLI resolves the default project for `service <vmID>`, and for
`move-service` falls back to iterating every project and listing every service
(`findServiceAcrossProjects`), which is N+1 requests.

**Recommendation.**

- `service` and `firewall get` accept `--project`, falling back to
  `config.json` `defaultProject`, else exit 1 per R22.
- The drift TOML gains a top-level optional `project = "..."` and an optional
  per-service `project` override. Resolution order: per-service, top-level,
  `--project`, config default. If none resolves, exit 1 per R22.
- R39 becomes: a declared service that the API does not return *in the
  resolved project* is `Missing`. A service that exists in another project is
  reported as `Missing`, and the spec should say so plainly rather than promise
  cross-project search.

### 4. R11: clap's default usage-error exit code is 2

clap exits with status 2 on invalid arguments. R11 reserves 2 for "drift
detected" and puts invalid input under 1. A CI gate reading exit 2 as "drift"
would misread a typo in a flag as drift. This is a trap, not a contradiction:
the spec is right, but the implementation must override clap's default and a
test must pin it. Add to R11: "including argument parsing errors, which MUST
exit 1, not clap's default of 2."

---

## Decisions the spec must make

### 5. R16, R27, R39, R15: errors are in the body, not the status line

The API reports most failures as HTTP 200 with an envelope:

- `{ "status": "KO", "message": "..." }` for failures
  (`api.go` `sendRequestCore`, `actions.js` `doAction`).
- `{ "status": "OK", "serviceInfos": [] }` for a service that does not exist.
  The Go client treats an empty `serviceInfos` as "service not found".
- `code: "AccessDenied"` or `code: "InvalidToken"` in some responses
  (`api.js`, `services.js`).

So:

- R16 "non-2xx" must be extended to "non-2xx, or 2xx with `status == "KO"`".
- R27 and R39 must define not-found as "2xx with empty `serviceInfos`" and
  possibly "KO with a message", not HTTP 404. Whether the API ever returns 404
  is unknown from the references.
- R15 must state that a `KO` body is never retried, whatever the HTTP status.
- R20 "credentials rejected" is `checkAPIToken` returning `status != "OK"` or
  no `jwt` (`api.js` `authenticate`).

### 6. R41: platform-injected firewall rules

The Terraform provider (`internal/firewall/helpers.go`, `rules.go`,
`schema.go`) documents rules the platform adds without the user asking:

- System ports, required and pinned to exactly `["0.0.0.0/0", "::/0"]`:
  `22/tcp/INPUT` and `4242/udp/INPUT`, plus `80/tcp/INPUT` when custom domains
  are used.
- Tool ports, added by the API for management UIs: `18344`, `18345`, `18346`,
  `18374`, `18445`, all `tcp/INPUT`.
- Template default ports per software.

Terraform deliberately excludes tool ports from its drift comparison "to
prevent state drift" (`conversion.go` `ExtractUserRules`). Under R41 as
written, a user who declares only their application ports will see up to
eight `Unexpected` rules on every healthy service, and the CI gate will never
pass.

**Options.**

- (a) Keep R41 strict. The user must declare the full set. Honest and simple,
  but the example in R32 (one rule, port 22) would report drift on any real
  service.
- (b) Add a per-service `firewall_mode = "exact" | "subset"`, default
  `"subset"`, where subset reports `Absent` but never `Unexpected`.
- (c) Strict by default, with a built-in ignore list mirroring Terraform's tool
  ports. This bakes Elestio internals into the diff engine.

**Recommendation.** (b). It keeps the diff engine free of platform knowledge,
and R44 to R47 hold in both modes. R32's example should either show the full
rule set or set `firewall_mode = "subset"`.

### 7. R28, R25: what is a secret, and does R28 apply to `--json`

What the raw `getServerDetails` response contains (Go `Service` struct,
`service.go`):

- `managedDBCLI`: a connection command with placeholders `[APP_PASSWORD]`,
  `[EMAIL]`, `[DOMAIN]`. The real password is substituted only after a
  separate call to `getAppCredentials` (`GetServiceDatabaseAdmin`).
- `adminUser`, `sshKeys` (public keys), `cname`, `ipv4`, `globalIP`.

Real passwords come only from `getAppCredentials` and `getServiceEnv`, which
finding 1's allowlist already blocks. So in v0.1 the tool never possesses a
real secret, and `--show-secrets` has nothing to show.

**Recommendation.** Either drop `--show-secrets` from v0.1 and rewrite R28 as
"MUST NOT call `getAppCredentials` or any endpoint that returns credentials",
or keep it and define it as: a denylist of raw field names (`managedDBCLI`,
`adminUser`, and any key matching `password`, `secret`, `token`, `cli`) that
is stripped from both human and `--json` output unless `--show-secrets` is
passed. R25 must then say whether `--json` emits raw API objects or a
normalised schema. Raw objects are more useful for scripting but couple every
consumer to Elestio's field names; a normalised object of the R23 fields is
stable. Pick one; I recommend normalised for `services` and raw-minus-denylist
for `service`.

### 8. R23, R32: pin the field mapping

The TOML keys in R32 are not the API's names. The mapping, from the Go
`Service` struct and the Node CLI's column definitions:

| TOML / human column | API JSON field | Notes |
| --- | --- | --- |
| `id` | `vmID` | May arrive as a number or a string. The skill file shows `"vmID": 848528` as a number; the Go client has `FlexString` for exactly this. Accept both, normalise to string. |
| `name` | `displayName` | |
| template/software | `templateName` | Present in Node CLI columns only. The Go struct has `template` (numeric ID). Not verifiable further without a live call. |
| `version` | `selected_software_tag` | |
| `provider` | `provider` | Exact string as the API returns it. R32's `"hetzner"` may not match the API's casing. |
| `datacenter` | `datacenter` | |
| `server_type` | `serverType` | |
| status | `status` and `deploymentStatus` | Two fields. R23 says "status"; say which, or show both as the official CLI does. |
| `firewall[].type` | `type` | API uses `INPUT`/`OUTPUT` uppercase. |
| `firewall[].port` | `port` | String. Ranges like `8000-9000` are valid (Terraform validator `IsPortOrRange`). |
| `firewall[].protocol` | `protocol` | `tcp` or `udp`, lowercase. |
| `firewall[].targets` | `targets` | Array of CIDR strings. |

The spec should carry this table so QA can build fixtures from it without
reading the implementation. One unverifiable assumption to test against the
live API early: that `selected_software_tag` and `templateName` are present in
the `getServices` list response and not only in `getServerDetails`. The Go
client uses one struct for both, which suggests yes, but does not prove it.

---

## Ambiguities

### 9. R15, R14: retry and timeout constants

- "Maximum 3 attempts": three total, or one plus three retries? Say "at most 3
  requests in total".
- Backoff base and cap are unspecified. Tests need them small. Say: delay
  before retry n is `base * 2^(n-1)`, base 500 ms by default, overridable so
  tests do not sleep.
- Connection errors and timeouts are not mentioned. The Go client retries 408
  and 5xx. Say whether transport errors are retried. I recommend yes, since
  every call in scope is an idempotent read even though it is a POST, and the
  spec should say that explicitly because "retry a POST" looks wrong on
  review.
- R14: is 30 s per attempt or for the whole operation? With 3 attempts and
  backoff, per-attempt gives a worst case over 90 s. Say per attempt.

### 10. R40, R46: normalisation and duplicates

- Case: the API returns `INPUT` and `tcp`; Terraform accepts `input` and maps
  it to uppercase (`conversion.go` `NormalizeTypeToAPI`). Say that `type` and
  `protocol` compare case-insensitively and `port` and `targets` compare
  exactly.
- Duplicates: set semantics means `[r, r]` equals `[r]`. R46 only covers
  permutations. Say whether duplicates in the declared list are a validation
  error or silently collapsed.
- Rule identity: Terraform keys a rule by `(port, protocol, type)` and treats
  `targets` as a set attribute. R40 says equality needs all four. Under R40, a
  rule whose targets changed shows as one `Absent` plus one `Unexpected`
  rather than one field difference. That is acceptable but should be stated so
  R45 can be tested (finding 14).

### 11. R31: open to the internet

- A rule with targets `["10.0.0.0/8", "0.0.0.0/0"]`: open or not? Say "any
  target equals `0.0.0.0/0` or `::/0`".
- An `OUTPUT` rule to `0.0.0.0/0` is not exposure. Say the flag applies to
  `INPUT` only, or say it applies to any type. Terraform currently supports
  only `input`.
- Only those two literal strings are evidenced (`helpers.go`
  `defaultTargetIPv4`, `defaultTargetIPv6`). Do not add `0.0.0.0` or `any`
  without evidence.

### 12. R48, R49, R38: output for all four difference kinds

The diff produces four kinds: field mismatch (R38), `Missing` (R39),
`Unexpected` and `Absent` (R41). R48's line format
`<id> <field>: declared=<x> actual=<y>` fits only the first. Define:

```text
41928 name: declared=prod-postgres actual=prod-pg
41928 missing: service not found in project 112
41928 firewall unexpected: INPUT 18345/tcp [0.0.0.0/0, ::/0]
41928 firewall absent: INPUT 22/tcp [0.0.0.0/0, ::/0]
```

Also define the JSON element shape for R49, for example `kind`, `service_id`,
`field`, `declared`, `actual`, with `declared` and `actual` null where they do
not apply. "Grouped by service" also needs saying: is there a header line per
service, or is grouping just ordering? Snapshot tests need the exact text.

### 13. R42, R47: define the order

"Stable order" should be concrete: services in declared order, fields in a
fixed canonical order (`name`, `server_type`, `provider`, `datacenter`,
`version`, `firewall`), firewall differences sorted by `(type, port,
protocol, targets)` with `Absent` before `Unexpected`. R47 says "byte-identical
output" but the engine is pure and returns a value; say whether the property
is over the rendered string or the returned value. Both are fine, testing both
is cheap.

### 14. R43, R45: reflexivity across two types

Declared state has optional fields; actual state does not. "Diff any state
against itself" needs a function that turns an actual state into a declared
state that asserts everything. Restate R43 as: for any actual `A`,
`diff(declare_all(A), A)` is empty. R45 should say what "naming that field"
means for firewall changes, since a target edit yields `Absent` and
`Unexpected` on the `firewall` field rather than a mismatch on
`firewall.targets`.

### 15. R33: absent versus empty firewall

TOML can express both "no `[[service.firewall]]` tables" and `firewall = []`.
Say: absent means do not check; empty means assert there are no rules (every
actual rule is `Unexpected` in exact mode).

### 16. R35 versus R34: missing `id` is a parse error under serde

If `id` is a required field in the deserialised struct, a missing `id` fails
at TOML parse time with a line number, which is R34's path, not R35's index.
To produce "index of the offending entry" the struct must parse `id` as
optional and validate afterwards. Say that, and say whether `id` may be a TOML
integer as well as a string (recommend both, normalised to string, since
`vmID` itself arrives both ways).

### 17. R37: partial failure

If the config declares five services and the third fetch fails with a network
error after retries, does the command exit 1 with nothing, or report the other
four and exit 1? Say. I recommend: abort with exit 1 and no drift output,
because a partial drift report that exits 1 is ambiguous to a CI gate.
Auth failure is always exit 1.

### 18. R29: firewall disabled or not deployed

The Go client returns an empty rule list when `isFirewallActivated == 0` or
`deploymentStatus != "Deployed"`, and swallows `DoActionOnServer` errors into
an empty list. Say what `firewall get` prints in those states (recommend an
explicit "firewall disabled" line rather than "no rules") and what drift does
(recommend: actual rules are the empty set, so declared rules are `Absent`).

### 19. R19, R18: what identity

`checkAPIToken` returns `status`, `jwt`, and `message` in every reference.
Nothing shows it returning the email or an account ID. The official CLI prints
the email from the credentials file. Say that R19's identity is the email that
was used to authenticate, and that R18's "authenticated request" is
`checkAPIToken` itself.

### 20. R17: naming the field

`serde_json` reports line and column for type mismatches, and a field name
only for missing fields. Naming the JSON path on every failure needs the
`serde_path_to_error` crate. Either allow that dependency in the spec or
soften R17 to "naming the location". I recommend allowing the crate.

---

## Minor

### 21. R3: env var name

The Terraform provider reads `ELESTIO_EMAIL` and `ELESTIO_API_TOKEN`. The spec
says `ELESTIO_TOKEN`. The official CLI reads no environment variables at all.
Recommend `ELESTIO_API_TOKEN` for consistency with the one reference that has
a convention, or accept both.

### 22. R4: permission check

Mode bits do not exist on Windows. Say the check runs on Unix only. Define
"more permissive than 0600" as any group or other bit set, so `0400` passes.

### 23. R8: "aligned" and colour

"Aligned" is not testable except by snapshot. Since nothing in v0.1 asks for
colour, the simplest way to satisfy the TTY clause is to emit no ANSI at all.
Say whether colour is wanted. If not, R8 collapses to "no ANSI codes, ever",
which is one grep in a test.

### 24. R7, R10: errors under `--json`

R7 covers successful output only. Say that errors are always plain text on
stderr and stdout is empty on error, so a `--json` consumer can rely on
"stdout parses or the exit code is non-zero".

### 25. R2: unused defaults

`config.json` has `defaultProject` at top level and `defaults.provider`,
`defaults.datacenter`, `defaults.serverType`, `defaults.support`. Only
`defaultProject` is used by any v0.1 command. Either drop provider and
datacenter from R2 or say what they are for.

### 26. R22: pointing at the official CLI

We cannot write config (R54). The message must say `--project <id>` or
`elestio config --set-default-project <id>` (the official CLI command from
`cli.js`). Say so, so the wording is testable.

### 27. R44: zero services

A TOML file with no `[[service]]` tables: exit 0 with "no drift", exit 0 with a
warning, or a validation error? Say. I recommend exit 0 with a stderr warning.

### 28. R59 with R52 and R54

R52 is testable by reading `src/lib.rs` in a test and asserting the attribute
is present. R54 is testable by running the binary with `HOME` pointed at an
empty temp directory and asserting nothing was created. Both are unusual; list
them so QA does not mark them as gaps.

### 29. R56 versus the Makefile

R56 says `cargo clippy -- -D warnings`; the Makefile runs
`--all-targets`, which also lints tests and benches. The Makefile is stricter,
which is fine, but the spec should match it.

### 30. Spec location

The spec is at `Spec.md`. The workflow description, the agent role files, and
the hook that protects the spec from edits all name `spec/SPEC.md`. Move the
file before Phase 2, or the guardrail will protect a path that does not exist.

---

## Things confirmed, for the record

- Base URL is `https://api.elest.io` in both clients (R13 default).
- Credentials file is JSON: `{ "email": "...", "apiToken": "..." }`, written
  with mode `0600`. Directory is `~/.elestio`, mode `0700`.
- `config.json` is JSON with `jwt`, `jwtExpiry` (epoch ms), `defaultProject`
  (string), and a `defaults` object.
- List services request body: `{ "appid": "Cloudxx", "projectId": "<id>",
  "isActiveService": "true", "jwt": "..." }` (Node CLI). The Go client sends
  `appid: ""` and a boolean. The response is `{ "servers": [...] }`, with the
  Node CLI also accepting `data.services`.
- Service details request body: `{ "vmID": "<id>", "projectID": "<id>",
  "jwt": "..." }`. Response `{ "serviceInfos": [ {...} ] }`.
- Firewall request body: `{ "vmID": "<id>", "action": "getFirewallRules",
  "jwt": "..." }`. Response `{ "rules": [...] }` or `{ "data": { "rules":
  [...] } }` (the Node CLI accepts both).
- Firewall rule shape: `{ "type", "port", "protocol", "targets": [] }`, all
  strings except `targets`.
- Immutable service fields per Terraform (`RequiresReplace`): `datacenter`,
  `project_id`, `provider_name`, `server_type`, `template_id`. This means drift
  on `provider`, `datacenter`, or `server_type` is a rebuild, not an update,
  which is worth a note in the drift output later but is not a spec issue now.
