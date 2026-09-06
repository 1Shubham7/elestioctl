# elestioctl — Specification

A read-only Rust CLI for the Elestio platform, plus a drift-detection command
the official CLI does not have.

**Status:** v0.1 spec. Every requirement below is numbered and testable.
Tests reference requirement IDs.

---

## 0. Context and rationale

Elestio ships an official CLI (`elestio`, npm, MIT, Node >= 18, zero npm
dependencies). It is comprehensive: deploy, services, templates, firewall,
SSL, backups, snapshots, CI/CD, billing.

This project is **not** a replacement. It is:

1. **A narrow read-only subset in Rust**, to compare a single static binary
   with no runtime against a global npm install requiring Node 18+.
2. **A drift-detection command they do not have** — declare desired service
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

## 1. Scope — commands in v0.1

| Command | Purpose |
| --- | --- |
| `elestioctl auth test` | Verify stored credentials against the API |
| `elestioctl services` | List services, optionally filtered by project |
| `elestioctl service <vmID>` | Show details for one service |
| `elestioctl firewall get <vmID>` | Show firewall rules for one service |
| `elestioctl drift --config <path>` | Compare declared TOML state to actual |

---

## 2. Configuration and credentials

**R1** — The tool MUST read credentials from `~/.elestio/credentials`, the
same file the official CLI writes. It MUST NOT require its own login flow
in v0.1.

**R2** — The tool MUST read defaults (default project, provider, datacenter)
from `~/.elestio/config.json` when present. A missing file is not an error;
defaults are simply absent.

**R3** — Credentials MAY be overridden by environment variables
`ELESTIO_EMAIL` and `ELESTIO_TOKEN`. Environment takes precedence over file.

**R4** — If the credentials file exists but has permissions more permissive
than `0600`, the tool MUST emit a warning to stderr and continue.

**R5** — If no credentials are found by any means, the tool MUST exit with
code 1 and a message naming both the file path and the environment
variables it looked for.

**R6** — The tool MUST NOT print the API token in any output, including
`--debug` output and error messages. Any struct holding the token MUST have
a `Debug` implementation that redacts it.

---

## 3. Global behaviour

**R7** — `--json` MUST cause all successful command output to be a single
valid JSON document on stdout, with no human-readable decoration.

**R8** — Without `--json`, output MUST be human-readable, aligned, and MUST
NOT contain ANSI colour codes when stdout is not a TTY.

**R9** — `--project <id>` MUST override the default project from config for
commands that take a project.

**R10** — `--debug` MUST cause full error chains to be printed to stderr.
Without it, errors MUST be a single line naming what failed and why.

**R11** — Exit codes MUST be:
  - `0` — success, and for `drift` specifically, no drift detected
  - `1` — error (network, auth, parse, invalid input)
  - `2` — `drift` only: the command succeeded and drift WAS detected

  This mirrors `terraform plan -detailed-exitcode` and makes the tool usable
  as a CI gate.

**R12** — All errors written to stderr MUST name the operation that failed.
"Request failed" is not acceptable; "failed to fetch service 41928" is.

---

## 4. API client

**R13** — The API base URL MUST be configurable via `ELESTIO_API_URL`,
defaulting to the production endpoint. This exists so tests can point at a
mock server.

**R14** — Every HTTP request MUST have a timeout. Default 30 seconds,
overridable via `ELESTIO_TIMEOUT_SECS`.

**R15** — HTTP 429 and 5xx responses MUST be retried with exponential
backoff, maximum 3 attempts. 4xx responses other than 429 MUST NOT be
retried.

**R16** — A non-2xx response that is not retried MUST produce an error
naming the HTTP status and the endpoint path.

**R17** — Malformed or unexpected JSON in a response MUST produce a parse
error naming the field that failed, not a panic.

---

## 5. `auth test`

**R18** — MUST make an authenticated request and report success or failure.

**R19** — On success without `--json`, MUST print the authenticated
identity. On success with `--json`, MUST emit an object with at least an
`authenticated` boolean.

**R20** — On authentication failure MUST exit 1 and distinguish "no
credentials found" from "credentials rejected by the API".

---

## 6. `services`

**R21** — MUST list services for the resolved project (from `--project`,
else config default).

**R22** — If no project can be resolved, MUST exit 1 with a message saying
how to set one.

**R23** — Human output MUST include, per service: id, name, template/software,
version, provider, datacenter, server type, and status.

**R24** — An empty list MUST be reported explicitly, not as blank output.

**R25** — `--json` output MUST be an array of service objects, empty array
when there are none.

---

## 7. `service <vmID>`

**R26** — MUST fetch and display details for a single service by ID.

**R27** — A vmID that does not exist MUST produce a clear "not found" error
and exit 1, distinguishable from a network failure.

**R28** — MUST NOT display any credential, password, or connection string
returned by the API, unless `--show-secrets` is explicitly passed.

---

## 8. `firewall get <vmID>`

**R29** — MUST fetch and display firewall rules for a service.

**R30** — Human output MUST show, per rule: direction/type, port, protocol,
and targets.

**R31** — Rules whose targets are `0.0.0.0/0` or `::/0` MUST be visually
marked as open to the internet in human output. In `--json` output each
rule MUST carry a boolean `open_to_internet`.

---

## 9. `drift --config <path>` — the core feature

### 9.1 Declared state format

**R32** — The config file MUST be TOML. Its shape:

```toml
[[service]]
id           = "41928"
name         = "prod-postgres"
server_type  = "MEDIUM-2C-4G"
provider     = "hetzner"
datacenter   = "hel1"
version      = "16"

  [[service.firewall]]
  type     = "INPUT"
  port     = "22"
  protocol = "tcp"
  targets  = ["0.0.0.0/0", "::/0"]
```

**R33** — Every field except `id` MUST be optional. An absent field means
"not declared, do not check". This is the central design decision: the tool
checks only what you assert, never everything it can see.

**R34** — A malformed TOML file MUST produce a parse error naming the line,
and exit 1.

**R35** — A `[[service]]` entry without an `id` MUST be a validation error
naming the index of the offending entry.

**R36** — Duplicate service IDs in one config MUST be a validation error.

### 9.2 Diff semantics

**R37** — For each declared service, the tool MUST fetch actual state and
compare only the declared fields.

**R38** — A field difference MUST be reported as a `Difference` carrying:
service id, field path, declared value, actual value.

**R39** — A declared service whose id does not exist at the API MUST be
reported as a `Missing` difference, not an error.

**R40** — Firewall rules MUST be compared as a **set**, not a list. Rule
ordering MUST NOT produce a difference. Two rules are equal when type, port,
protocol, and the *set* of targets are all equal.

**R41** — A firewall rule present in actual but not declared MUST be
reported as `Unexpected`. A rule declared but not present MUST be reported
as `Absent`.

**R42** — The diff MUST be deterministic: the same declared config and the
same actual state MUST always produce the same output, in a stable order.

### 9.3 Diff invariants (property-tested)

These are asserted with `proptest` over generated inputs, not just examples:

**R43** — *Reflexivity*: diffing any state against itself yields no
differences.

**R44** — *Emptiness*: an empty declared config yields no differences
regardless of actual state.

**R45** — *Detection*: if any declared field is changed to a different
value, the diff MUST contain at least one difference naming that field.

**R46** — *Set semantics*: for any firewall rule list, diffing it against
any permutation of itself yields no differences.

**R47** — *Determinism*: diffing the same inputs twice yields byte-identical
output.

### 9.4 Output

**R48** — Without `--json`, drift MUST be reported grouped by service, one
difference per line, in the form
`<service-id> <field>: declared=<x> actual=<y>`.

**R49** — With `--json`, output MUST be an object with a `drift_detected`
boolean and a `differences` array.

**R50** — When no drift is found the tool MUST say so explicitly and exit 0.

**R51** — When drift is found the tool MUST exit 2 (see R11).

---

## 10. Safety properties

**R52** — The crate MUST declare `#![forbid(unsafe_code)]` at the root.

**R53** — The tool MUST NOT issue any HTTP method other than GET in v0.1.
This MUST be enforced in the client layer, not merely by convention, and
MUST be covered by a test.

**R54** — The tool MUST NOT write to any path outside its own config
directory. v0.1 writes nothing at all.

---

## 11. Quality gates

**R55** — `cargo fmt --check` MUST pass.

**R56** — `cargo clippy -- -D warnings` MUST pass with zero warnings.

**R57** — `cargo audit` MUST report no known vulnerabilities.

**R58** — `cargo deny check` MUST pass for licences and advisories.

**R59** — Every requirement R1–R54 MUST be referenced by at least one test,
by ID, in a comment or test name. A requirement with no test is a gap and
MUST be listed as such in `docs/TRACEABILITY.md`.

**R60** — `cargo mutants` MUST be run against the diff engine module. The
surviving-mutant count MUST be recorded before and after test improvement in
`docs/NOTES.md`.