# elestioctl: notes

`elestioctl` is a small read-only command line client for the Elestio hosting
platform, written in Rust, plus one command their official client does not
have: `drift`, which compares a TOML file describing how your services should
look against what the API says they actually look like, and exits non-zero if
they differ. It was built in one working session as a demonstration of a
spec-first, multi-agent, verification-first development process. This document
is written for someone who has never seen the project and covers three things:
how the code is put together, the Rust decisions worth being able to defend,
and how the AI workflow was run and what it did and did not catch.

Where a claim below rests on something that happened during the build, the
failure log at the end records it. Nothing there is invented.

---

## 1. Architecture

### 1.1 Module layout

```text
src/
  lib.rs           crate root: #![forbid(unsafe_code)], module list, docs
  main.rs          the binary: clap parsing, wiring, exit codes. Nothing else.
  secret.rs        Secret: a String whose Debug prints [REDACTED]
  config.rs        ~/.elestio/credentials, config.json, env overrides
  client.rs        HTTP: allowlist, JWT injection, timeout, retry, envelope
  model.rs         API shapes (private) and normalised Service / FirewallRule
  commands.rs      one async fn per command; returns data, prints nothing
  output.rs        human tables and JSON for auth/services/service/firewall
  drift_config.rs  TOML parsing and validation for drift
  diff.rs          the drift engine: pure, no I/O
  report.rs        human lines and JSON for drift differences
```

**Library versus binary.** Everything except `main.rs` is a library crate.
The binary is about two hundred lines: parse arguments, load settings, build
a client, call one function from `commands`, hand the result to `output` or
`report`, map the outcome to an exit code. The reason is testability. A test
can call `commands::drift(&client, &declared)` against a mock server and
inspect a `Vec<Difference>` directly. If the logic lived in `main`, every test
would have to spawn the binary and parse its stdout, which is slow and
brittle. The binary is still tested end to end for the things only it owns:
exit codes, stderr wording, that `--json` produces one document.

**Why `diff.rs` is pure.** The diff engine takes a slice of `Declared`
values and a map of `Actual` values and returns a `Vec<Difference>`. No HTTP,
no filesystem, no clock, no environment variable, no logging. This is not
aesthetics. It is what makes two kinds of testing possible:

- Property testing (`proptest`) generates thousands of random inputs and
  asserts invariants. That only works if calling the function has no side
  effects and needs no setup.
- Mutation testing (`cargo mutants`) edits the source, one small change at a
  time, and reruns the tests to see whether any test notices. Each mutant is
  a full test run, so the module under test has to be fast and free of
  network calls, or the run takes hours.

The engine also has no idea where its inputs came from. `Actual` is built
by `commands::drift` from API responses, but the same struct could be built
from a JSON file or a fixture. That is the seam the property tests use.

### 1.2 The error model

Two error crates are used, on purpose, in two different places.

**`thiserror` in the library.** Every library module has its own error enum:
`ConfigError`, `ClientError`, `CommandError`, `DriftConfigError`. Each
variant is a distinct situation a caller might want to react to differently.
The one that matters most is in `client.rs`:

```rust
pub enum ClientError {
    NotAllowed { method, path, action },  // R53: refused before sending
    MissingJwt { path },
    Transport { path, attempts, source },  // network failed 3 times
    HttpStatus { path, status, attempts }, // non-2xx
    Api { path, message },                 // 2xx with "status": "KO"
    AuthRejected { message },              // R20: credentials refused
    Parse { path, json_path, reason },     // R17: names the JSON path
    InvalidSetting { name, reason },
    Build(reqwest::Error),
}
```

`commands::get_service` turns an empty result into `CommandError::NotFound
{ vm_id, project }`. That is a separate variant from anything network-related,
which is what R27 asks for: a caller (or a test) can tell "does not exist"
from "could not reach the API" by matching on the variant, not by grepping a
message.

Which errors are recoverable? Inside the client, transport errors and
retryable statuses (408, 429, 5xx) are recovered from by retrying, up to
three requests total. Everything else is returned. Above the client, nothing
is recovered: a command either produces a result or an error, and `main`
maps every error to exit 1. There is no "warn and continue" path except the
file permission warning (R4), which is collected as a string and printed,
not raised.

**`anyhow` in the binary.** `main.rs` does not care which variant it got;
it cares about telling the user what operation failed (R12) and, with
`--debug`, why, all the way down (R10). `anyhow::Context` attaches an
operation name to whatever error comes up:

```rust
commands::get_service(&client, &project, &vm_id)
    .await
    .with_context(|| format!("failed to fetch service {vm_id}"))?;
```

Without `--debug`, `{:#}` prints the chain on one line:
`error: failed to fetch service 41928: service 41928 not found in project 112`.
With `--debug`, each cause is on its own line. The library never uses
`anyhow` because a library that returns `anyhow::Error` has thrown away the
information a caller might match on.

**Keeping the token out of `Debug` (R6).** The API token and the JWT are
wrapped in `Secret`, a newtype around `String` with a hand-written `Debug`
that prints `[REDACTED]` and no `Display` at all. `Credentials`,
`CachedJwt`, `Settings`, `EnvOverrides` and `ApiClient` all hold `Secret`,
so `#[derive(Debug)]` on them is safe: derive calls the field's `Debug`, and
the field's `Debug` redacts. The only way to get the raw value out is
`.expose()`, which is called in exactly two places (building the sign-in body
and inserting `jwt` into request bodies). Grep for `expose` and you have
audited every exit point.

Two further guards: the JWT goes in the JSON body, never the URL, so
reqwest's error messages, which include the URL, cannot contain it. And the
`tracing` calls in the client log method, path, attempt number and status,
never a body.

### 1.3 Retry and timeout policy (R14, R15)

| Setting | Default | Override |
| --- | --- | --- |
| Per-attempt timeout | 30 s | `ELESTIO_TIMEOUT_SECS` |
| Attempts (total requests) | 3 | fixed |
| Backoff before retry n | 500 ms x 2^(n-1) | `ELESTIO_RETRY_BASE_MS` |
| Retried | 408, 429, 5xx, transport errors | fixed |
| Not retried | other 4xx, 2xx with `"status": "KO"` | fixed |

Why these. Thirty seconds is long enough for a slow API response and short
enough that a hung connection does not stall a CI job for minutes; the
official Node client has no timeout at all. Three attempts is the smallest
number that survives one transient blip and one unlucky retry; more than
that on a read-only tool just delays the error. The 500 ms base means the
worst case adds 1.5 s of waiting (0.5 + 1.0), which is unnoticeable
interactively but enough for a load balancer to recover. The base is
overridable so tests can set it to 1 ms and exercise all three attempts in
a few milliseconds.

The timeout is per attempt, not for the whole operation, so the worst case is
about 90 s plus backoff. The spec says so explicitly because "30 second
timeout" is ambiguous and a reader would otherwise assume the total.

One thing that looks wrong and is not: every request is a POST, and POSTs
are conventionally not retried. Here every call in the allowlist is an
idempotent read (the API just happens to use POST for everything), so
retrying is safe. The spec (R15) says this in words so the next reader does
not "fix" it.

### 1.4 Exit codes (R11)

| Code | Meaning |
| --- | --- |
| 0 | success; for `drift`, no differences |
| 1 | any error: network, auth, parse, bad input, bad arguments |
| 2 | `drift` only: the command worked and found differences |

This is `terraform plan -detailed-exitcode`. The point is CI. A pipeline step
can run `elestioctl drift --config prod.toml` and branch on the code: 0
means proceed, 2 means someone changed something out of band and a human
should look, 1 means the check itself is broken and should not be trusted
either way. Without the three-way split, a script cannot tell "drift" from
"the API was down", and would either block deploys on outages or wave drift
through.

One trap: `clap`, the argument parser, exits with 2 on a usage error by
default. `elestioctl drift --confg typo.toml` would have exited 2 and a CI
gate would have read a typo as drift. `main` calls `Cli::try_parse()` and
maps usage errors to 1 by hand. This was caught during the spec review, not
by a test, and is exactly the kind of thing a spec review is for.

### 1.5 Declared fields only (R33)

The drift TOML checks only what you write down. A `[[service]]` with just an
`id` and a `name` checks the name and nothing else. This is the opposite of
Terraform, which owns the whole resource and reports any field that differs
from state.

The reasons:

- The tool is read-only and has no state file. It cannot know what the
  "last applied" value of a field was, so the only thing it can compare
  against is what the user asserts now.
- Elestio services have dozens of fields, many of which change on their own
  (status, deployment status, IP addresses, prices). Comparing everything
  would report drift on every run.
- A CI gate should fail for reasons someone chose. "Provider must be hetzner
  and the SSH rule must exist" is a policy. "Every field must equal a snapshot
  from Tuesday" is noise.

The rule is: absent means not declared, do not check. The one subtlety is
firewall rules, where "no `firewall` key" (do not check) and `firewall = []`
(assert there are none) are different, and both are expressible in TOML.

### 1.6 Firewall rules as sets (R40)

The API returns firewall rules as a JSON array. Two rules are the same rule
if type, port, protocol and the set of targets match; the position in the
array means nothing, and the order of targets inside a rule means nothing
either. So the engine compares sets, not lists, and a reordering produces no
difference. Case is normalised on the way in (`input` and `INPUT` are the
same type, `TCP` and `tcp` the same protocol) because the Terraform provider
uses lower case and the API upper case, and a user will copy from either.

The Rust representation makes this nearly free. `Rule` holds `targets` as a
`BTreeSet<String>`, and derives `Ord` with fields in the order (type, port,
protocol, targets). Two consequences:

- Set difference is `BTreeSet<&Rule>` on both sides and `.difference()`.
- Iterating a `BTreeSet` is sorted, so the "absent" and "unexpected" groups
  come out in the order R42 specifies without a comparator being written.

Ports sort as strings, so `18345` comes before `22`. The spec asks for a
stable order, not a numeric one, and string order is what the derived `Ord`
gives. It is documented rather than fixed because fixing it would mean a
hand-written `Ord` for one cosmetic gain.

The other firewall decision is the `subset` default. The platform injects
rules the user never wrote: SSH on 22, the Nebula VPN on 4242/udp, and five
management ports in the 183xx range. Under strict set equality, every real
service would show five to eight "unexpected" rules. `firewall_mode =
"subset"` (every declared rule must exist, extras are ignored) is the default
and `"exact"` is opt-in. This came out of the spec review, from reading the
Terraform provider's code that deliberately filters those ports out of its
own drift detection.

---

## 2. Rust specifics

These are the decisions I would want to be able to explain to someone who
knows Go or Python and is reading Rust for the first time.

### 2.1 Where ownership or borrowing forced a design

**`Difference` owns its strings.** The engine borrows its inputs (`&[Declared]`,
`&BTreeMap<String, Actual>`) and returns `Vec<Difference>` where every field
is an owned `String`, not a `&str` borrowed from the inputs. The borrowed
version would be cheaper (no copies), but a `Difference<'a>` with a lifetime
parameter cannot outlive the declared config it points into, and the report
renderer, the JSON encoder and the tests all want to hold differences after
the inputs are gone. The copies are a few short strings per difference;
choosing the lifetime-free type keeps every call site simple.

**`Secret` is a newtype, not a trait.** The alternative to wrapping the token
was to be careful never to print it. Rust's answer to "be careful" is to make
the careless thing a type error: `Secret` has no `Display`, so
`println!("{}", token)` does not compile, and its `Debug` is redaction. The
raw value can only be read by name (`expose()`).

**`Option<String>` for every actual field.** The API does not promise every
field on every endpoint, and `serde` fails the whole response if a required
field is missing. So `RawService` marks everything except `vmID` as
`Option` with `#[serde(default)]`, and the normalised `Service` keeps the
`Option`. The diff engine then compares `Option<String>` on the declared
side (None = not declared) with `Option<String>` on the actual side (None =
API did not say), and a declared value against an absent actual is reported
as a mismatch with `actual=(absent)`. Flattening to `String` with `""` for
missing would have been simpler and would have lied.

**`&mut self` on `sign_in`, `&self` on everything else.** The client stores
the JWT after sign-in, so `sign_in` needs `&mut self`. Every read method
takes `&self`. In `main`, the client is `let mut client`, `ensure_session`
borrows it mutably for one call, and then the command borrows it immutably.
The borrow checker enforces that a command cannot accidentally re-sign-in
mid-flight. In Go this would be a mutex or a comment.

**Two-stage TOML parsing.** `id` is required by the spec but is `Option` in
the serde struct, because if serde enforced it the error would be "missing
field id at line 7", and the spec (R35) wants "entry at index 2 has no id".
The parse is serde, then a plain loop validates. Same for duplicate ids: serde
cannot express "unique across the array", so it is a `BTreeSet` and an
`insert` that returns false.

### 2.2 Which error crate and why

Covered in 1.2. The one-line rule: `thiserror` where code will match on the
error (library), `anyhow` where a human will read it (binary). Using
`anyhow` in the library would have made `NotFound` versus network
indistinguishable to tests; using `thiserror` in the binary would have meant
an enum with a variant for every possible context string.

### 2.3 Async versus blocking

`reqwest` has a blocking API that would have read more simply, and a CLI
that makes three sequential requests does not need concurrency. The
tokio/async version was chosen anyway, for the tests: `wiremock`, the mock
HTTP server, is async-native. Running the blocking client inside an async
test means spawning it on a separate thread in every test. With async, a
test is `#[tokio::test] async fn ...` and the client is awaited directly.
`main` builds a `current_thread` runtime, which is a few microseconds of
overhead. This is a case where the test setup drove a production decision,
and it is worth being honest about that.

### 2.4 What Go would have done differently

- **Errors.** Go would return `error` everywhere and callers would use
  `errors.As` to recover the type. Rust's enums make the set of possible
  errors visible in the signature and exhaustively matchable; a new variant
  is a compile error at every `match` that forgot it.
- **Optional fields.** Go decodes a missing JSON field as the zero value
  (`""`, `0`), silently. Rust makes you choose `Option` and then makes you
  handle `None`. The Go reference client has a `NumberAsBool` type and a
  `FlexString` type for exactly the API quirks this crate handles with
  `deserialize_with`; the difference is that in Rust forgetting to handle
  a case is a compile error, in Go it is a zero.
- **Sets.** Go has no set type; the Terraform provider builds
  `map[string]bool` keyed on `port|protocol|type` by hand. Rust's
  `BTreeSet<Rule>` with a derived `Ord` does the same thing with no key
  string to get wrong.
- **What was harder.** Ownership around the `Difference` type (2.1), the
  broken-pipe handling (Rust ignores SIGPIPE, so `println!` into a closed
  pipe panics; restoring the signal handler needs `unsafe`, which the crate
  forbids, so every stdout write goes through a helper that exits quietly on
  `BrokenPipe`), and the `rustls` crypto provider (the crate builds
  `reqwest` without a default provider because the default one needs
  `cmake`, so `ApiClient::new` installs the `ring` provider explicitly).
  None of these exist in Go.

### 2.5 Why a single static binary matters

The official CLI is `npm install -g elestio` and needs Node 18 or newer on
the machine. In CI that is a base image choice or an install step, plus a
supply chain of transitive packages (theirs has none, to their credit, but
Node itself is the dependency). `elestioctl` is one file. Copy it into a
scratch container, `chmod +x`, run. There is no runtime to version-match, no
`node_modules`, and the TLS stack (`rustls` with `ring`) is compiled in
rather than borrowed from the OS. For a tool whose job is to be a CI gate,
"needs nothing installed" is the feature.

---

## 3. The AI workflow

Everything in this section happened in one working session on 7 September
2026. It was run once. Where something worked, that is one data point, not a
practice. Where something did not, the failure log at the end has the
details.

The roles: **dev** implemented the code. **QA** wrote the tests in a
separate session that could not read the implementation. **critic**
reviewed the diff against the spec on a different model. The human set the
spec and the process and made the decisions the spec review put to them; the
rest was delegated.

### 3.1 The spec-first loop, and what the spec review caught

The order was: read the spec, attack the spec, amend the spec, then write
code. No code was written until the spec had been read against the four
reference repositories (the vendor's Go client, Node CLI, Terraform
provider, and agent skill file).

The review (`docs/SPEC-REVIEW.md`) produced thirty findings. Four were
blocking, meaning the spec as written could not be implemented:

1. **R53 asked for GET-only.** The API has no GET endpoints for anything
   in scope. Every read, including sign-in and firewall rules, is a POST,
   and the firewall read shares its path with every mutation. Implementing
   the spec literally would have produced a tool that could not make a
   single request. It became an allowlist of four (method, path, action)
   triples.
2. **The JWT round trip conflicted with "writes nothing".** The credentials
   file holds an API token that is useless on its own; every call needs a
   JWT obtained by POSTing that token, and the official CLI caches the JWT
   to disk. The spec now allows reading the cache and forbids writing it.
3. **Service reads need a project ID** that neither `service <vmID>` nor
   the drift TOML had anywhere to put.
4. **`clap` exits 2 on usage errors**, which is the drift-detected code. A
   typo in a flag would have read as drift to a CI gate.

The other twenty-six were ambiguities: what "3 attempts" means, whether a
disabled firewall is zero rules, which field names map to which API keys,
what order the output is in, what "not found" looks like when the API says
`200 OK` with an empty array. Each got a decision, and the decisions went
into the spec as v0.2 with the requirement numbers unchanged.

Two things worth saying about this. First, none of the four blocking
findings would have been caught by a test, because tests are written from
the spec; a spec that is wrong produces tests that are wrong in the same
way. Only reading the actual API client caught them. Second, the review took
about as long as writing the config module. It was the highest-value hour
of the build.

### 3.2 Why QA was isolated, and what that caught

QA ran as a separate session with three inputs: the spec, a generated
document of public signatures and doc comments (`docs/API.md`), and its
role file. A hook blocked any read of `src/` other than `lib.rs` for the
duration, so the isolation was enforced, not requested. QA wrote 235 tests,
every one named by requirement ID, and left one failing on purpose; a
second QA pass after mutation testing brought the total to 243.

The argument for isolation is in `agents/qa.md`: if the same context writes
the code and the tests, the tests encode the code's misreading of the spec
and pass. That is an argument. Here is the instance.

Dev wrote the HTTP client so that a `200 OK` whose body was not JSON was
classified as a transport error and retried three times. Dev did this on
purpose, with a comment explaining why ("a truncated body is the usual
cause"). It was wrong: R17 says malformed JSON is a parse error, and R15
lists what may be retried and this is not on it. A test written by Dev would
have asserted three attempts and a transport error, because that is what
Dev believed the right behaviour was. QA, reading only the spec, wrote
`r17_non_json_body_is_a_parse_error_not_a_panic`, asserted one request and
a parse error, watched it fail, and reported the discrepancy instead of
adjusting the test. The fix was ten lines and the test passed unchanged.

What isolation cost: QA guessed the argument order of three functions
wrong because the generated API document truncated their signatures. The
compiler caught it. The lesson is that the boundary is only as good as the
document that crosses it, and the extractor was fixed afterwards.

### 3.3 Why the critic runs on a different model

The critic (Claude Opus, where dev and QA were Claude Fable) was given the
spec and a diff of `src/` and nothing else: no conversation, no reasoning,
no knowledge of what the author intended. It found:

- **Redirects.** reqwest follows up to ten redirects by default, and a
  `307` from an allowed path would replay the body, JWT and all, to
  whatever host the redirect named, past the allowlist. QA's black-box
  tests could not see this: a "the mock received zero requests" assertion
  cannot see a request that went somewhere else. This is a security
  property that took a reader with the code in front of them and R53 in
  mind.
- **HOME unset** produced an error naming neither the credentials path nor
  the environment variables, against R5.
- **The broken-pipe fix** called `exit(0)`, which would have turned
  `drift | head` into exit 0 even with drift found.
- **Trimming** of ports and targets where the spec said compare exactly.

And it was wrong once, specifically and plausibly: it claimed `clap`'s
colour feature would put ANSI codes in `--help`. Running the binary showed
zero escape bytes, on a pipe and on a forced TTY. The finding was still
acted on (the feature is now compiled out, so R8 holds by construction
rather than by a dependency's rendering choice), but it was wrong, and it
is in the failure log because a reviewer's output is a list of leads to
verify, not facts.

Would the same model have found the redirect issue? Unknown; the experiment
was run once with one configuration. The reason to use a different model is
not evidence that it is better; it is that a model reviewing its own output
tends to re-derive the same reasoning and approve it, and a different model
has different defaults. The redirect finding is consistent with that. It is
not proof.

### 3.4 Why guardrails are hooks and not prompt instructions

`.claude/hooks/pre-tool-use.py` runs before every tool call and blocks:
recursive force deletes, writes outside the project, edits to `deny.toml`,
`spec/SPEC.md` and the verify targets in the `Makefile`, force pushes,
network calls to hosts off an allowlist, and, while a marker file exists,
any read of `src/` other than `lib.rs`.

The reason it is a hook is in the file's docstring: a prompt is a request,
a hook is an enforcement point. The prompt is weighed against everything
else in context and can be rationalised past under pressure. The hook runs
outside the model, has no context, and does the same thing on the first
call and the thousandth.

It demonstrated both halves of that within a minute of being installed. It
blocked its own author's commit because the commit message quoted the
forbidden delete command. Correct: it has no judgement, and that is the
point. It then blocked the reworded commit because the message contained a
URL and the host check ran on every URL in every command. Wrong: a URL in a
commit message is not a network call. The check was narrowed to commands
that invoke a network tool. The hook is not a sandbox, and its docstring
says so: `python3 -c "open(...).write(...)"` would get past the write
check. What it does is make the forbidden thing a deliberate act instead of
a reflex.

The frozen files matter most. The verify targets and `deny.toml` are the
checks; a model that could edit them could make any failure pass. The spec
is the contract; a model that could edit it could make any behaviour
correct. Those three files were edited only in Phases 1 and 2, before the
hook existed, and the hook would have to be removed by the human for that
to change.

### 3.5 The verification harness

```makefile
verify-fast:      # ~10s, run after every edit
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test

verify-full: verify-fast
    cargo audit
    cargo deny check
    cargo mutants --file src/diff.rs
```

The split is about feedback latency. An agent looping on a change needs a
signal in seconds or it starts batching changes and loses track of which
one broke what. Formatting, lints as errors, and the test suite fit in
about ten seconds here (the CLI tests, which spawn the binary against a
mock server, are three of those). The slow tier adds two network-touching
checks (`cargo audit` pulls the advisory database; `cargo deny` checks
licences, bans, sources and advisories against a policy file) and mutation
testing, which rebuilds and retests once per mutant and takes minutes.

`clippy -D warnings` deserves a note. It turned a dead-code warning into an
error when the drift exit variant existed before the drift command did. The
options were `#[allow(dead_code)]` or removing the variant until it was
used. The variant was removed and added back three commits later. That is
the harness working: the lint asked a question ("why does this exist?") and
the honest answer was "it does not yet".

### 3.6 Property testing

R43 to R47 are stated as invariants and tested with `proptest`, which
generates random `Declared`, `Actual` and `Rule` values (128 cases per
property, 8 properties):

| Invariant | What is generated | What is asserted |
| --- | --- | --- |
| Reflexivity (R43) | any actual state `A` | `diff(declare_all(A), A)` is empty |
| Emptiness (R44) | any actual, any id-only declaration | no differences |
| Detection (R45) | any actual, a declared field set to a different value | a difference names that field |
| Set semantics (R46) | any rule list, a shuffle of it, shuffled targets | no differences in exact mode |
| Determinism (R47) | any inputs | two runs give equal vectors and byte-identical rendering |

Why invariants beat examples when the tests are machine-written. An
example test encodes one input the author thought of. If the author (a
model) and the implementer (a model) think of the same inputs, which they
often do because they read the same spec with similar defaults, the example
tests the happy path both had in mind. A property says "for every input in
this space" and then samples the space with a generator the author did not
hand-pick. The generator will produce the empty target set, the rule
duplicated three times, the port `""`, the target with a trailing space.
The R40 trimming deviation (entry 11 in the failure log) is exactly the kind
of thing a property with generated whitespace would have found; it was
found by the critic instead, because the QA generators used simple
alphanumeric strings. That is a limitation of the generators as written,
recorded here.

Properties also fail in a way that teaches: `proptest` shrinks the failing
input to the smallest one that still fails, so the report is "a rule list
with one rule whose targets are `[""]`", not a 40-line fixture.

### 3.7 Mutation testing

`cargo mutants` takes a source file, makes one small change at a time
(replace a function body with a default value, flip `==` to `!=`, return
an empty vector), and runs the test suite. A mutant that the suite still
passes against has **survived**: the tests did not notice a bug that was
injected. Line coverage cannot tell you this; a line can be executed by a
test that asserts nothing about it.

The run against the diff engine, before any test was written to target it:

| | Count |
| --- | --- |
| Mutants generated in `src/diff.rs` | 14 |
| Caught (a test failed) | 11 |
| Unviable (did not compile) | 3 |
| **Survived** | **0** |

The eleven caught include the two operator flips in `diff_service` (`!=`
to `==` in the scalar comparison, `==` to `!=` in the firewall mode check),
both return-empty replacements, and the string-returning helpers replaced
with `""` and `"xyzzy"`. The three unviable are `Default::default()`
substitutions for types that have no `Default`, which is noise.

So the before number is zero and the "write tests to kill survivors" step
had nothing to kill in the engine. That is the honest result and it needs
two qualifications. First, `cargo mutants`' default mutant set is coarse:
it replaces whole function bodies and flips a few operators. It does not,
for example, drop one arm of a match or off-by-one a comparison, so
"zero survivors" means "the suite notices when a function is gutted", not
"the suite is complete". Second, this is one module of about 280 lines with
31 example tests and 8 properties aimed at it by a session that knew it
would be mutation-tested. It would be surprising if the default mutants
survived.

**Extending the experiment.** Because zero survivors in the engine said
more about the suite's aim than its reach, three more runs were made.

First, the two other pure modules, `report.rs` and `drift_config.rs`: 18
mutants, 15 caught, 3 unviable, 0 survived. Second, nine hand-built mutants
in `diff.rs` of kinds `cargo mutants` does not generate (drop the case
folding on type or protocol, swap two scalar fields in the report order,
put the wrong project in a `Missing`, reverse the declared order, make
`declare_all` use subset mode, change the target separator in rendering,
emit `Unexpected` before `Absent`, skip a mismatch when the actual value is
absent). All nine were caught. At this point the suite looked complete.

Third, the client, which is where the two most consequential defects of the
build (retry-on-decode, redirects) had lived and which QA had not been told
would be mutated:

| `src/client.rs` | Before | After |
| --- | --- | --- |
| Mutants generated | 61 | 60 |
| Caught | 48 | 51 |
| Timed out (infinite loop or ignored environment; detected) | 2 | 3 |
| Unviable | 6 | 6 |
| **Survived** | **5** | **0** |

The five survivors, and what each revealed about the suite:

1. `action_suffix` replaced with `""` or `"xyzzy"` (two mutants). The
   error for a refused call was tested for its variant and for the path,
   but no test checked that the message names the action. R12 says errors
   name the operation; for the shared action endpoint, the action *is* the
   operation.
2. The `!jwt.is_empty()` guard in sign-in replaced with `true`. A
   `{"status": "OK", "jwt": ""}` response was accepted as signed in. QA had
   tested the missing-`jwt` case (R20) but not the empty-string case.
3. The backoff exponent `attempt - 1` replaced with `attempt + 1` and with
   `attempt / 1` (two mutants). QA's R15 backoff test measured wall-clock
   time around a retried call with a tolerance wide enough to accept 300 ms
   or 600 ms where 150 ms was expected. A timing test pins "roughly right";
   it cannot pin a formula.

What changed. The backoff arithmetic was moved into a public pure function,
`backoff_delay(base, attempt)`, so it could be asserted exactly. QA was
re-run, still isolated, and told only what the spec requires in the three
areas (not which lines had mutated). It added eight tests: two for the
refused-call message, one for the empty JWT, and five for the backoff
formula including two properties (`f(base, n+1) == 2 * f(base, n)`, and the
closed form). The rerun had no survivors. The mutant count dropped by one
because the extracted function has one fewer mutation site than the inline
expression.

The point of the before-and-after is not the zero. It is that a suite of 235
tests, every requirement covered, every property passing, all hand-built
engine mutants caught, still had three behaviours that could be broken
without a test failing, and that the only way to learn that was to break
them and see.

### 3.8 Honest limitations

- **Run once.** Every claim in this section is about one build, one
  session, one configuration of models. Nothing here is an established
  practice; it is a demonstration that the pieces fit.
- **Isolation is by hook and prompt, not by sandbox.** The QA session
  could not `cat src/client.rs`, but it could have run `cargo test` on a
  failing build and read the compiler's echoed source lines. It did not
  need to, but the boundary is leakier than "cannot see the
  implementation" suggests.
- **The critic sees the diff, not the behaviour.** It reasoned itself into
  a wrong ANSI finding because it could not run the binary. It also could
  not know that tests were being written elsewhere and flagged their
  absence as blocking. Its findings are leads.
- **The spec review depends on the reference material.** The four blocking
  findings came from reading the vendor's clients. A project with no
  reference implementation would have had to discover the same things by
  calling the API, and the spec review would have caught less.
- **No live API call was made.** Every test runs against a mock server that
  returns the shapes the reference clients expect. Whether
  `selected_software_tag` and `templateName` are present in the real list
  response, as assumed from the Go struct, is unverified. The first run
  against a real account may find a field name wrong. That would be a
  model-layer fix, not an engine fix, but it would be a fix.
- **Mutation testing covered four modules, not the crate.** The engine,
  report, drift config and client were mutated; the model, config and output
  modules were not, after two concurrent runs over them starved each other
  and were stopped. The client run found the only survivors, so the
  unmutated modules may well hold more.
- **Four of the eighteen failure-log entries are about the process
  tooling** (the hook blocking its author, twice; the API extractor
  truncating signatures; two mutation runs starving each other), not the
  product. The workflow generated some of its own
  failures.
- **The whole thing was built in a few hours.** The failure log has eighteen
  entries because the process surfaced them, and because a build that
  moves this fast makes mistakes at this rate. Both are true.

---

## 4. Failure log

The full log, eighteen entries, is in `docs/FAILURE-LOG.md`. Each entry records
what was wrong, how it was caught, and what changed. Nothing in it is invented;
the commit history carries the same events.

Where the catches came from:

| Caught by | Entries |
| --- | --- |
| Reading the reference repos (spec review) | 1 |
| Dev checking its own state or running the binary | 2, 3, 4, 6, 12, 15, 17 |
| The guardrail hook | 5, 18 |
| Mutation testing | 16 |
| QA writing from the spec | 7 |
| The critic | 7, 8, 9, 10, 11 |
| The compiler | 14 |
| Nothing (process artefact, noted) | 13 |

Entry 7 appears twice because QA and the critic found the same defect
independently. Entry 12 is the critic being wrong and Dev catching it by
running the binary.
