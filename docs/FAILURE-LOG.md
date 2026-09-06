# Failure log

Every time a model in this build was confidently wrong: what it got wrong,
how it was caught, and what changed. Only things that actually happened are
listed. "Dev" is the implementing session (Claude Fable 5.1), "QA" the
isolated test-writing session (same model, no implementation access), and
"critic" the reviewing session (Claude Opus, spec and diff only).

Entries are in the order they happened.

## 1. The spec asked for something the API cannot do

**Wrong:** Spec v0.1, R53: "The tool MUST NOT issue any HTTP method other
than GET." Written from the reasonable assumption that a read is a GET.

**Caught by:** Phase 0 spec review. Reading `elestio-go-api-client` and
`elestio-cli` showed that every endpoint in scope, including sign-in, list,
details and firewall rules, is a POST, and that the firewall read shares its
path with every mutation and differs only by an `action` string in the body.

**Changed:** R53 was rewritten as a closed allowlist of (method, path,
action) triples, enforced in the client before anything is sent. This is a
stronger guarantee than the original: it also blocks read endpoints that
return credentials.

## 2. Dev committed the wrong spec under the right message

**Wrong:** Dev chained `git mv Spec.md spec/SPEC.md && cat > spec/SPEC.md
<<EOF ... EOF` followed by `git add -A && git commit -m "Spec v0.2 ..."` on
a separate line. The `git mv` failed because the original file was never
tracked, the heredoc never ran, and the commit went ahead anyway, adding
the untracked v0.1 file under a message claiming v0.2.

**Caught by:** Reading `git show --stat HEAD` before moving on.

**Changed:** The commit message was amended to say what it actually was
("Track original v0.1 spec as received"), then the move and rewrite were
redone as separate steps. Lesson kept: chain everything with `&&` or check
the state between steps.

## 3. Dev declared the TLS switch working because it compiled

**Wrong:** `cmake` was missing, so reqwest's default rustls backend
(`aws-lc-sys`) could not build. Dev switched to `rustls-no-provider` plus
the `ring` crate, saw a clean `cargo build` and `make verify`, and moved
on, believing TLS worked.

**Caught by:** The first smoke run of the binary against an unreachable
URL panicked at client construction: "No rustls crypto provider is
configured ... you must install a crypto provider before building a
Client."

**Changed:** `ApiClient::new` installs the `ring` provider explicitly. The
test suite exercises the client against a real (mock) HTTP server, so this
class of "compiles but panics on first use" cannot recur silently.

## 4. Dev did not know that `println!` panics on a closed pipe

**Wrong:** Output used `println!` and `print!`. Rust ignores SIGPIPE, so a
write to a pipe whose reader has exited panics with exit code 101.

**Caught by:** The smoke test piped `--help` into `head -3`, which exited
101 with "failed printing to stdout: Broken pipe".

**Changed:** Every stdout write goes through a helper that swallows
`BrokenPipe`. Restoring the default SIGPIPE handler needs `unsafe`, which
R52 forbids, so the helper is the only option. See entry 10 for the second
iteration of this fix.

## 5. The hook blocked its own author, twice

**Wrong:** The first commit of the guardrail hook was blocked by the hook,
because the commit message quoted the forbidden delete command literally.
The reworded second attempt was blocked because the message contained a URL
(the session link) and the hook checked every URL in a command against the
host allowlist.

**Caught by:** The hook, on Dev's own commands.

**Changed:** The first block was correct behaviour and the message was
reworded. The second was a false positive: a URL in a commit message is
text, not a network call. The host check is now applied only when the
command invokes a network-capable tool (`curl`, `wget`, `ssh`, `git clone`,
`cargo install --git`, and so on). The self-test moved from an inline
heredoc to a file for the same reason: the hook scans the command text, and
test fixtures containing forbidden literals blocked the command that
defined them.

## 6. Dev assumed `make verify-fast` produced the binary

**Wrong:** The smoke test ran `target/debug/elestioctl` and got no output
and exit 0 for every case, including `--help`. Dev's first reading was that
something was badly wrong with argument handling.

**Caught by:** Checking the binary's timestamp. `cargo clippy` and `cargo
test` do not link the main binary; the file on disk was the Phase 1
placeholder from an earlier `cargo build`.

**Changed:** The smoke script runs `cargo build` first. No code change.

## 7. Dev treated an unparsable 2xx body as a network error

**Wrong:** In `ApiClient::attempt`, a `200 OK` whose body was not JSON was
classified as a transport error and retried three times, then reported as
"transport error after 3 attempt(s)" with no parse information. R17 says
malformed JSON is a parse error; R15 lists what is retried and this is not
on the list.

**Caught by:** Twice, independently. QA wrote
`r17_non_json_body_is_a_parse_error_not_a_panic` from the spec, ran it,
saw it fail, and left it failing with a note rather than adjusting it. The
critic, reading only the diff, flagged the same lines. Neither knew about
the other.

**Changed:** The body is read as text and parsed with `serde_json`; a
failure is `ClientError::Parse` with path `$`, not retried. The QA test
passed unchanged after the fix.

This is the clearest example in the build of why QA is isolated. Dev
wrote the retry-on-decode-error path deliberately, with a comment
justifying it ("a truncated body is the usual cause"). A test written by
the same context would have encoded that reasoning and passed.

## 8. Dev left redirects enabled

**Wrong:** `reqwest::Client` follows up to ten redirects by default. A
`307` or `308` from an allowed path would replay the same method and body,
JWT included, to whatever host the `Location` header named. The allowlist
check ran once, on the original URL, and never saw the redirect target.

**Caught by:** The critic. The QA suite did not catch it: a "zero requests
received by the mock" test cannot see a request that went to a different
host.

**Changed:** `.redirect(Policy::none())`. A 3xx is now a non-2xx status
error. This one is the reason the critic exists: it is a security property
that neither the spec's wording nor a black-box test written from the spec
would naturally reach, and a reviewer reading the code with R53 in mind
found it in minutes.

## 9. Dev's no-HOME error named neither the path nor the variables

**Wrong:** With `HOME` unset, `main` returned "HOME is not set; cannot
locate ~/.elestio" before looking at the environment. R3 says environment
credentials work regardless of the file, and R5 says the no-credentials
message must name the file path and both variable names.

**Caught by:** The critic, with the concrete input `env -u HOME
ELESTIO_EMAIL=... ELESTIO_API_TOKEN=... elestioctl auth test`.

**Changed:** `~` stands in for the unknown home, config loading proceeds,
environment credentials are honoured, and the R5 message reads
"~/.elestio/credentials".

## 10. Dev's broken-pipe fix masked the drift exit code

**Wrong:** The fix for entry 4 called `exit(0)` on `BrokenPipe`. So
`elestioctl drift ... | head -1` would exit 0 even when drift was found,
which is precisely the code a CI gate reads.

**Caught by:** The critic.

**Changed:** The helper returns silently on `BrokenPipe` and the command's
outcome still decides the exit code.

## 11. Dev normalised what the spec said to compare exactly

**Wrong:** `Rule::new` trimmed whitespace from ports and targets. R40
says type and protocol fold case and "port and each target compare
exactly".

**Caught by:** The critic, as a note.

**Changed:** Trimming removed. Small, but it is a spec deviation Dev made
with good intentions and without noticing it was one.

## 12. The critic was wrong about ANSI codes

**Wrong:** The critic reported that `clap` with its default `color` feature
embeds ANSI styling and that calling `e.to_string()` on a clap error
bypasses the stripping, so `--help | cat -v` would show escape codes (R8).
The reasoning was plausible and specific.

**Caught by:** Running the binary. `--help | grep -c $'\x1b'` gave 0, as
did a usage error, as did `--help` under `script` to force a TTY. clap's
`Display` for styled strings renders plain text; the ANSI path is a
separate method.

**Changed:** clap's `color` feature was disabled anyway, because "R8 holds
because of how a dependency renders" is weaker than "R8 holds because the
code that could emit colour is not compiled in". The finding was wrong; the
follow-up was still worth doing. Recorded so the critic's output is read as
a set of leads to verify, not a list of facts.

## 13. The critic flagged the absence of tests in a diff that was never going to contain them

**Wrong:** The critic marked "no tests anywhere in the diff" as blocking.
The diff it was given was `src/` and `Cargo.toml` only, by design: QA
writes the tests, in a separate session, and they were being written at the
same time.

**Caught by:** Dev, knowing the process.

**Changed:** Nothing in code. Noted here because it shows the critic does
what it was told, review the diff against the spec, and has no way to know
about work happening outside the diff. That is the intended trade.

## 14. The generated API document truncated multi-line signatures

**Wrong:** `docs/API.md`, produced by a signature extractor, cut
`get_service(project, vm_id)` and two similar functions at the first line
break. QA, working only from that document, guessed the argument order as
`(vm_id, project)`.

**Caught by:** The compiler, when QA's first draft did not type-check.
QA corrected the tests and reported the document defect.

**Changed:** Tests fixed by QA. The extractor was not fixed during the
build; the limitation stands and is recorded here. The lesson is that the
isolation boundary is only as good as the document that crosses it.

## 15. Dev's own filtering hid a formatting failure

**Wrong:** Dev ran `make verify-fast` piped through a `grep` for
`warning|error|test result` and saw nothing but a non-zero exit. `cargo
fmt --check` fails by printing a diff, which matched none of the patterns.

**Caught by:** The exit code, and then running `cargo fmt` unfiltered.

**Changed:** Habit only: run `cargo fmt` before verify. Included because it
is a small instance of a large pattern, filtering tool output down to what
you expect to see and thereby missing what you did not.
