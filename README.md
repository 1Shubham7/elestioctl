# elestioctl

A read-only command line client for the [Elestio](https://elest.io) platform,
written in Rust, plus a `drift` command that compares a TOML description of
how your services should look against what the API reports and exits
non-zero when they differ.

This is not a replacement for the official `elestio` CLI. It reads the same
`~/.elestio/credentials` and `~/.elestio/config.json` files that CLI writes,
never mutates anything, and never writes to disk.

## Commands

```text
elestioctl auth test                      verify stored credentials
elestioctl services [--project ID]        list services in a project
elestioctl service <vmID> [--project ID]  show one service
elestioctl firewall get <vmID>            show firewall rules
elestioctl drift --config <path>          compare declared state to actual
```

Global flags: `--json` for machine output, `--debug` for full error chains
and request logging, `--project <ID>` to override the config default.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success, or no drift |
| 1 | error of any kind, including bad arguments |
| 2 | `drift` only: drift was detected |

## Drift config

```toml
project = "112"

[[service]]
id            = "41928"
name          = "prod-postgres"
server_type   = "MEDIUM-2C-4G"
provider      = "hetzner"
version       = "16"
firewall_mode = "subset"    # or "exact"

  [[service.firewall]]
  type     = "INPUT"
  port     = "22"
  protocol = "tcp"
  targets  = ["0.0.0.0/0", "::/0"]
```

Only declared fields are checked. An absent field means "do not check".

## Environment

| Variable | Purpose |
| --- | --- |
| `ELESTIO_EMAIL`, `ELESTIO_API_TOKEN` | credentials, override the file |
| `ELESTIO_API_URL` | base URL, default `https://api.elest.io` |
| `ELESTIO_TIMEOUT_SECS` | per-attempt timeout, default 30 |
| `ELESTIO_RETRY_BASE_MS` | backoff base, default 500 |

## Building and verifying

```sh
cargo build --release
make verify        # fmt, clippy -D warnings, tests (~10s)
make verify-full   # plus cargo audit, cargo deny, cargo mutants
```

## Documents

- `spec/SPEC.md`: the specification, requirements R1 to R60
- `docs/SPEC-REVIEW.md`: what the review of the first spec found
- `docs/NOTES.md`: architecture, Rust decisions, and how the build was run
- `docs/TRACEABILITY.md`: requirement to test mapping
- `docs/FAILURE-LOG.md`: every time a model was confidently wrong
- `agents/`: the dev, QA and critic role definitions
