//! Binary entry point. Kept deliberately thin: argument parsing, wiring, and
//! exit code mapping live here; everything else lives in the `elestioctl`
//! library.
//!
//! Error handling split: the library uses `thiserror` so callers get typed
//! variants they can match on (`NotFound` versus a transport error, R27).
//! This binary uses `anyhow`, which is for the opposite job: attach a
//! human-readable operation name to whatever went wrong (R12) and print the
//! chain (R10). Typed errors where code decides, context chains where a
//! person reads.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};

use elestioctl::client::{ApiClient, ClientConfig};
use elestioctl::commands;
use elestioctl::config::{self, EnvOverrides, Settings};
use elestioctl::output;

/// Read-only Elestio CLI with drift detection.
#[derive(Parser, Debug)]
#[command(name = "elestioctl", version, about, disable_help_subcommand = true)]
struct Cli {
    /// Emit a single JSON document on stdout instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    /// Print full error chains and request logging to stderr.
    #[arg(long, global = true)]
    debug: bool,

    /// Project ID; overrides `defaultProject` from ~/.elestio/config.json.
    #[arg(long, global = true, value_name = "ID")]
    project: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Credential checks.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// List services in a project.
    Services,
    /// Show one service.
    Service {
        /// The service's vmID.
        vm_id: String,
    },
    /// Firewall rules.
    Firewall {
        #[command(subcommand)]
        command: FirewallCommand,
    },
    /// Compare declared TOML state with actual state.
    Drift {
        /// Path to the TOML file describing desired state.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum AuthCommand {
    /// Verify stored credentials against the API.
    Test,
}

#[derive(Subcommand, Debug)]
enum FirewallCommand {
    /// Show firewall rules for a service.
    Get {
        /// The service's vmID.
        vm_id: String,
    },
}

/// What a successful command wants the process to exit with (R11).
enum Outcome {
    /// Exit 0.
    Clean,
}

fn main() -> ExitCode {
    // R11: clap exits 2 on a usage error by default, which would collide with
    // "drift detected". Parse by hand and map usage errors to 1. `--help` and
    // `--version` also arrive as `Err` but are not errors; they print to
    // stdout and exit 0.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) if e.use_stderr() => {
            // `eprint!` also panics on a closed stderr; a usage error must
            // still exit 1, not 101.
            use std::io::Write;
            let _ = std::io::stderr().write_all(e.to_string().as_bytes());
            return ExitCode::from(1);
        }
        Err(e) => {
            write_stdout(&e.to_string());
            return ExitCode::SUCCESS;
        }
    };

    if cli.debug {
        // R10: request logging goes to stderr only when asked for. Bodies are
        // never logged (see client.rs), so this cannot leak the JWT (R6).
        let _ = tracing_subscriber::fmt()
            .with_env_filter("elestioctl=debug")
            .with_writer(std::io::stderr)
            .without_time()
            .try_init();
    }

    let debug = cli.debug;
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to start async runtime: {e}");
            return ExitCode::from(1);
        }
    };

    match runtime.block_on(run(cli)) {
        Ok(Outcome::Clean) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, debug);
            ExitCode::from(1)
        }
    }
}

/// R10, R12: one line without `--debug`; the whole cause chain with it.
fn report_error(e: &anyhow::Error, debug: bool) {
    if debug {
        let mut chain = e.chain();
        if let Some(first) = chain.next() {
            eprintln!("error: {first}");
        }
        for cause in chain {
            eprintln!("  caused by: {cause}");
        }
    } else {
        // `{:#}` joins the chain with ": " on one line.
        eprintln!("error: {e:#}");
    }
}

fn load_settings() -> anyhow::Result<Settings> {
    let home =
        config::home_dir().ok_or_else(|| anyhow!("HOME is not set; cannot locate ~/.elestio"))?;
    let settings = config::load(&home, &EnvOverrides::from_process_env())
        .context("failed to load credentials")?;
    for warning in &settings.warnings {
        eprintln!("{warning}");
    }
    Ok(settings)
}

fn build_client() -> anyhow::Result<ApiClient> {
    let cfg = ClientConfig::from_env().context("failed to read client settings")?;
    ApiClient::new(cfg).context("failed to build HTTP client")
}

fn emit(json: bool, value: serde_json::Value, human: String) -> anyhow::Result<()> {
    if json {
        // R7: exactly one JSON document, nothing else, on stdout.
        let mut text = serde_json::to_string_pretty(&value)?;
        text.push('\n');
        write_stdout(&text);
    } else {
        write_stdout(&human);
    }
    Ok(())
}

/// Write to stdout without panicking when the reader has gone away.
///
/// Rust ignores SIGPIPE, so `println!` into a closed pipe (`elestioctl
/// services | head -1`) panics with exit 101. A CLI used as a CI gate must
/// not do that. Restoring SIGPIPE needs `unsafe`, which the crate forbids
/// (R52), so instead every stdout write goes through here and a broken pipe
/// ends the process quietly with success: the reader chose to stop.
fn write_stdout(text: &str) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if let Err(e) = lock.write_all(text.as_bytes()).and_then(|_| lock.flush()) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("error: failed to write to stdout: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<Outcome> {
    let settings = load_settings()?;
    let mut client = build_client()?;

    match cli.command {
        Command::Auth {
            command: AuthCommand::Test,
        } => {
            let report = commands::auth_test(&mut client, &settings)
                .await
                .context("authentication test failed")?;
            emit(
                cli.json,
                output::auth_json(&report),
                output::auth_human(&report),
            )?;
            Ok(Outcome::Clean)
        }
        Command::Services => {
            let project = commands::resolve_project(cli.project.as_deref(), &settings)?;
            commands::ensure_session(&mut client, &settings, SystemTime::now())
                .await
                .context("failed to sign in")?;
            let services = commands::list_services(&client, &project)
                .await
                .with_context(|| format!("failed to list services in project {project}"))?;
            emit(
                cli.json,
                output::services_json(&services),
                output::services_human(&project, &services),
            )?;
            Ok(Outcome::Clean)
        }
        Command::Service { vm_id } => {
            let project = commands::resolve_project(cli.project.as_deref(), &settings)?;
            commands::ensure_session(&mut client, &settings, SystemTime::now())
                .await
                .context("failed to sign in")?;
            let service = commands::get_service(&client, &project, &vm_id)
                .await
                .with_context(|| format!("failed to fetch service {vm_id}"))?;
            emit(
                cli.json,
                output::service_json(&service),
                output::service_human(&service),
            )?;
            Ok(Outcome::Clean)
        }
        Command::Firewall {
            command: FirewallCommand::Get { vm_id },
        } => {
            let project = commands::resolve_project(cli.project.as_deref(), &settings)?;
            commands::ensure_session(&mut client, &settings, SystemTime::now())
                .await
                .context("failed to sign in")?;
            let report = commands::firewall_get(&client, &project, &vm_id)
                .await
                .with_context(|| format!("failed to fetch firewall rules for service {vm_id}"))?;
            emit(
                cli.json,
                output::firewall_json(&report),
                output::firewall_human(&report),
            )?;
            Ok(Outcome::Clean)
        }
        Command::Drift { config } => Err(anyhow!(
            "drift is not implemented yet (config: {})",
            config.display()
        )),
    }
}
