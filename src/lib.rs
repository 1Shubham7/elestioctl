//! `elestioctl`: a read-only command line client for the Elestio platform,
//! plus a drift-detection command that compares declared TOML state against
//! what the API reports.
//!
//! The crate is split into a library (this file and its modules) and a thin
//! binary in `src/main.rs`. The library holds everything testable: config
//! loading, the HTTP client, data models, and the pure diff engine. The binary
//! only parses arguments, calls into the library, and maps results to exit
//! codes.
//!
//! Requirement identifiers (`R1` to `R60`) refer to `spec/SPEC.md`.

// R52: the whole crate refuses `unsafe`. This is also set in `Cargo.toml`
// under `[lints.rust]`, but the spec asks for the attribute at the crate root,
// and having it here means a reader of this file sees it without opening the
// manifest.
#![forbid(unsafe_code)]

pub mod config;
pub mod secret;

/// Crate version, taken from `Cargo.toml` at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
