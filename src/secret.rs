//! A string that refuses to be printed.
//!
//! R6: the API token and the JWT must never appear in any output, including
//! `--debug` output and error messages. The cheapest way to make that true
//! everywhere at once is to make the *type* that holds them incapable of
//! displaying its contents. `Secret` implements `Debug` by printing
//! `[REDACTED]`, does not implement `Display` at all, and only gives the raw
//! value back through an explicitly named method. A reviewer grepping for
//! `.expose()` sees every place the value leaves the wrapper.
//!
//! Rust note: `#[derive(Debug)]` on a struct holding a `String` would print
//! the string. Writing `Debug` by hand is the whole point of this type.

use std::fmt;

/// A credential value (API token or JWT) that redacts itself in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a raw credential.
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// Return the raw value. The name is deliberately loud.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// True when the wrapped value is the empty string.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// R6: redacting Debug. `{:?}` on anything that contains a Secret prints
// `[REDACTED]` in its place, so a struct that derives Debug and holds a
// Secret is safe to log.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
