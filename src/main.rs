//! Binary entry point. Kept deliberately thin: argument parsing and exit code
//! mapping live here, everything else lives in the `elestioctl` library.

#![forbid(unsafe_code)]

fn main() {
    // Phase 1 placeholder. The real CLI arrives in Phase 3.
    let _ = elestioctl::VERSION;
}
