//! R52: the crate root forbids unsafe code. Tested by reading the source of
//! `src/lib.rs`, the one implementation file QA is allowed to read (R59).
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn r52_crate_root_forbids_unsafe_code() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let text = std::fs::read_to_string(&root).expect("read crate root");
    let attr = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("#![forbid("))
        .expect("crate root has a #![forbid(...)] attribute");
    assert!(
        attr.contains("unsafe_code"),
        "expected #![forbid(unsafe_code)], found {attr}"
    );
    assert!(text.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn r52_manifest_also_forbids_unsafe_code() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(manifest).expect("read manifest");
    let parsed: toml::Value = toml::from_str(&text).expect("valid toml");
    assert_eq!(
        parsed["lints"]["rust"]["unsafe_code"].as_str(),
        Some("forbid")
    );
}
