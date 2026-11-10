//! Checks the rules in the implementation plan that the compiler would not
//! otherwise enforce (sections 1.4, 3.1 and 7.1).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use toml::{Table, Value};

/// Every crate, with the workspace crates it may depend on.
const CRATES: &[(&str, &[&str])] = &[
    ("seal-format", &[]),
    ("seal-keys", &["seal-format"]),
    ("seal-proto", &[]),
    ("seal-broker", &["seal-format", "seal-keys"]),
    (
        "seal-client",
        &["seal-broker", "seal-format", "seal-keys", "seal-proto"],
    ),
    (
        "seal",
        &["seal-broker", "seal-format", "seal-keys", "seal-proto"],
    ),
    ("seal-testkit", &[]),
];

const OPEN_FEATURE: &str = "seal-format feature \"open\"";
const TEST_VECTORS_FEATURE: &str = "seal-format feature \"test-vectors\"";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_toml(path: &Path) -> Table {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.parse()
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn manifest(name: &str) -> Table {
    read_toml(
        &workspace_root()
            .join("crates")
            .join(name)
            .join("Cargo.toml"),
    )
}

fn is_workspace_crate(name: &str) -> bool {
    CRATES.iter().any(|(known, _)| *known == name)
}

fn workspace_deps(manifest: &Table, section: &str) -> BTreeSet<String> {
    manifest
        .get(section)
        .and_then(Value::as_table)
        .map(|deps| {
            deps.keys()
                .filter(|name| is_workspace_crate(name))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// The features `cargo tree` reports for a package, one per line.
fn feature_tree(package: &str, extra: &[&str]) -> String {
    let output = Command::new(env!("CARGO"))
        .current_dir(workspace_root())
        .args([
            "tree",
            "--locked",
            "--target",
            "all",
            "--edges",
            "features,no-dev",
        ])
        .args(["--package", package])
        .args(extra)
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("cargo tree prints UTF-8")
}

#[test]
fn the_crate_list_matches_the_workspace() {
    let on_disk: BTreeSet<String> = fs::read_dir(workspace_root().join("crates"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let listed: BTreeSet<String> = CRATES.iter().map(|(name, _)| (*name).to_owned()).collect();
    assert_eq!(on_disk, listed);
}

#[test]
fn the_workspace_forbids_unsafe_code_and_denies_panicking_shortcuts() {
    let root = read_toml(&workspace_root().join("Cargo.toml"));
    let lints = &root["workspace"]["lints"];
    assert_eq!(lints["rust"]["unsafe_code"].as_str(), Some("forbid"));
    for lint in [
        "dbg_macro",
        "expect_used",
        "panic",
        "print_stdout",
        "unwrap_used",
    ] {
        assert_eq!(lints["clippy"][lint].as_str(), Some("deny"), "{lint}");
    }
}

#[test]
fn every_crate_inherits_the_workspace_lints() {
    for (name, _) in CRATES {
        let inherits = manifest(name)
            .get("lints")
            .and_then(|lints| lints.get("workspace"))
            .and_then(Value::as_bool);
        assert_eq!(inherits, Some(true), "{name}");
    }
}

#[test]
fn every_crate_root_forbids_unsafe_code() {
    for (name, _) in CRATES {
        let src = workspace_root().join("crates").join(name).join("src");
        let root = if src.join("lib.rs").exists() {
            src.join("lib.rs")
        } else {
            src.join("main.rs")
        };
        let text = fs::read_to_string(&root).unwrap();
        assert!(
            text.contains("#![forbid(unsafe_code)]"),
            "{}",
            root.display()
        );
    }
}

#[test]
fn every_crate_inherits_the_rust_version_and_license() {
    for (name, _) in CRATES {
        let manifest = manifest(name);
        for field in ["rust-version", "license", "edition"] {
            let inherited = manifest["package"]
                .get(field)
                .and_then(|value| value.get("workspace"))
                .and_then(Value::as_bool);
            assert_eq!(inherited, Some(true), "{name}: {field}");
        }
    }
}

#[test]
fn the_pinned_toolchain_is_the_declared_rust_version() {
    let toolchain = read_toml(&workspace_root().join("rust-toolchain.toml"));
    let channel = toolchain["toolchain"]["channel"].as_str().unwrap();
    let root = read_toml(&workspace_root().join("Cargo.toml"));
    let rust_version = root["workspace"]["package"]["rust-version"]
        .as_str()
        .unwrap();
    assert!(
        channel.starts_with(&format!("{rust_version}.")),
        "toolchain {channel}, rust-version {rust_version}"
    );
}

#[test]
fn crates_depend_only_in_the_planned_direction() {
    for (name, allowed) in CRATES {
        let allowed: BTreeSet<String> = allowed.iter().map(|dep| (*dep).to_owned()).collect();
        let deps = workspace_deps(&manifest(name), "dependencies");
        let unexpected: Vec<_> = deps.difference(&allowed).collect();
        assert!(unexpected.is_empty(), "{name} depends on {unexpected:?}");
    }
}

#[test]
fn the_testkit_is_never_a_normal_dependency_or_published() {
    for (name, _) in CRATES {
        let manifest = manifest(name);
        for section in ["dependencies", "build-dependencies"] {
            assert!(
                !workspace_deps(&manifest, section).contains("seal-testkit"),
                "{name} has seal-testkit in {section}"
            );
        }
    }
    assert_eq!(
        manifest("seal-testkit")["package"]["publish"].as_bool(),
        Some(false)
    );
}

#[test]
fn opening_is_not_a_default_feature_of_seal_format() {
    let manifest = manifest("seal-format");
    assert!(
        manifest["features"].get("open").is_some(),
        "the open feature exists"
    );
    let defaults = manifest["features"]
        .get("default")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(!defaults.iter().any(|f| f.as_str() == Some("open")));
}

#[test]
fn seal_format_alone_has_no_opening_code() {
    assert!(!feature_tree("seal-format", &[]).contains(OPEN_FEATURE));
}

#[test]
fn seal_client_without_in_process_has_no_opening_code() {
    assert!(!feature_tree("seal-client", &[]).contains(OPEN_FEATURE));
}

// Also shows that the two checks above are able to see the feature.
#[test]
fn seal_client_with_in_process_links_opening_code() {
    assert!(feature_tree("seal-client", &["--features", "in-process"]).contains(OPEN_FEATURE));
}

#[test]
fn the_webassembly_build_has_no_opening_code() {
    let manifest = manifest("seal-format");
    let wasm = manifest["features"]["wasm"].as_array().unwrap();
    assert!(!wasm.iter().any(|feature| feature.as_str() == Some("open")));
    assert!(!feature_tree("seal-format", &["--features", "wasm"]).contains(OPEN_FEATURE));
}

#[test]
fn nothing_links_the_fixed_randomness_used_for_test_vectors() {
    for (name, _) in CRATES {
        let tree = feature_tree(name, &["--all-features"]);
        assert!(!tree.contains(TEST_VECTORS_FEATURE), "{name}");
    }
}

#[test]
fn the_service_links_opening_code() {
    assert!(feature_tree("seal", &[]).contains(OPEN_FEATURE));
}

/// Every workflow file, joined. The rules below hold for all of them.
fn ci_workflow() -> String {
    let mut files: Vec<_> = fs::read_dir(workspace_root().join(".github/workflows"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            !name.starts_with('.') && (name.ends_with(".yml") || name.ends_with(".yaml"))
        })
        .collect();
    files.sort();
    assert!(!files.is_empty());
    files
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn ci_pins_every_action_to_a_full_commit() {
    let workflow = ci_workflow();
    let actions: Vec<&str> = workflow
        .lines()
        .filter_map(|line| {
            line.trim_start()
                .trim_start_matches("- ")
                .strip_prefix("uses: ")
        })
        .collect();
    assert!(!actions.is_empty());
    for action in actions {
        let reference = action
            .split_whitespace()
            .next()
            .and_then(|uses| uses.split_once('@'))
            .map(|(_, reference)| reference)
            .unwrap_or_default();
        assert!(
            reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()),
            "{action}"
        );
    }
}

#[test]
fn ci_has_read_only_permissions_and_keeps_no_credentials() {
    let workflow = ci_workflow();
    assert!(workflow.contains("\npermissions:\n  contents: read\n"));
    let checkouts = workflow.matches("uses: actions/checkout@").count();
    assert!(checkouts > 0);
    assert_eq!(
        workflow.matches("persist-credentials: false").count(),
        checkouts
    );
    assert!(!workflow.contains("pull_request_target"));
    assert!(!workflow.contains("self-hosted"));
}
