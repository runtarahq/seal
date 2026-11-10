//! Proves that the opening code does not exist without the `open` feature.
//!
//! trybuild builds these files as their own project, depending on `seal-format`
//! as this crate's dev-dependency does, without `open`, whatever other workspace
//! crates enable. The stderr files pin the reason for each failure, so that a
//! file failing to compile for an unrelated reason fails the test.

#[test]
fn acceptance_a_sealing_only_build_cannot_open() {
    let cases = trybuild::TestCases::new();
    cases.pass("tests/ui/sealing_only.rs");
    cases.compile_fail("tests/ui/no_open_function.rs");
    cases.compile_fail("tests/ui/no_private_key.rs");
    cases.compile_fail("tests/ui/no_fixed_randomness.rs");
}
