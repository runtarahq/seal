//! What only the service does: callers, certificates, restarts, several instances,
//! limits, health and the CLI.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::io::Write as _;
use std::process::Command;
use std::time::Duration;

use seal_client::{ErrorCode, Mode, SealClient};
use seal_format::KeysetId;
use seal_testkit::pki::TestPki;
use serde_json::json;
use support::*;

fn token_policy(provider: &MockProvider) -> seal_format::Policy {
    policy(&json!({ "rules": [plain_rule(provider, &bearer())] }))
}

async fn eventually<F, Fut>(within: Duration, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let started = tokio::time::Instant::now();
    while !condition().await {
        assert!(
            started.elapsed() < within,
            "the condition did not hold within {within:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// Callers.

#[tokio::test]
async fn acceptance_an_unknown_uid_is_refused() {
    let uid = nix::unistd::getuid().as_raw();
    let callers = format!(
        "[[callers]]\nname = \"someone-else\"\nunix_uid = {}\nkeysets = [\"*\"]\n",
        uid + 1
    );
    let options = Options {
        callers: Some(callers),
        ..Options::default()
    };
    let instance = start(Mode::Unix, options, &[]).await;
    let error = instance.client.info().await.err().unwrap();
    assert_eq!(error.code, ErrorCode::Transport);
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused() {
    let instance = start(Mode::Mtls, Options::default(), &[]).await;
    let stranger = TestPki::new("someone else");
    let mut tls = client_tls(&instance.setup, &stranger.client("test-app"));
    tls.ca_pem = instance.setup.pki.ca_pem.clone();
    let address = instance
        .process
        .as_ref()
        .unwrap()
        .address
        .strip_prefix("tcp:")
        .unwrap()
        .to_owned();
    let client = seal_client::mtls(&[address], &tls).unwrap();
    assert_eq!(
        client.info().await.err().unwrap().code,
        ErrorCode::Transport
    );
}

#[tokio::test]
async fn acceptance_a_certificate_with_an_unknown_subject_is_refused() {
    let instance = start(Mode::Mtls, Options::default(), &[]).await;
    let other = instance.setup.pki.client("not-listed");
    let address = instance
        .process
        .as_ref()
        .unwrap()
        .address
        .strip_prefix("tcp:")
        .unwrap()
        .to_owned();
    let client = seal_client::mtls(&[address], &client_tls(&instance.setup, &other)).unwrap();
    assert_eq!(
        client.info().await.err().unwrap().code,
        ErrorCode::Transport
    );
    assert_eq!(
        instance.client.info().await.unwrap().mode,
        "mtls",
        "the listed caller still works"
    );
}

#[tokio::test]
async fn a_caller_is_limited_to_its_keysets_and_admin_calls_need_admin() {
    let provider = MockProvider::plain().await;
    let uid = nix::unistd::getuid().as_raw();
    let callers = format!("[[callers]]\nname = \"app\"\nunix_uid = {uid}\nkeysets = [\"other\"]\n");
    let options = Options {
        callers: Some(callers),
        ..Options::default()
    };
    let instance = start(Mode::Unix, options, &[&provider]).await;
    let token = instance
        .setup
        .seal("token", b"SEALCANARY-token", &token_policy(&provider))
        .await;
    let error = instance
        .client
        .send(get(&url(&provider, "/echo"), &[("token", &token)]))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::CallerDenied);
    assert!(provider.received().is_empty());
    let webhook =
        seal_format::policy::builder::webhook_hmac(seal_format::policy::HmacHash::Sha256).unwrap();
    let verify = seal_client::VerifyRequest {
        keyset: keyset(),
        item: item(),
        field: field("secret"),
        value: instance
            .setup
            .seal("secret", b"SEALCANARY-signing", &webhook)
            .await
            .into(),
        message: bytes::Bytes::from_static(b"message"),
        mac: vec![0; 32],
    };
    let error = instance.client.verify(verify).await.err().unwrap();
    assert_eq!(error.code, ErrorCode::CallerDenied);
    let keyset = KeysetId::new("other").unwrap();
    assert_eq!(
        instance
            .client
            .generate_keyset(&keyset)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::CallerDenied
    );
    assert_eq!(
        instance
            .client
            .public_keys(&keyset)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::CallerDenied
    );
    let refused: Vec<_> = instance
        .setup
        .audit_records()
        .into_iter()
        .filter(|record| record["op"] == "generate" || record["op"] == "public_keys")
        .collect();
    assert!(
        refused.is_empty(),
        "a refused caller never reaches the keys"
    );
}

#[tokio::test]
async fn the_client_fails_over_to_an_endpoint_that_answers() {
    let instance = start(Mode::Unix, Options::default(), &[]).await;
    let live = instance
        .process
        .as_ref()
        .unwrap()
        .address
        .strip_prefix("unix:")
        .unwrap()
        .to_owned();
    let dead = instance.setup.dir.path().join("nobody-listens.sock");
    let client = seal_client::unix(&[dead, live.into()]).unwrap();
    assert_eq!(client.info().await.unwrap().mode, "unix");
    // And keeps using the one that answered.
    assert_eq!(client.info().await.unwrap().mode, "unix");
    let nothing = seal_client::unix(&[instance.setup.dir.path().join("nothing.sock")]).unwrap();
    assert_eq!(
        nothing.info().await.err().unwrap().code,
        ErrorCode::Transport
    );
}

// Certificates.

#[tokio::test]
async fn certificates_reload_when_their_files_change() {
    let mut setup = Setup::new(None).await;
    // Start with a certificate for the wrong name, which the client refuses.
    let wrong = setup.pki.server(&["old.test"]);
    let (cert, key, ca) = write_tls(&setup, &wrong);
    let listen = format!(
        "[listen]\ntcp = \"127.0.0.1:0\"\ntls = {{ cert = {:?}, key = {:?}, client_ca = {:?} }}\nreload_interval = \"100ms\"\n",
        cert.display().to_string(),
        key.display().to_string(),
        ca.display().to_string()
    );
    let path = write_config(
        &setup,
        &setup.config_text(Mode::Mtls, &Options::default(), &listen),
    );
    let process = spawn(&path);
    let address = process.address.strip_prefix("tcp:").unwrap().to_owned();
    let client = seal_client::mtls(
        std::slice::from_ref(&address),
        &client_tls(&setup, &setup.client),
    )
    .unwrap();
    assert_eq!(
        client.info().await.err().unwrap().code,
        ErrorCode::Transport
    );

    let right = setup.pki.server(&[SERVER_NAME]);
    std::fs::write(&key, &right.key_pem).unwrap();
    std::fs::write(&cert, &right.cert_pem).unwrap();
    eventually(Duration::from_secs(10), || async {
        let client = seal_client::mtls(
            std::slice::from_ref(&address),
            &client_tls(&setup, &setup.client),
        )
        .unwrap();
        client.info().await.is_ok()
    })
    .await;
    setup.provider_cas.clear();
    // The log is read on another thread, so it can trail the reload a little.
    eventually(Duration::from_secs(10), || async {
        process
            .stderr
            .lock()
            .unwrap()
            .contains("reloaded the service's certificates")
    })
    .await;
}

// Restarts and several instances.

#[tokio::test]
async fn acceptance_a_restarted_instance_serves_the_same_values() {
    let provider = MockProvider::plain().await;
    let setup = Setup::new(None).await;
    let token = setup
        .seal("token", b"SEALCANARY-s3cret", &token_policy(&provider))
        .await;
    for _ in 0..2 {
        let (client, process) = connect(Mode::Unix, &Options::default(), &setup).await;
        let response = client
            .send(get(&url(&provider, "/echo"), &[("token", &token)]))
            .await
            .unwrap();
        text(response).await;
        drop(client);
        drop(process);
    }
    let received = provider.received();
    assert_eq!(received.len(), 2);
    assert!(
        received
            .iter()
            .all(|request| request.header("authorization") == Some("Bearer SEALCANARY-s3cret"))
    );
}

fn fast_refresh() -> Options {
    Options {
        keys: "refresh_interval = \"1s\"\nmax_stale = \"3s\"\nmax_unwrap_age = \"20s\"\n"
            .to_owned(),
        ..Options::default()
    }
}

#[tokio::test]
async fn acceptance_a_rotation_and_a_deletion_on_one_instance_reach_another_within_max_stale() {
    let provider = MockProvider::plain().await;
    let shared = tempfile::tempdir().unwrap();
    let keys = shared.path().join("keys");
    let options = Options {
        keys_dir: Some(keys.clone()),
        ..fast_refresh()
    };
    let one = start(Mode::Unix, options.clone(), &[&provider]).await;
    let two = start(Mode::Unix, options, &[&provider]).await;

    // A value sealed to the first key, which instance two has loaded and is using.
    let old_token = one
        .setup
        .seal("token", b"SEALCANARY-old-token", &token_policy(&provider))
        .await;
    async fn send_with(
        instance: &Instance,
        url: &str,
        token: &seal_format::Envelope,
    ) -> Result<(), ErrorCode> {
        let response = instance
            .client
            .send(get(url, &[("token", token)]))
            .await
            .map_err(|error| error.code)?;
        text(response).await;
        Ok(())
    }
    let echo = url(&provider, "/echo");
    send_with(&two, &echo, &old_token).await.unwrap();

    // Rotate on instance one.
    let rotated = one.client.rotate(&keyset()).await.unwrap();
    let new_token = one
        .setup
        .seal("token", b"SEALCANARY-new-token", &token_policy(&provider))
        .await;
    assert_eq!(new_token.kid().as_str(), rotated.kid);
    let response = two
        .client
        .send(get(&url(&provider, "/echo"), &[("token", &new_token)]))
        .await
        .unwrap();
    text(response).await;

    // Delete the old key in the store: instance two, in constant use, stops opening it.
    let old_kid = old_token.kid().to_string();
    std::fs::remove_file(keys.join("acme").join(format!("{old_kid}.json"))).unwrap();
    let started = tokio::time::Instant::now();
    loop {
        match send_with(&two, &echo, &old_token).await {
            Ok(()) => {}
            Err(code) => {
                assert_eq!(code, ErrorCode::OpenFailed);
                break;
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(3) + Duration::from_secs(2),
            "not within max_stale"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn acceptance_reseal_round_trips_a_rotation() {
    let provider = MockProvider::plain().await;
    let instance = start(Mode::Unix, Options::default(), &[&provider]).await;
    let token = instance
        .setup
        .seal("token", b"SEALCANARY-s3cret", &token_policy(&provider))
        .await;
    let rotated = instance.client.rotate(&keyset()).await.unwrap();

    let input = instance.setup.dir.path().join("values.jsonl");
    let output = instance.setup.dir.path().join("resealed.jsonl");
    let line = json!({ "item": item().as_str(), "field": "token", "envelope": token });
    std::fs::File::create(&input)
        .unwrap()
        .write_all(format!("{line}\n").as_bytes())
        .unwrap();
    let config = write_config(
        &instance.setup,
        &instance.setup.config_text(
            Mode::Unix,
            &Options::default(),
            "[listen]\nunix = \"/unused\"\n",
        ),
    );
    let result = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["reseal", "--keyset", "acme", "--config"])
        .arg(&config)
        .arg("--in")
        .arg(&input)
        .arg("--out")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("resealed 1 values"));

    let resealed: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&output).unwrap().trim()).unwrap();
    let envelope =
        seal_format::Envelope::from_json(resealed["envelope"].to_string().as_bytes()).unwrap();
    assert_eq!(envelope.kid().as_str(), rotated.kid);
    assert!(
        !std::fs::read_to_string(&output)
            .unwrap()
            .contains("SEALCANARY-s3cret")
    );
    let response = instance
        .client
        .send(get(&url(&provider, "/echo"), &[("token", &envelope)]))
        .await
        .unwrap();
    text(response).await;
    assert_eq!(
        provider.received()[0].header("authorization"),
        Some("Bearer SEALCANARY-s3cret")
    );

    // Running it again changes nothing, and it never overwrites its output.
    let again = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["reseal", "--keyset", "acme", "--config"])
        .arg(&config)
        .arg("--in")
        .arg(&output)
        .arg("--out")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!again.status.success());
}

/// Runs `seal reseal` over these lines, and returns whether it succeeded, what it
/// printed and the lines it wrote.
fn run_reseal(
    setup: &Setup,
    name: &str,
    lines: &[serde_json::Value],
    extra: &[&str],
) -> (bool, String, Vec<serde_json::Value>) {
    let input = setup.dir.path().join(format!("{name}.in.jsonl"));
    let output = setup.dir.path().join(format!("{name}.out.jsonl"));
    let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
    std::fs::write(&input, text).unwrap();
    let config = write_config(
        setup,
        &setup.config_text(
            Mode::Unix,
            &Options::default(),
            "[listen]\nunix = \"/unused\"\n",
        ),
    );
    let result = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["reseal", "--keyset", "acme", "--config"])
        .arg(&config)
        .arg("--in")
        .arg(&input)
        .arg("--out")
        .arg(&output)
        .args(extra)
        .output()
        .unwrap();
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let written = std::fs::read_to_string(&output)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (result.status.success(), printed, written)
}

/// A provider moves, or an integration changes how it authenticates: whoever runs seal
/// can give stored values a new policy without anyone entering the secrets again. The
/// application cannot, since only seal's host can open them.
#[tokio::test]
async fn reseal_gives_a_value_a_new_policy_only_when_told_to() {
    let provider = MockProvider::plain().await;
    let instance = start(Mode::Unix, Options::default(), &[&provider]).await;
    let setup = &instance.setup;
    let token = setup
        .seal("token", b"SEALCANARY-s3cret", &token_policy(&provider))
        .await;
    let kept = setup
        .seal("kept", b"SEALCANARY-kept", &token_policy(&provider))
        .await;
    let api_key = json!({ "rules": [plain_rule(
        &provider,
        &json!({ "header": { "name": "X-Api-Key", "format": "{}" } }),
    )] });
    let line = |field: &str, envelope: &seal_format::Envelope| json!({ "item": item().as_str(), "field": field, "envelope": envelope });
    let mut moved = line("token", &token);
    moved["policy"] = api_key.clone();
    let lines = [moved.clone(), line("kept", &kept)];

    // Not without the flag, whatever the input says.
    let (ok, printed, _) = run_reseal(setup, "unflagged", &lines, &[]);
    assert!(!ok);
    assert!(
        printed.contains("line 1") && printed.contains("--rewrite-policies"),
        "{printed}"
    );
    assert!(!printed.contains("SEALCANARY"));

    let (ok, printed, written) = run_reseal(setup, "flagged", &lines, &["--rewrite-policies"]);
    assert!(ok, "{printed}");
    assert!(
        printed.contains("resealed 1 values, 1 with a new policy"),
        "{printed}"
    );
    assert_eq!(written.len(), 2);
    assert!(
        written[0].get("policy").is_none(),
        "the output is only values"
    );
    assert_eq!(
        written[1],
        line("kept", &kept),
        "a value with nothing to change is kept"
    );
    assert!(
        !serde_json::to_string(&written)
            .unwrap()
            .contains("SEALCANARY")
    );

    let envelope =
        seal_format::Envelope::from_json(written[0]["envelope"].to_string().as_bytes()).unwrap();
    let response = instance
        .client
        .send(get(&url(&provider, "/echo"), &[("token", &envelope)]))
        .await
        .unwrap();
    text(response).await;
    let received = &provider.received()[0];
    assert_eq!(received.header("x-api-key"), Some("SEALCANARY-s3cret"));
    assert_eq!(received.header("authorization"), None);

    // Naming the policy a value already has changes nothing.
    let mut same = line("token", &envelope);
    same["policy"] = api_key.clone();
    let (ok, printed, written) = run_reseal(setup, "same", &[same], &["--rewrite-policies"]);
    assert!(
        ok && printed.contains("resealed 0 values, 0 with a new policy"),
        "{printed}"
    );
    assert_eq!(written[0], line("token", &envelope));

    // A new policy must be valid, and cannot make a value shared.
    let mut invalid = moved.clone();
    invalid["policy"]["rules"][0]["inject"] =
        json!({ "header": { "name": "Host", "format": "{}" } });
    let mut shared = moved;
    shared["policy"]["shared"] = json!(true);
    for (name, line, reason) in [
        ("invalid", invalid, "its new policy is not valid"),
        ("shared", shared, "cannot change whether a value is shared"),
    ] {
        let (ok, printed, written) = run_reseal(setup, name, &[line], &["--rewrite-policies"]);
        assert!(!ok && printed.contains(reason), "{printed}");
        assert!(written.is_empty());
    }
}

// Limits.

#[tokio::test]
async fn the_rate_per_caller_is_enforced() {
    let provider = MockProvider::plain().await;
    let options = Options {
        limits: "rate_per_caller = \"2/m\"\n".to_owned(),
        ..Options::default()
    };
    let instance = start(Mode::Unix, options, &[&provider]).await;
    let token = instance
        .setup
        .seal("token", b"SEALCANARY-token", &token_policy(&provider))
        .await;
    for _ in 0..2 {
        text(
            instance
                .client
                .send(get(&url(&provider, "/echo"), &[("token", &token)]))
                .await
                .unwrap(),
        )
        .await;
    }
    let error = instance
        .client
        .send(get(&url(&provider, "/echo"), &[("token", &token)]))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert!(error.code.is_retryable());
    assert_eq!(provider.received().len(), 2);
}

#[tokio::test]
async fn concurrent_streams_are_limited() {
    let provider = MockProvider::plain().await;
    let options = Options {
        limits: "max_concurrent_streams = 1\n".to_owned(),
        ..Options::default()
    };
    let instance = start(Mode::Unix, options, &[&provider]).await;
    let token = instance
        .setup
        .seal("token", b"SEALCANARY-token", &token_policy(&provider))
        .await;
    let holding = instance
        .client
        .send(get(&url(&provider, "/stall"), &[("token", &token)]))
        .await
        .unwrap();
    let error = instance
        .client
        .send(get(&url(&provider, "/echo"), &[("token", &token)]))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    drop(holding);
    eventually(Duration::from_secs(5), || async {
        instance
            .client
            .send(get(&url(&provider, "/echo"), &[("token", &token)]))
            .await
            .is_ok()
    })
    .await;
}

// Health, metrics and startup.

#[tokio::test]
async fn health_metrics_and_readiness_are_served() {
    let provider = MockProvider::plain().await;
    let options = Options {
        metrics: true,
        ..Options::default()
    };
    let instance = start(Mode::Unix, options, &[&provider]).await;
    let token = instance
        .setup
        .seal("token", b"SEALCANARY-token", &token_policy(&provider))
        .await;
    text(
        instance
            .client
            .send(get(&url(&provider, "/echo"), &[("token", &token)]))
            .await
            .unwrap(),
    )
    .await;

    let logs = instance.logs();
    let address = logs
        .lines()
        .find(|line| line.contains("serving metrics"))
        .and_then(|line| line.split("address=").nth(1))
        .map(|rest| rest.split_whitespace().next().unwrap().to_owned())
        .unwrap();
    let fetch = |path: &str| {
        let output = Command::new("curl")
            .args(["-s", "-o", "-", "-w", "\n%{http_code}"])
            .arg(format!("http://{address}{path}"))
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    };
    assert!(fetch("/healthz").ends_with("200"));
    assert!(fetch("/readyz").ends_with("200"));
    let metrics = fetch("/metrics");
    assert!(metrics.ends_with("200"));
    assert!(metrics.contains("seal_keyring"), "{metrics}");
    assert!(!metrics.contains("acme"), "metrics carry no keyset names");
}

#[test]
fn startup_refuses_a_memory_ceiling_over_the_budget_and_check_config_explains() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let setup = runtime.block_on(Setup::new(None));
    let options = Options {
        limits: "memory_budget = \"64MiB\"\n".to_owned(),
        ..Options::default()
    };
    let config = write_config(
        &setup,
        &setup.config_text(
            Mode::Unix,
            &options,
            "[listen]\nunix = \"/tmp/unused.sock\"\n",
        ),
    );

    let check = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["check-config", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!check.status.success());
    let printed = String::from_utf8_lossy(&check.stdout);
    assert!(
        printed.contains("streams") && printed.contains("over the budget"),
        "{printed}"
    );

    let serve = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["serve", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!serve.status.success());
    assert!(String::from_utf8_lossy(&serve.stderr).contains("memory ceiling"));

    let good = write_config(
        &setup,
        &setup.config_text(
            Mode::Unix,
            &Options::default(),
            "[listen]\nunix = \"/tmp/unused.sock\"\n",
        ),
    );
    let check = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["check-config", "--config"])
        .arg(&good)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stdout)
    );
}

#[cfg(unix)]
#[test]
fn a_configuration_others_can_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let setup = runtime.block_on(Setup::new(None));
    let config = write_config(
        &setup,
        &setup.config_text(
            Mode::Unix,
            &Options::default(),
            "[listen]\nunix = \"/tmp/x.sock\"\n",
        ),
    );
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["check-config", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("writable by its group or others"));
}

#[test]
fn keygen_makes_wrapping_keys_and_keysets_and_version_prints() {
    let directory = tempfile::tempdir().unwrap();
    let kek = directory.path().join("kek");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_seal"))
            .args(args)
            .output()
            .unwrap()
    };
    let made = run(&["keygen", "--wrapping-key", kek.to_str().unwrap()]);
    assert!(made.status.success());
    assert!(
        !run(&["keygen", "--wrapping-key", kek.to_str().unwrap()])
            .status
            .success(),
        "never replaced"
    );

    let version = run(&["version"]);
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("seal "));
}
