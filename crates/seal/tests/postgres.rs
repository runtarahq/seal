//! Postgres sessions through seal against real servers, versions 14 to 18, in all three
//! modes, with `tokio-postgres` as the application's client. They need Docker, so they
//! are ignored by default; CI's container job runs them with `--ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt, TryStreamExt};
use seal_client::{ConnectRequest, Mode};
use seal_format::{Envelope, Policy};
use seal_testkit::containers::{self, Container, PostgresSetup};
use seal_testkit::pki::{Issued, TestPki};
use serde_json::{Value, json};
use support::*;
use tokio_postgres::error::SqlState;
use tokio_postgres::{AsyncMessage, Client};

/// One test per Postgres version and mode.
macro_rules! version_matrix {
    ($($name:ident => $version:expr;)*) => {$(
        mod $name {
            use super::*;

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            #[ignore = "needs Docker"]
            async fn in_process() {
                scenario($version, Mode::InProcess).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            #[ignore = "needs Docker"]
            async fn unix() {
                scenario($version, Mode::Unix).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            #[ignore = "needs Docker"]
            async fn mtls() {
                scenario($version, Mode::Mtls).await;
            }
        }
    )*};
}

version_matrix! {
    postgres_14 => 14;
    postgres_15 => 15;
    postgres_16 => 16;
    postgres_17 => 17;
    postgres_18 => 18;
}

const HBA: &str = "local all all trust
hostssl all cert_user all cert
hostssl all md5_user all md5
hostssl all clear_user all password
hostssl replication repl_user all scram-sha-256
hostssl all all all scram-sha-256
";

const INIT_SQL: &str = "CREATE USER app_user PASSWORD 'app-secret';
CREATE DATABASE app OWNER app_user;
CREATE DATABASE other;
CREATE USER cert_user;
SET password_encryption = 'md5';
CREATE USER md5_user PASSWORD 'md5-secret';
RESET password_encryption;
CREATE USER clear_user PASSWORD 'clear-secret';
CREATE USER repl_user REPLICATION PASSWORD 'repl-secret';
";

struct Database {
    _container: Container,
    port: u16,
    server_ca: String,
    clients: TestPki,
}

async fn database(version: u32) -> Database {
    let server_pki = TestPki::new("db server CA");
    let server = server_pki.server(&[HOST]);
    let clients = TestPki::new("db client CA");
    let container = containers::postgres(
        version,
        &PostgresSetup {
            server_cert_pem: &server.cert_pem,
            server_key_pem: &server.key_pem,
            client_ca_pem: &clients.ca_pem,
            hba: HBA,
            init_sql: INIT_SQL,
        },
    )
    .await
    .unwrap_or_else(|| panic!("Postgres {version} starts"));
    let port = container.port(5432).unwrap();
    Database {
        _container: container,
        port,
        server_ca: server_pki.ca_pem,
        clients,
    }
}

impl Database {
    fn policy(&self, user: &str, inject: Value) -> Policy {
        policy(&json!({ "rules": [{
            "destination": {
                "scheme": "postgres", "host": HOST, "port": self.port,
                "databases": ["app"], "user": { "literal": user },
                "tls": { "ca": self.server_ca },
            },
            "inject": inject,
        }] }))
    }

    fn request(&self, field_name: &str, value: &Envelope) -> ConnectRequest {
        ConnectRequest {
            keyset: keyset(),
            item: item(),
            sealed: BTreeMap::from([(field(field_name), value.clone().into())]),
            plain: BTreeMap::new(),
            host: HOST.to_owned(),
            port: self.port,
        }
    }
}

/// A session as `tokio-postgres` makes one, with no TLS and no password. Notifications
/// come out of the returned channel.
async fn session(
    instance: &Instance,
    request: ConnectRequest,
    user: &str,
    dbname: &str,
) -> Result<(Client, tokio::sync::mpsc::UnboundedReceiver<String>), tokio_postgres::Error> {
    let stream = instance.client.connect_pg(request).await.unwrap();
    let (client, mut connection) = tokio_postgres::Config::new()
        .user(user)
        .dbname(dbname)
        .connect_raw(stream, tokio_postgres::NoTls)
        .await?;
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut messages = futures_util::stream::poll_fn(move |cx| connection.poll_message(cx));
        while let Some(Ok(message)) = messages.next().await {
            if let AsyncMessage::Notification(notification) = message {
                let _ = sender.send(notification.payload().to_owned());
            }
        }
    });
    Ok((client, receiver))
}

/// Runs `IDENTIFY_SYSTEM` in a replication session, speaking the protocol directly, since
/// `tokio-postgres` cannot ask for replication. Returns the system identifier, or the
/// SQLSTATE of an error.
async fn identify_system(
    instance: &Instance,
    request: ConnectRequest,
    replication: &str,
) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = instance.client.connect_pg(request).await.unwrap();
    let mut body = (3_u32 << 16).to_be_bytes().to_vec();
    for (name, value) in [
        ("user", "repl_user"),
        ("database", "app"),
        ("replication", replication),
    ] {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut startup = u32::try_from(body.len() + 4)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    startup.extend_from_slice(&body);
    stream.write_all(&startup).await.unwrap();

    async fn message(stream: &mut seal_client::PgStream) -> (u8, Vec<u8>) {
        let tag = stream.read_u8().await.unwrap();
        let length = stream.read_u32().await.unwrap();
        let mut body = vec![0; length as usize - 4];
        stream.read_exact(&mut body).await.unwrap();
        (tag, body)
    }
    fn sqlstate(body: &[u8]) -> String {
        body.split(|byte| *byte == 0)
            .find_map(|field| field.strip_prefix(b"C"))
            .map(|code| String::from_utf8_lossy(code).into_owned())
            .unwrap_or_default()
    }
    loop {
        match message(&mut stream).await {
            (b'Z', _) => break,
            (b'E', body) => return Err(sqlstate(&body)),
            _ => {}
        }
    }
    let mut query = vec![b'Q'];
    let text = b"IDENTIFY_SYSTEM\0";
    query.extend_from_slice(&u32::try_from(text.len() + 4).unwrap().to_be_bytes());
    query.extend_from_slice(text);
    stream.write_all(&query).await.unwrap();
    let mut system_id = None;
    loop {
        match message(&mut stream).await {
            (b'D', body) => {
                // A column count, then each column's length and value: the first is the
                // system identifier.
                let length = u32::from_be_bytes([body[2], body[3], body[4], body[5]]) as usize;
                system_id = Some(String::from_utf8(body[6..6 + length].to_vec()).unwrap());
            }
            (b'E', body) => return Err(sqlstate(&body)),
            (b'Z', _) => return system_id.ok_or_else(|| "no row".to_owned()),
            _ => {}
        }
    }
}

fn code(error: &tokio_postgres::Error) -> Option<SqlState> {
    error.code().cloned()
}

/// How many audit records there are, to find what comes after.
fn records(instance: &Instance) -> usize {
    instance.setup.audit_records().len()
}

/// The audit record of a session after `after` records that logged in by `method`,
/// waiting for it, since a session audits itself when it ends. Another session ending
/// meanwhile may have written its record first.
async fn session_record(instance: &Instance, after: usize, method: &str) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let found = instance
            .setup
            .audit_records()
            .into_iter()
            .skip(after)
            .find(|record| record["op"] == "connect" && record["pg_auth"] == method);
        if let Some(record) = found {
            return record;
        }
        assert!(tokio::time::Instant::now() < deadline, "no session record");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn scenario(version: u32, mode: Mode) {
    let db = database(version).await;
    let instance = start(mode, Options::default(), &[]).await;
    let setup = &instance.setup;

    // SCRAM with channel binding, and an ordinary session's work.
    let password = setup
        .seal(
            "password",
            b"app-secret",
            &db.policy("app_user", json!({ "pg_password": {} })),
        )
        .await;
    let mark = records(&instance);
    let (client, mut notifications) = session(
        &instance,
        db.request("password", &password),
        "app_user",
        "app",
    )
    .await
    .unwrap_or_else(|error| panic!("Postgres {version}: {error:?}"));
    client
        .batch_execute("CREATE TABLE t (id int, v text)")
        .await
        .unwrap();
    let mut client = client;
    let transaction = client.transaction().await.unwrap();
    transaction
        .execute("INSERT INTO t VALUES (1, 'gone')", &[])
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    client
        .execute("INSERT INTO t VALUES ($1, $2)", &[&2_i32, &"kept"])
        .await
        .unwrap();
    let count: i64 = client
        .query_one("SELECT count(*) FROM t", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);

    client.batch_execute("LISTEN seal_channel").await.unwrap();
    client
        .batch_execute("NOTIFY seal_channel, 'hello'")
        .await
        .unwrap();
    let payload = tokio::time::timeout(Duration::from_secs(5), notifications.recv())
        .await
        .unwrap();
    assert_eq!(payload.as_deref(), Some("hello"));

    let sink = client.copy_in("COPY t FROM STDIN").await.unwrap();
    futures_util::pin_mut!(sink);
    sink.send(bytes::Bytes::from_static(b"3\tcopied\n4\tcopied\n"))
        .await
        .unwrap();
    assert_eq!(sink.finish().await.unwrap(), 2);
    let copied: Vec<u8> = client
        .copy_out("COPY (SELECT id FROM t ORDER BY id) TO STDOUT")
        .await
        .unwrap()
        .try_fold(Vec::new(), |mut all, chunk| async move {
            all.extend_from_slice(&chunk);
            Ok(all)
        })
        .await
        .unwrap();
    assert_eq!(copied, b"2\n3\n4\n");
    drop(client);
    let record = session_record(&instance, mark, "scram-sha-256-plus").await;
    assert_eq!(
        record["pg_auth"], "scram-sha-256-plus",
        "Postgres {version}"
    );
    assert_eq!(record["path"], "app");

    // A wrong password is the server's refusal, with its SQLSTATE and none of its text.
    let wrong = setup
        .seal(
            "password",
            b"not-the-secret",
            &db.policy("app_user", json!({ "pg_password": {} })),
        )
        .await;
    let error = session(&instance, db.request("password", &wrong), "app_user", "app")
        .await
        .err()
        .unwrap();
    assert_eq!(code(&error), Some(SqlState::INVALID_PASSWORD));
    assert!(!format!("{error:?}").contains("app_user\""), "{error:?}");

    // A database the policy does not allow is refused by seal.
    let error = session(
        &instance,
        db.request("password", &password),
        "app_user",
        "other",
    )
    .await
    .err()
    .unwrap();
    assert_eq!(code(&error), Some(SqlState::INVALID_CATALOG_NAME));
    let error = session(
        &instance,
        db.request("password", &password),
        "postgres",
        "app",
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        code(&error),
        Some(SqlState::INVALID_AUTHORIZATION_SPECIFICATION)
    );

    // A cancel, through another seal instance.
    let other = start(
        mode,
        Options {
            keys_dir: Some(setup.keys_dir.clone()),
            ..Options::default()
        },
        &[],
    )
    .await;
    let (client, _) = session(
        &instance,
        db.request("password", &password),
        "app_user",
        "app",
    )
    .await
    .unwrap();
    let token = client.cancel_token();
    let sleeping = tokio::spawn(async move { client.batch_execute("SELECT pg_sleep(30)").await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    seal_client::cancel_pg(&*other.client, db.request("password", &password), &token)
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(10), sleeping)
        .await
        .expect("the query was cancelled")
        .unwrap()
        .unwrap_err();
    assert_eq!(code(&error), Some(SqlState::QUERY_CANCELED));

    // A client certificate alone.
    let issued: Issued = db.clients.client("cert_user");
    let key = setup
        .seal(
            "client_key",
            issued.key_pem.as_bytes(),
            &db.policy(
                "cert_user",
                json!({ "client_cert": { "cert": { "literal": issued.cert_pem } } }),
            ),
        )
        .await;
    let mark = records(&instance);
    let (client, _) = session(
        &instance,
        db.request("client_key", &key),
        "cert_user",
        "app",
    )
    .await
    .unwrap_or_else(|error| panic!("Postgres {version}, certificate: {error:?}"));
    let user: String = client
        .query_one("SELECT current_user::text", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(user, "cert_user");
    drop(client);
    assert_eq!(
        session_record(&instance, mark, "cert").await["outcome"],
        "ok"
    );

    // MD5 only where the rule allows it, and a cleartext password.
    let md5 = |allow: bool| db.policy("md5_user", json!({ "pg_password": { "allow_md5": allow } }));
    let refused = setup.seal("password", b"md5-secret", &md5(false)).await;
    let error = session(
        &instance,
        db.request("password", &refused),
        "md5_user",
        "app",
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        code(&error),
        Some(SqlState::INVALID_AUTHORIZATION_SPECIFICATION)
    );
    let allowed = setup.seal("password", b"md5-secret", &md5(true)).await;
    let mark = records(&instance);
    let (client, _) = session(
        &instance,
        db.request("password", &allowed),
        "md5_user",
        "app",
    )
    .await
    .unwrap();
    drop(client);
    assert_eq!(
        session_record(&instance, mark, "md5").await["outcome"],
        "ok"
    );
    let clear = setup
        .seal(
            "password",
            b"clear-secret",
            &db.policy(
                "clear_user",
                json!({ "pg_password": { "allow_cleartext_password": true } }),
            ),
        )
        .await;
    let mark = records(&instance);
    let (client, _) = session(
        &instance,
        db.request("password", &clear),
        "clear_user",
        "app",
    )
    .await
    .unwrap();
    drop(client);
    assert_eq!(
        session_record(&instance, mark, "cleartext").await["outcome"],
        "ok"
    );

    // Replication, logical and physical, where every rule allows it; refused otherwise.
    let replication = |allow: bool| {
        policy(&json!({ "rules": [{
            "destination": {
                "scheme": "postgres", "host": HOST, "port": db.port,
                "databases": ["app"], "user": { "literal": "repl_user" },
                "tls": { "ca": db.server_ca }, "allow_replication": allow,
            },
            "inject": { "pg_password": {} },
        }] }))
    };
    let allowed = setup
        .seal("password", b"repl-secret", &replication(true))
        .await;
    let system_id = identify_system(&instance, db.request("password", &allowed), "database")
        .await
        .unwrap_or_else(|state| panic!("Postgres {version}, logical replication: {state}"));
    assert!(
        !system_id.is_empty() && system_id.bytes().all(|b| b.is_ascii_digit()),
        "{system_id}"
    );
    let physical = identify_system(&instance, db.request("password", &allowed), "true")
        .await
        .unwrap_or_else(|state| panic!("Postgres {version}, physical replication: {state}"));
    assert_eq!(physical, system_id);
    let refused = setup
        .seal("password", b"repl-secret", &replication(false))
        .await;
    let state = identify_system(&instance, db.request("password", &refused), "database")
        .await
        .unwrap_err();
    assert_eq!(state, "28000");

    let mut registry = seal_testkit::canary::CanaryRegistry::new();
    for secret in ["app-secret", "md5-secret", "clear-secret", "repl-secret"] {
        registry.register(&seal_testkit::canary::Canary::from_value(secret));
    }
    assert!(registry.scan("logs", &instance.logs()).is_empty());
    let audit = std::fs::read_to_string(&setup.audit).unwrap_or_default();
    assert!(registry.scan("audit", &audit).is_empty());
}
