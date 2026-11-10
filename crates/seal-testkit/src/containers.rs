//! Providers in containers, run with the `docker` command: RustFS for S3 and Azurite
//! for Azure Storage. Each container is removed when its handle is dropped.
//!
//! Images are pinned by digest. Tests that need them are ignored by default and run
//! in CI's container job, or with `cargo test -- --ignored` where Docker is running.

use std::process::{Command, Stdio};
use std::time::Duration;

/// RustFS, an S3-compatible object store.
pub const RUSTFS_IMAGE: &str =
    "rustfs/rustfs@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2";

/// Azurite, Microsoft's Azure Storage emulator.
pub const AZURITE_IMAGE: &str = "mcr.microsoft.com/azure-storage/azurite@sha256:830430c1da1a2d537e08f3e6764dd1f5ae00cf0346bcaf625b968ec3f0971fd5";

/// The access key RustFS is started with.
pub const RUSTFS_ACCESS_KEY: &str = "sealtest";

/// The secret key RustFS is started with.
pub const RUSTFS_SECRET_KEY: &str = "sealtest-secret-key";

/// Azurite's well-known development account.
pub const AZURITE_ACCOUNT: &str = "devstoreaccount1";

/// Azurite's well-known development key.
pub const AZURITE_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

/// A running container.
pub struct Container {
    id: String,
    ports: Vec<(u16, u16)>,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            // With its anonymous volumes: database and object store images declare
            // them, and they would otherwise outlive the container.
            .args(["rm", "-f", "-v", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Whether a Docker daemon answers.
#[must_use]
pub fn docker_available() -> bool {
    Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

impl Container {
    /// Starts `image`, publishing each port on a free loopback port. `None` if it
    /// cannot be started.
    #[must_use]
    pub fn start(image: &str, ports: &[u16], env: &[(&str, &str)], args: &[&str]) -> Option<Self> {
        let mut command = Command::new("docker");
        command.args(["run", "-d", "--rm"]);
        for port in ports {
            command.args(["-p", &format!("127.0.0.1::{port}")]);
        }
        for (name, value) in env {
            command.args(["-e", &format!("{name}={value}")]);
        }
        command.arg(image).args(args);
        let output = command.stderr(Stdio::null()).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let id = String::from_utf8(output.stdout).ok()?.trim().to_owned();
        let mut container = Self {
            id,
            ports: Vec::new(),
        };
        for port in ports {
            let output = Command::new("docker")
                .args(["port", &container.id, &port.to_string()])
                .output()
                .ok()?;
            let text = String::from_utf8(output.stdout).ok()?;
            let published = text
                .lines()
                .find_map(|line| line.strip_prefix("127.0.0.1:"))
                .and_then(|port| port.trim().parse().ok())?;
            container.ports.push((*port, published));
        }
        Some(container)
    }

    /// The loopback port a container port is published on.
    #[must_use]
    pub fn port(&self, inner: u16) -> Option<u16> {
        self.ports
            .iter()
            .find(|(port, _)| *port == inner)
            .map(|(_, published)| *published)
    }

    /// Waits until each published port answers `method path` with a response that
    /// contains `expected`.
    pub async fn wait_until_ready(
        &self,
        method: &str,
        path: &str,
        expected: &str,
        within: Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        for (_, published) in &self.ports {
            loop {
                if answers_http(*published, method, path)
                    .await
                    .is_some_and(|response| response.contains(expected))
                {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        true
    }
}

/// The whole response to `method path`, if one comes.
async fn answers_http(port: u16, method: &str, path: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .ok()?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .ok()?
        .ok()?;
    String::from_utf8(response).ok()
}

/// RustFS, started with [`RUSTFS_ACCESS_KEY`] and [`RUSTFS_SECRET_KEY`], on port 9000.
pub async fn rustfs() -> Option<Container> {
    let container = Container::start(
        RUSTFS_IMAGE,
        &[9000],
        &[
            ("RUSTFS_ACCESS_KEY", RUSTFS_ACCESS_KEY),
            ("RUSTFS_SECRET_KEY", RUSTFS_SECRET_KEY),
        ],
        &[],
    )?;
    // RustFS answers before it can write. An anonymous write is refused for its
    // credentials only once it could be carried out.
    container
        .wait_until_ready("PUT", "/readiness", "AccessDenied", Duration::from_secs(60))
        .await
        .then_some(container)
}

/// Azurite with Blob on 10000, Queue on 10001 and Table on 10002.
pub async fn azurite() -> Option<Container> {
    let container = Container::start(
        AZURITE_IMAGE,
        &[10000, 10001, 10002],
        &[],
        &[
            "azurite",
            "--blobHost",
            "0.0.0.0",
            "--queueHost",
            "0.0.0.0",
            "--tableHost",
            "0.0.0.0",
            "--loose",
        ],
    )?;
    container
        .wait_until_ready("GET", "/", "HTTP/1.1", Duration::from_secs(60))
        .await
        .then_some(container)
}

/// Postgres images, by major version, pinned by digest.
pub const POSTGRES_IMAGES: &[(u32, &str)] = &[
    (
        14,
        "postgres@sha256:b084304744d27cbc34513a1d2916129bd6a33383fa17b79b9a9030a950f14870",
    ),
    (
        15,
        "postgres@sha256:aae6554de426ae1990f1a939ff183a0299146cf7142a6f4c379c3357af9cc2d8",
    ),
    (
        16,
        "postgres@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139",
    ),
    (
        17,
        "postgres@sha256:3540c0362c809df084ffac0ae69fe794515f9de92692f02178bcdce0ef0302ac",
    ),
    (
        18,
        "postgres@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395",
    ),
];

/// How a Postgres container is set up: its TLS certificate, the CA its clients'
/// certificates come from, `pg_hba.conf`, and SQL run once at start.
pub struct PostgresSetup<'a> {
    /// The server's certificate, in PEM.
    pub server_cert_pem: &'a str,
    /// The server's private key, in PEM.
    pub server_key_pem: &'a str,
    /// The CA for client certificates, in PEM.
    pub client_ca_pem: &'a str,
    /// `pg_hba.conf`.
    pub hba: &'a str,
    /// SQL run as the superuser when the database is created.
    pub init_sql: &'a str,
}

/// Writes the files from the environment, owned by `postgres`, and starts the server
/// with TLS and the given `pg_hba.conf`.
const POSTGRES_START: &str = r#"set -e
mkdir -p /certs
printf '%s' "$SERVER_CERT" > /certs/server.crt
printf '%s' "$SERVER_KEY" > /certs/server.key
printf '%s' "$CLIENT_CA" > /certs/ca.crt
printf '%s' "$HBA" > /certs/pg_hba.conf
printf '%s' "$INIT_SQL" > /docker-entrypoint-initdb.d/seal.sql
chown -R postgres:postgres /certs
chmod 600 /certs/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/certs/server.crt \
  -c ssl_key_file=/certs/server.key -c ssl_ca_file=/certs/ca.crt -c hba_file=/certs/pg_hba.conf
"#;

/// Postgres of a major version on port 5432, with TLS. Ready once it answers an
/// `SSLRequest` over TCP, which it does only after its setup has run.
pub async fn postgres(version: u32, setup: &PostgresSetup<'_>) -> Option<Container> {
    let image = POSTGRES_IMAGES
        .iter()
        .find(|(major, _)| *major == version)
        .map(|(_, image)| *image)?;
    let container = Container::start(
        image,
        &[5432],
        &[
            ("POSTGRES_PASSWORD", "postgres-superuser-secret"),
            ("SERVER_CERT", setup.server_cert_pem),
            ("SERVER_KEY", setup.server_key_pem),
            ("CLIENT_CA", setup.client_ca_pem),
            ("HBA", setup.hba),
            ("INIT_SQL", setup.init_sql),
        ],
        &["sh", "-c", POSTGRES_START],
    )?;
    let port = container.port(5432)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while tokio::time::Instant::now() < deadline {
        if offers_tls(port).await {
            return Some(container);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

async fn offers_tls(port: u16) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(mut stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
        return false;
    };
    if stream
        .write_all(&[0, 0, 0, 8, 4, 210, 22, 47])
        .await
        .is_err()
    {
        return false;
    }
    let mut answer = [0; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut answer)).await,
        Ok(Ok(_))
    ) && answer[0] == b'S'
}
