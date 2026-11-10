# seal: Postgres sessions

How an application uses a sealed Postgres credential. seal logs in to the database, then
relays the session without reading it. The application gets a working session and never
the password.

## Using a session

The application opens a session with `connect_pg`, naming the server and presenting the
sealed values. It then speaks Postgres over the returned stream with `tokio-postgres`,
with no TLS and no password. The leg to seal is already protected (in-process, a Unix
socket, or mutual TLS), and seal does the login.

```rust
let stream = client
    .connect_pg(ConnectRequest {
        keyset,
        item,
        sealed: BTreeMap::from([(FieldName::new("password")?, sealed_password.into())]),
        plain: BTreeMap::new(),
        host: "db.example.com".to_owned(),
        port: 5432,
    })
    .await?;
let (client, connection) = tokio_postgres::Config::new()
    .user("app_user")
    .dbname("app")
    .connect_raw(stream, tokio_postgres::NoTls)
    .await?;
tokio::spawn(connection);
```

Everything a session does works as usual: queries, transactions, `COPY` in and out, and
`LISTEN` and `NOTIFY`. Once the login is over, seal reads nothing.

To cancel a query, `seal_client::cancel_pg` (feature `postgres`) sends the session's
cancel token through seal with the same sealed values. Cancels are stateless: seal opens
a new connection to the server and forwards the request. It keeps no session table, so
the cancel may go through any seal instance.

## The policy

A Postgres destination names the host and port exactly, the databases a session may use,
the user, and how the server's certificate is checked. [`policy.md`](policy.md#postgres)
has every option.

```json
{ "rules": [{
  "destination": {
    "scheme": "postgres", "host": "db.example.com", "port": 5432,
    "databases": ["app"], "user": { "literal": "app_user" },
    "tls": "verify_full"
  },
  "inject": { "pg_password": {} }
}] }
```

The builder makes this: `builder::postgres(host, port, databases, user)`.

A session's startup must name the policy's user, and a database the policy allows: a
missing `database` means the user's name, as in Postgres. Replication is refused unless
every matched rule allows it. The caller's other startup parameters, such as
`application_name`, go to the server as they are.

The user can be a literal, a plain field the rule lists, or a sealed companion. A
password and a client certificate may be presented together. The rules must then agree
on the user and on TLS, and a session may use only the databases both allow.

## The login

1. seal connects to an address it has checked, like any destination. A private address
   needs `allow_private_destination` and an operator who honours it.
2. It sends `SSLRequest`, and refuses a server that does not offer TLS. It reads exactly
   the one-byte answer before the handshake, so nothing unprotected can be slipped in.
3. TLS verifies the server against the configured roots, or the rule's CA, and the host
   name, with ALPN `postgresql`. A client certificate goes here, if one was presented.
4. seal sends the startup, then logs in with what the server asks for:

   | The server asks for | seal | Allowed |
   |---|---|---|
   | `SCRAM-SHA-256-PLUS` | SCRAM with `tls-server-end-point` channel binding | Always |
   | `SCRAM-SHA-256` | SCRAM, telling the server whether it could have bound | Always |
   | MD5 | The MD5 response | Only with `allow_md5` |
   | A cleartext password | The password, over TLS | Only with `allow_cleartext_password` |
   | Nothing | — | Only when the rule presents no password: with a client certificate (`cert` in `pg_hba.conf`), or `trust` |
   | Anything else | Fails with `PG_AUTH_FAILED` | Never |

   SCRAM checks the server's signature as well, so a server that does not know the
   password cannot pass as the real one. Channel binding ties the login to this TLS
   connection. With `require_channel_binding`, a login that would not be bound is
   refused before anything derived from the password is sent: one to a server that
   does not offer `SCRAM-SHA-256-PLUS`, or whose certificate has no hash to bind to.
   A server that accepts the login without asking for the password the
   rule presents has proved nothing, and the login fails with `PG_AUTH_FAILED`.
5. On success seal sends the application `AuthenticationOk`. From then on it relays.

The audit record names how each session logged in, in `pg_auth`: `scram-sha-256-plus`,
`scram-sha-256`, `md5`, `cleartext`, `cert` or `trust`.

## Errors

A refusal that needs no network, such as a server the policy does not name, makes
`connect_pg` itself fail. The application sees a `SealError`, and no connection is made.

Anything refused during the login reaches the application as a Postgres error, so
`tokio-postgres` reports it as usual:

| Cause | SQLSTATE |
|---|---|
| Another user | `28000` |
| A database the policy does not allow | `3D000` |
| Replication, where not allowed | `28000` |
| A method the rule does not allow | `28000` |
| The server refused the login | The server's own, such as `28P01` |
| The server cannot be reached, or fails TLS | `08001` |

seal keeps only the server's SQLSTATE and replaces its message with "authentication
failed", since a server's message can name users or more.

## Limits

A session ends when nothing moves for the idle timeout, or at `pg_max_session` (default
8 hours), whichever comes first. A rule can shorten either. Its bytes each way go in the
audit record. Each session holds one of `max_concurrent_streams` and one provider
connection.

## Tested against

Postgres 14, 15, 16, 17 and 18, in all three modes, with `tokio-postgres`
(`crates/seal/tests/postgres.rs`):

- SCRAM with channel binding, a client certificate, MD5 and cleartext;
- queries, transactions, `LISTEN`/`NOTIFY` and `COPY` both ways;
- a wrong password, and a user or database the policy does not allow;
- a `pg_sleep` cancelled through another seal instance;
- logical and physical replication sessions running `IDENTIFY_SYSTEM` where the rule
  allows replication, and refused where it does not.

A nightly test copies 1 GB in and out within the memory limit.
