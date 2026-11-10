# seal: policies

A policy is the rules for where and how a secret may be used. It is sealed inside
the value, so neither seal nor the caller needs a registry, and a compromised
caller cannot change where an existing secret goes.

A test parses every `json` example here as a policy and checks that every option
appears, so this document cannot drift from the code.

Policies are refused, not corrected, if anything is unexpected: an unknown field or
kind, a host that is not normalised, a path that could mean something else. A policy
is limited to 16 rules (in each list), 8 definitions and 16 KiB in canonical form.

## Rules

A use of a secret must match one of `rules`. The first rule that matches is used.

```json
{
  "rules": [{
    "destination": { "scheme": "https", "host": "api.example.com", "port": 443, "path_prefix": "/v2/" },
    "methods": ["GET", "POST"],
    "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } }
  }]
}
```

**A rule's own secret is never named.** The value whose policy holds a rule is that
rule's secret. An injection names only the other parts of a credential, each as
`{ "field": "…" }` or `{ "literal": "…" }`.

| Option | Meaning |
|---|---|
| `destination` | Where the secret may go |
| `methods` | `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or `OPTIONS`. Any of them if absent. HTTP only. `CONNECT` and `TRACE` cannot be allowed |
| `inject` | How the secret is attached |
| `plain` | Plain fields the caller may supply as parts of the credential |
| `seal_response` | Response fields that are always sealed |
| `limits` | Tighter limits for this rule |
| `allow_private_destination` | See [Weakening options](#weakening-options) |
| `allow_plain_http` | See [Weakening options](#weakening-options) |

## Destinations

### HTTP

`scheme`, `host` and `port` are exact. `port` defaults by scheme.

- `host` is a DNS name or IP literal, already lowercase and IDNA-normalised, with no
  wildcards or trailing dot. Write `xn--bcher-kva.example`, not `bücher.example`.
- `path_prefix` starts with `/` and matches on segment boundaries. It may not have
  `.` or `..` segments, empty segments, or an encoded dot or separator (`%2e`, `%2f`,
  `%5c`).

### Postgres

```json
{
  "rules": [{
    "destination": {
      "scheme": "postgres", "host": "db.example.com", "port": 5432,
      "databases": ["app", "reports"],
      "user": { "literal": "app_user" },
      "tls": { "ca": "-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----" },
      "allow_replication": true
    },
    "inject": { "pg_password": {} }
  }]
}
```

| Option | Meaning |
|---|---|
| `databases` | The databases a session may use. At least one |
| `user` | The user a session logs in as |
| `tls` | `"verify_full"` (the default) checks the configured roots and the host name, or `{ "ca": "…" }` a specific CA in PEM |
| `allow_replication` | Allows a replication session. Off by default |

## Injections

### `header`

`format` has exactly one `{}`. A rule cannot inject into hop-by-hop headers, `Host`,
`Content-Length`, `Transfer-Encoding` or any `Proxy-*` header.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.example.com" },
  "inject": { "header": { "name": "X-Api-Key", "format": "{}" } }
}] }
```

### `basic`

The secret is the password.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.example.com" },
  "inject": { "basic": { "username": { "field": "username" } } },
  "plain": ["username"]
}] }
```

### `query`

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.example.com" },
  "inject": { "query": { "name": "api_key" } }
}] }
```

### `form_field`

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.example.com", "path_prefix": "/login" },
  "inject": { "form_field": { "name": "password" } }
}] }
```

### `json_field`

`pointer` is an RFC 6901 pointer, and nothing may already exist there.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.example.com" },
  "inject": { "json_field": { "pointer": "/auth/token" } }
}] }
```

### `client_cert`

The secret is the private key. Needs `https`, or a Postgres destination. `ca` and
`server_name` verify the provider; [`signing.md`](signing.md#client-certificates) has how
connections are pooled.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.example.com" },
  "inject": { "client_cert": {
    "cert": { "field": "cert" },
    "chain": { "field": "chain" },
    "ca": "-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----",
    "server_name": "internal.example.com"
  } },
  "plain": ["cert", "chain"]
}] }
```

### `aws_sigv4`

The secret is the secret access key. `payload` lists what is allowed from `computed`,
`caller_hash` and `streaming`; [`signing.md`](signing.md) explains how seal chooses
among them, and which headers a caller may not set.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "s3.eu-west-1.amazonaws.com" },
  "inject": { "aws_sigv4": {
    "region": "eu-west-1",
    "service": "s3",
    "access_key_id": { "field": "access_key_id" },
    "session_token": { "field": "session_token" },
    "payload": ["computed", "caller_hash", "streaming"],
    "allow_unsigned_payload": true
  } },
  "plain": ["access_key_id"]
}] }
```

`allow_headers` lets the caller set ACL, grant and copy headers, which are refused
otherwise. A copy source must be within the path prefix, which such a rule needs:

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "s3.eu-west-1.amazonaws.com", "path_prefix": "/tenant-a/" },
  "inject": { "aws_sigv4": {
    "region": "eu-west-1",
    "service": "s3",
    "access_key_id": { "literal": "AKIAIOSFODNN7EXAMPLE" },
    "payload": ["computed"],
    "allow_headers": ["x-amz-acl", "x-amz-copy-source"]
  } }
}] }
```

### `azure_shared_key`

The secret is the account key. `service` is `blob`, `queue`, `file` or `table`.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "account.blob.core.windows.net" },
  "inject": { "azure_shared_key": { "account": { "literal": "account" }, "service": "blob" } }
}] }
```

### `jwt_assertion`

The secret is the key that signs a short-lived JWT. The JWT goes only into the request,
never back to the caller, and only to this exact endpoint: `path_prefix` must be the
token endpoint's full path, with no trailing `/`.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "auth.example.com", "path_prefix": "/oauth/token" },
  "inject": { "jwt_assertion": {
    "alg": "RS256",
    "aud": { "value": "https://tenant.example.com/" },
    "claims": {
      "iss": "client-id",
      "sub": "client-id",
      "scope": "read",
      "extra": { "tenant": "acme" }
    },
    "header": { "typ": "JWT", "kid": "key-1", "x5t#S256": "thumbprint" },
    "form_field": "client_assertion",
    "max_lifetime_s": 300
  } }
}] }
```

| Option | Meaning |
|---|---|
| `alg` | `RS256`, `PS256` or `ES256` |
| `aud` | Required, with no default: `"token_endpoint"` for the destination's URL, or `{ "value": "…" }` for an exact string, sent byte for byte |
| `claims` | `iss` is required. `sub`, `scope` and `extra` are optional. seal sets `aud`, `iat`, `nbf`, `exp` and `jti`, so `extra` cannot use those names |
| `header` | Optional `typ` (default `JWT`), `kid` and `x5t#S256` |
| `form_field` | `client_assertion` for client authentication, `assertion` for the JWT bearer grant |
| `max_lifetime_s` | At most 300 |

Providers expect different audiences, so check each one's documentation: Google,
Microsoft Entra and Okta document the token endpoint or the URL being called, Auth0
its tenant URL with a trailing `/`, and Salesforce its login URL. A value's host need
not match the destination's.

### `pg_password`

SCRAM-SHA-256 is always allowed. The others only run over TLS.

```json
{ "rules": [{
  "destination": {
    "scheme": "postgres", "host": "db.example.com", "port": 5432,
    "databases": ["app"], "user": { "field": "user" }
  },
  "inject": { "pg_password": { "allow_md5": true, "allow_cleartext_password": true } },
  "plain": ["user"]
}] }
```

### `companion`

This value is not used directly. Another field's rule uses it at this destination, and
it may go nowhere else. A sealed session token could have this policy:

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "s3.eu-west-1.amazonaws.com" },
  "inject": { "companion": {} }
}] }
```

## Response sealing

A rule with `seal_response` always seals the named fields, and returns the response with
them replaced by sealed values. Without this in the policy, a compromised caller could use
a refresh token and read the new access token.

It protects the declared fields, at their declared locations. The same value anywhere else
in a response is not found or sealed, and seal does not stop a provider returning a
credential some other way.

`at` depends on `format`:

| `format` | `at` |
|---|---|
| `json` | An RFC 6901 pointer, such as `/access_token` |
| `form` | A key, such as `access_token` |
| `xml` | An element path from the root, such as `AssumeRoleResponse/AssumeRoleResult/Credentials/SecretAccessKey` |

An XML path names elements as written, prefix and all, and only the content of a matched
element changes. A document type declaration, a field that repeats or holds markup, or an
entity other than the predefined ones refuses the response, since seal could not be sure
where the token is.

Each field has a name for the new value (`as`) and names its policy in `definitions`. A new
value gets the rules of that definition, plus the same `definitions`:

```json
{
  "rules": [{
    "destination": { "scheme": "https", "host": "auth.example.com", "path_prefix": "/oauth/token" },
    "inject": { "form_field": { "name": "client_secret" } },
    "seal_response": {
      "format": "json",
      "fields": [
        { "at": "/access_token", "as": "access_token", "policy": "api" },
        { "at": "/refresh_token", "as": "refresh_token", "policy": "refresh" }
      ]
    }
  }],
  "definitions": {
    "api": { "rules": [{
      "destination": { "scheme": "https", "host": "api.example.com" },
      "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } }
    }] },
    "refresh": { "rules": [{
      "destination": { "scheme": "https", "host": "auth.example.com", "path_prefix": "/oauth/token" },
      "inject": { "form_field": { "name": "refresh_token" } },
      "seal_response": {
        "format": "json",
        "fields": [
          { "at": "/access_token", "as": "access_token", "policy": "api" },
          { "at": "/refresh_token", "as": "refresh_token", "policy": "refresh" }
        ]
      }
    }] }
  }
}
```

The refresh token's definition names itself, so each rotation produces a byte-identical
policy: rotations are unlimited, and the policy does not grow. Cycles are safe, because one
response seals its fields once.

An STS response, located by element path:

```json
{
  "rules": [{
    "destination": { "scheme": "https", "host": "sts.amazonaws.com" },
    "inject": { "aws_sigv4": {
      "region": "us-east-1", "service": "sts",
      "access_key_id": { "field": "access_key_id" }, "payload": ["computed"]
    } },
    "plain": ["access_key_id"],
    "seal_response": {
      "format": "xml",
      "fields": [{
        "at": "AssumeRoleResponse/AssumeRoleResult/Credentials/SessionToken",
        "as": "session_token",
        "policy": "session"
      }]
    }
  }],
  "definitions": {
    "session": { "rules": [{
      "destination": { "scheme": "https", "host": "s3.amazonaws.com" },
      "inject": { "companion": {} }
    }] }
  }
}
```

And a form-encoded one, for providers that respond that way:

```json
{
  "rules": [{
    "destination": { "scheme": "https", "host": "provider.example.com", "path_prefix": "/token" },
    "inject": { "form_field": { "name": "client_secret" } },
    "seal_response": {
      "format": "form",
      "fields": [{ "at": "access_token", "as": "access_token", "policy": "api" }]
    }
  }],
  "definitions": {
    "api": { "rules": [{
      "destination": { "scheme": "https", "host": "api.provider.example.com" },
      "inject": { "header": { "name": "Authorization", "format": "token {}" } }
    }] }
  }
}
```

## Shared values

A value is normally usable only with requests for the record it is bound to. A platform's
credential, such as the client secret of an OAuth app every tenant uses, is sealed once and
marked `shared`, so that it can be presented with any tenant's request. Only its sealer
decides this: a value sealed from a response is never shared, so a tenant's tokens stay
with the tenant's record.

A shared credential should also say which uses are allowed. `require_form` makes seal check
the caller's form body before sending: each listed field must appear exactly once, with one
of the listed values. Here a shared client secret may only be used for the grants that act
for a user who consented, never for `client_credentials`, which would act as the app
itself.

```json
{
  "rules": [{
    "destination": { "scheme": "https", "host": "auth.example.com", "path_prefix": "/oauth/token" },
    "inject": { "form_field": { "name": "client_secret" } },
    "require_form": { "grant_type": ["authorization_code", "refresh_token"] }
  }],
  "shared": true
}
```

The builder's `oauth_client` does this when `shared` is set, and refuses to share a JWT
bearer grant key, since that grant acts as the key's owner.

## Limits

Each limit can only tighten the global limit of the same name, so a sealed policy can never
raise seal's memory ceiling. None may be zero.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.example.com" },
  "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } },
  "limits": {
    "buffer_cap_bytes": 65536,
    "idle_timeout_s": 30,
    "connect_timeout_s": 5,
    "first_byte_timeout_s": 30,
    "buffered_total_timeout_s": 30,
    "max_stream_duration_s": 3600,
    "pg_max_session_s": 3600
  }
}] }
```

## Weakening options

Options that weaken a guarantee are named for it, and are off by default.

| Option | On | Effect |
|---|---|---|
| `allow_private_destination` | A rule | Allows an internal address (loopback, RFC 1918, CGNAT, unique-local), if the deployment's configuration also permits it, and every value presented with this one sets it too. Never a link-local or metadata address |
| `allow_plain_http` | A rule | Allows plain HTTP. Required for scheme `http`, and invalid otherwise |
| `allow_unsigned_payload` | `aws_sigv4` | Allows `UNSIGNED-PAYLOAD` |
| `allow_headers` | `aws_sigv4` | Lets the caller set ACL, grant or copy headers |
| `allow_md5` | `pg_password` | Allows MD5 authentication |
| `allow_cleartext_password` | `pg_password` | Allows a cleartext password |
| `allow_replication` | A Postgres destination | Allows a replication session |

```json
{ "rules": [{
  "destination": { "scheme": "http", "host": "10.0.0.5", "port": 8080 },
  "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } },
  "allow_private_destination": true,
  "allow_plain_http": true
}] }
```

## The builder

`seal_format::policy::builder` produces correct policies for the common cases, with companion
rules generated. It accepts `https` endpoints only, so a weakening option has to be written out
where it is used.

| Function | Produces |
|---|---|
| `bearer(api_base)` | A bearer token for an API |
| `api_key_header(api_base, name)` | An API key in a header |
| `basic(api_base, username)` | A password for basic auth |
| `oauth_client(config)` | Policies for an OAuth client secret or signing key, and for a password. Its tokens are limited to where they belong, and its refresh token's definition names itself |
| `aws(region, service, endpoint, access_key_id, session_token, payload)` | A secret access key |
| `azure(account, service, endpoint)` | An account key |
| `client_cert(api_base, cert, chain)` | A client certificate's private key |
| `postgres(host, port, databases, user)` | A Postgres password, with SCRAM only and the server verified |

A part of a composite credential comes from a `PartSource`: `Literal` fixes it in the policy,
`Plain` lists it in `plain`, and `Sealed` generates a companion policy for that field, returned
in `companions`.
