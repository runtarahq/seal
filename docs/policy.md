# seal: policies

A policy is the rules for where and how a secret may be used. It is sealed inside
the value, so neither seal nor the caller needs a registry, and a compromised
caller cannot change where an existing secret goes.

A test parses every `json` example here as a policy and checks that every option
appears, so this document cannot drift from the code.

Policies are refused, not corrected, if anything is unexpected: an unknown field or
kind, a host that is not normalised, a path that could mean something else. A policy
is limited to 16 rules (in each list), 8 definitions and 16 KiB in canonical form.

Besides `rules`, a policy may have `definitions` ([Response sealing](#response-sealing)),
`shared` ([Shared values](#shared-values)) and `verify` ([Verification](#verification)).

## Rules

A request that uses a secret must match one of `rules`. The first rule that matches is
used. A secret that is only checked against, never sent, has [`verify`](#verification)
instead.

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
| `allow_injected_path` | See [Weakening options](#weakening-options) |

## Destinations

### HTTP

`scheme` and `port` are exact, and so is `host` unless it is a pattern. `port` defaults by
scheme.

- `host` is a DNS name or IP literal, already lowercase and IDNA-normalised, with no
  trailing dot. Write `xn--bcher-kva.example`, not `bücher.example`.
- `host` may instead be a pattern, `*.` and a domain of at least two labels, for a
  provider whose API is on many hosts. See [Host patterns](#host-patterns).
- `path_prefix` starts with `/` and matches on segment boundaries. It may not have
  `.` or `..` segments, empty segments, or an encoded dot or separator (`%2e`, `%2f`,
  `%5c`).

### Host patterns

Some providers serve one API from many hosts, named per region or per tenant, and tell
the application which to call. A pattern allows every name under one domain:

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "*.smba.trafficmanager.net" },
  "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } }
}] }
```

It matches a host that ends with the domain on a label boundary, with one label or
several before it: `emea.smba.trafficmanager.net` and `a.b.smba.trafficmanager.net`, but
not `smba.trafficmanager.net` itself, which needs a rule of its own, and not
`evilsmba.trafficmanager.net`. The `*` only leads, as a whole label; `*.com` and a
pattern under an IP literal are refused. TLS still verifies the certificate against the
host the request named.

A pattern sends the secret to whoever can serve a name under the domain. Use one only
for a domain whose every name is the provider's: not one where customers get names of
their own, such as a hosting or storage domain, where anyone could register a name and
ask for the credential. A Postgres destination, a `jwt_assertion` rule and a client
certificate's `server_name` take one host and no pattern.

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

### `path`

For an API that takes its credential in the URL's path, such as Telegram's
`/bot<token>/sendMessage`. `prefix` goes before the caller's path, with exactly one `{}`
for the secret: whole segments, starting with `/` and not ending with one. The caller
names the URL without it, here `https://api.telegram.org/sendMessage`, and that is the
path a `path_prefix` matches and the audit record holds. A `path_prefix` therefore
bounds what follows the injected prefix, not the whole path sent: with a prefix of
`/bot{}` and a `path_prefix` of `/send`, requests go to `/bot<token>/send…`.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.telegram.org" },
  "inject": { "path": { "prefix": "/bot{}" } }
}] }
```

The secret is percent-encoded, so it cannot add a segment or end the path, and one that
would make a `.` or `..` segment is refused. A response header that repeats it as written
in the path, such as a redirect's `Location`, is dropped.

A path injection changes where the request goes after every rule matched the caller's
path, and anyone can seal a value with one. So another sealed value may be presented
with it only if that value's own rule allows exactly this prefix, with
`allow_injected_path`. Telegram's `setWebhook` takes the bot token in the path and the
webhook's `secret_token` in the body:

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.telegram.org", "path_prefix": "/setWebhook" },
  "methods": ["POST"],
  "inject": { "form_field": { "name": "secret_token" } },
  "allow_injected_path": "/bot{}",
  "require_form": { "url": ["https://app.example.com/telegram"] }
}], "verify": "equals" }
```

The rule's `path_prefix` still bounds what follows the injected prefix. What fills the
prefix is whichever value is presented, which may be another bot's token, so the rule
must be safe for any of them: here `require_form` holds the webhook to one URL, since
Telegram sends the secret to whatever URL is registered.

### `form_field`

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "api.example.com", "path_prefix": "/login" },
  "inject": { "form_field": { "name": "password" } }
}] }
```

### `json_field`

`pointer` is an RFC 6901 pointer, and nothing may already exist there. The body must be
a JSON object. Everything else in it is sent as the caller wrote it, digit for digit;
only the objects on the way to the pointer are written again, compactly and in key order.

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

A rule for a whole endpoint has no path prefix to hold a copy's source to. Where the
endpoint is addressed by path, so that its host is every bucket's,
`allow_copy_from_any_bucket` lets a copy read any object there. It is a
[weakening option](#weakening-options), and wrong for a host that is one bucket's, as
with virtual-hosted URLs: a copy could then read the others.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "storage.example.com" },
  "inject": { "aws_sigv4": {
    "region": "us-east-1",
    "service": "s3",
    "access_key_id": { "literal": "AKIAIOSFODNN7EXAMPLE" },
    "payload": ["computed"],
    "allow_headers": ["x-amz-copy-source"],
    "allow_copy_from_any_bucket": true
  } }
}] }
```

`region` and `service` are usually fixed, so that a signature is good for one service in
one region. A credential used for whatever service each request is for, such as one an
agent uses across an account, has them named by the caller instead: each is then a plain
field the rule lists, with the values `allowed` if they can be listed.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "*.amazonaws.com" },
  "inject": { "aws_sigv4": {
    "region": { "field": "aws_region", "allowed": ["eu-west-1", "us-east-1"] },
    "service": { "field": "aws_service" },
    "access_key_id": { "literal": "AKIAIOSFODNN7EXAMPLE" },
    "payload": ["computed"]
  } },
  "plain": ["aws_region", "aws_service"]
}] }
```

The caller sends `aws_region` and `aws_service` as plain fields with each request,
written as AWS writes them, such as `sqs` and `eu-west-1`; a request that leaves one
out, or names one the rule does not allow, is refused before anything is sent. seal
signs for what was named and does not check it against the host: a request signed for
the wrong service is refused by AWS. Nothing in such a policy then holds the credential
to a service, so its own IAM permissions are the limit, and they should be narrow. With
a custom endpoint, keep `host` exact. A rule that allows presigning fixes its service.

Customers serve names of their own under `amazonaws.com`, which a
[host pattern](#host-patterns) is otherwise wrong for. SigV4 is the exception: the secret
access key is never sent, only a signature that is good for the one host, path and body
it was made for, so a host that is not AWS's learns nothing it can use elsewhere.

`allow_presign` also lets the caller have a presigned URL for an object the rule allows,
lasting at most `max_expiry_s`. It is a [weakening option](#weakening-options): the URL
works without seal until it expires. The rule must name its `methods`, from `GET`,
`HEAD`, `PUT` and `DELETE`, and its service must be `s3`.
[`signing.md`](signing.md#presigned-urls) has what a URL covers.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "s3.eu-west-1.amazonaws.com", "path_prefix": "/tenant-a/" },
  "methods": ["GET"],
  "inject": { "aws_sigv4": {
    "region": "eu-west-1",
    "service": "s3",
    "access_key_id": { "literal": "AKIAIOSFODNN7EXAMPLE" },
    "payload": ["computed"],
    "allow_presign": { "max_expiry_s": 900 }
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

With `allow_presign`, the caller may have a shared access signature for one blob, as for
`aws_sigv4`. The service must be `blob`.

```json
{ "rules": [{
  "destination": { "scheme": "https", "host": "account.blob.core.windows.net", "path_prefix": "/exports/" },
  "methods": ["GET"],
  "inject": { "azure_shared_key": {
    "account": { "literal": "account" }, "service": "blob",
    "allow_presign": { "max_expiry_s": 900 }
  } }
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

`require_channel_binding` goes the other way: the login must be SCRAM-SHA-256-PLUS,
bound to the TLS connection, or it is refused. It cannot be combined with the two
options above.

```json
{ "rules": [{
  "destination": {
    "scheme": "postgres", "host": "db.example.com", "port": 5432,
    "databases": ["app"], "user": { "literal": "app_user" }
  },
  "inject": { "pg_password": { "require_channel_binding": true } }
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

In a JSON response, everything but the sealed fields comes back as the provider wrote it,
digit for digit; only the objects and arrays on the way to a field are written again,
compactly and in key order. A key that repeats in one of those keeps its last value.

An XML path names elements by their local names: a namespace prefix, in the path or in
the response, is ignored, so a provider cannot move a token out of reach by writing
`<x:Token>` for `<Token>`. Only the content of a matched element changes. A document type declaration, a field that repeats or holds markup, or an
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

A field may also name claims to return in plaintext, for a token that is a JWT. Some
providers put what an application needs in the token itself: its expiry, or which tenant
it was issued for. seal returns the named claims in the reply's `claims`, by field name,
as a JSON object:

```json
{
  "rules": [{
    "destination": { "scheme": "https", "host": "identity.xero.com", "path_prefix": "/connect/token" },
    "inject": { "form_field": { "name": "client_secret" } },
    "seal_response": {
      "format": "json",
      "fields": [{
        "at": "/access_token", "as": "access_token", "policy": "api",
        "expose_claims": ["authentication_event_id", "exp"]
      }]
    }
  }],
  "definitions": {
    "api": { "rules": [{
      "destination": { "scheme": "https", "host": "api.xero.com" },
      "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } }
    }] }
  }
}
```

At most 8 claims a field, each at most 1 KiB as JSON; a larger one is left out. A token
that is not a JWT, or lacks a claim, exposes nothing and the response is sealed as usual.
seal reads the claims without checking the token's signature, and never returns the
signature, so the claims are no use as a credential. Name only claims that are not
secret.

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

## Verification

A webhook's signing secret is never sent anywhere: the application uses it to check that
a message came from the provider. With `verify`, the application asks seal instead, with
the message and the code that came with it, and seal answers yes or no. A policy with
`verify` needs no `rules`, and then its secret can go nowhere.

```json
{ "verify": { "hmac": { "hash": "sha256" } } }
```

`hash` is `sha1`, `sha256` or `sha512`. The caller builds the message as the provider
signs it, such as Slack's `v0:<timestamp>:<body>`, and decodes the code to bytes. seal
compares the whole code in constant time and never returns one, so a caller can check
codes but cannot make them, nor find one a byte at a time. The builder's
`webhook_hmac(hash)` makes this policy.

Some providers sign nothing: they send back, with each webhook, a token the application
chose when it registered the webhook, such as Telegram's `secret_token` in
`X-Telegram-Bot-Api-Secret-Token`. `equals` checks such a token:

```json
{ "verify": "equals" }
```

The caller presents the token that came with the webhook in place of the code, and no
message: the token does not cover one, and seal refuses a call that sends one. seal
compares the whole token in constant time, and a value sealed empty matches nothing. A
caller can try tokens, at the rate its keyset allows, so the token must be long and
random: seal a generated one, not one a person chose. The builder's `webhook_token()`
makes this policy.

A platform's own webhook secret, such as one Slack app's for every tenant, can also be
`shared`:

```json
{ "verify": { "hmac": { "hash": "sha256" } }, "shared": true }
```

A policy may have both `rules` and `verify`. A value sealed from a response never has
`verify`.

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
| `allow_injected_path` | A rule | Lets the value go with one that [injects into the path](#path) with exactly this prefix. The request is then sent under that prefix, filled by whichever such value is presented |
| `allow_unsigned_payload` | `aws_sigv4` | Allows `UNSIGNED-PAYLOAD` |
| `allow_headers` | `aws_sigv4` | Lets the caller set ACL, grant or copy headers |
| `allow_copy_from_any_bucket` | `aws_sigv4` | Lets a copy read any object on the rule's host, for a rule with no path prefix. Only for an endpoint addressed by path |
| `allow_presign` | `aws_sigv4`, `azure_shared_key` | Lets the caller have a presigned URL or shared access signature for one object, lasting at most `max_expiry_s`. The caller can copy it and pass it on, and it works without seal, unaudited, until it expires |
| `allow_md5` | `pg_password` | Allows MD5 authentication |
| `allow_cleartext_password` | `pg_password` | Allows a cleartext password |
| `require_channel_binding` | `pg_password` | Not a weakening: refuses any login but SCRAM-SHA-256-PLUS. Cannot go with the two above |
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
| `path_secret(api_base, prefix)` | A secret in the URL's path, such as a Telegram bot token |
| `basic(api_base, username)` | A password for basic auth |
| `oauth_client(config)` | Policies for an OAuth client secret or signing key, and for a password. Its tokens are limited to where they belong, and its refresh token's definition names itself |
| `aws(region, service, endpoint, access_key_id, session_token, payload)` | A secret access key |
| `azure(account, service, endpoint)` | An account key |
| `client_cert(api_base, cert, chain)` | A client certificate's private key |
| `webhook_hmac(hash)` | A webhook signing secret, which only verifies |
| `webhook_token()` | A token a provider sends back with each webhook, which only verifies |
| `postgres(host, port, databases, user)` | A Postgres password, with SCRAM only and the server verified |

A part of a composite credential comes from a `PartSource`: `Literal` fixes it in the policy,
`Plain` lists it in `plain`, and `Sealed` generates a companion policy for that field, returned
in `companions`.
