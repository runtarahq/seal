# seal: threat model

Status: reviewed against what was built, in the hardening pass before the first release.
It describes seal as built: the HTTP broker with every injection and signing scheme,
response sealing, Postgres sessions, the service and its callers, and the keyring.

## What seal is for

An application can use a credential through seal, but cannot read it. A breach of
the application therefore gives the attacker use of credentials, toward the
destinations they were sealed for and recorded in seal's audit log, and that use
ends when the breach is closed. It does not give the attacker copies that keep
working afterwards.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Private keys of keysets | In seal's memory, unwrapped; wrapped in the key source | Open every value sealed to them, including those in backups |
| Key-wrapping key | A file readable only by seal's user, or a KMS (OVHcloud KMS or AWS KMS), which it never leaves | Unwraps the private keys |
| KMS credentials | An access certificate's key, a token or an AWS secret access key, in a file readable only by seal's user; in seal's memory for the life of the process (OVHcloud) or of one request (AWS). Or, for AWS, whatever the SDK finds: a key in the environment or the shared files, or a role's temporary credentials from the host, which the SDK keeps in memory until they are about to expire | Ask the KMS to unwrap any private key seal has a wrapped copy of |
| Key source credentials | An access key for the bucket that holds the wrapped keys, in a file readable only by seal's user; in seal's memory during one request | Read, add and delete wrapped keys: take keys away from seal or put deleted ones back. They open nothing |
| Opened secrets | In seal's memory, during one `send`, or a Postgres session until its login ends | The credentials themselves |
| Client-certificate private keys | In a TLS configuration, while its identity exists | Credentials kept beyond one request (see Residual risks) |
| SigV4 signing keys | In seal's memory, during one request or chunked upload | Sign requests for one day, region and service |
| Sealed values and policies | In the application's storage, and passing through seal | Unreadable, but usable by anyone who can call seal with them |
| Audit records | Written by seal to its configured sink | The record of use after a breach |

## Actors

| Actor | Can | Should not be able to |
|---|---|---|
| Application, working normally | Seal values, and ask seal to use them | Read a secret |
| Compromised application | Use any value it can present, for any request a value's policy allows | Read a secret, change a policy, reach a destination no policy allows, or hide its use |
| Administrative caller | Generate and rotate keys | Read a private key, which never leaves seal unwrapped. Destroy a keyset, which needs `destroy_keysets` |
| Caller that may destroy keysets | Make every value of the keysets it may use unreadable, for good | Read a value, or touch a keyset it may not use |
| Provider | Receive the credentials sealed for it | Receive another destination's credentials |
| Database server | Receive a SCRAM proof or, where the rule allows, an MD5 hash or a password | Pass as the real server: TLS verifies its name, and SCRAM its knowledge of the password |
| Network attacker | Observe and interfere with traffic | Read or redirect credentials, given correct TLS validation |
| Attacker with a stolen backup | Read the sealed values | Open them without the private keys |
| Root on seal's host | Everything: **out of scope** | — |

## Trust boundaries

1. **Caller to seal.** seal authenticates callers by mTLS certificate or Unix socket
   peer credentials, and allows each one only its configured keysets. In library
   mode this boundary does not exist.
2. **Sealed value to seal.** A value is untrusted input until it opens. Its associated
   data binds it to a keyset, key, item and field, and its policy is authenticated
   by the encryption, so a caller cannot move a value or change its policy. Only a
   value whose policy is `shared` serves another record's request, and the caller
   must be allowed its keyset too.
3. **Caller's request to the policy.** Every caller-supplied part of a request is
   untrusted. It must match a rule, and it cannot set anything the rule injects or
   signs.
4. **seal to provider.** seal resolves and checks the address, connects to the
   checked address, validates TLS and never follows redirects.
5. **seal to a Postgres server.** As for a provider, then: unless the rule weakens it,
   TLS is required and verified before anything is sent, and seal reads exactly the one-byte answer to its
   `SSLRequest`, so nothing unprotected can be slipped in. SCRAM checks the server's
   signature, and channel binding ties the login to this TLS connection when the
   server offers it. A server that accepts the login without asking for the password
   the rule presents is refused. The caller's
   startup must name the policy's user.
6. **Provider's response to the caller.** Response sealing replaces declared fields
   before the response reaches the caller. Everything else passes through.
7. **seal to key source and KMS.** These supply the private keys. The key source is a
   directory on seal's host, or a bucket reached over TLS with an access key, and holds
   only wrapped keys: whoever controls it can take keys away from seal or put deleted
   ones back, and opens nothing without the wrapping key. Whoever controls the KMS controls what seal can open. A KMS is reached over TLS, verified against the
   public roots or a configured CA, and sees each private key it wraps or unwraps. The
   keyset and kid are authenticated with each wrapped key, so the key source cannot
   pass one keyset's key off as another's.

## What enforces each boundary

| Boundary | Enforced by | Checked by |
|---|---|---|
| Caller to seal | Peer credentials, or the client certificate's subject, compared attribute by attribute, or one of its subject alternative names; configured keysets, including a shared value's; an audit record of each refusal | `crates/seal/tests/service.rs`; `a_certificate_subject_is_compared_by_attribute`; `a_caller_needs_the_platform_keyset_to_use_a_shared_value` |
| Sealed value to seal | HPKE with associated data; the policy inside the ciphertext; the `shared` flag | `crates/seal-format/tests/acceptance.rs`, the published vectors, `a_value_from_another_record_is_refused_unless_shared` |
| Caller's request to the policy | The matcher, a pure function over untrusted policies; strict URL parsing; refused headers | `crates/seal-broker/src/matcher/tests.rs` (with property tests), `url_match` and other fuzz targets, `caller_set_amz_headers_are_refused_before_dns` |
| seal to provider | Address checks after DNS on every address; TLS; no redirects | `acceptance_a_private_address_is_refused_after_dns_with_no_connection`, `acceptance_redirects_are_returned_not_followed` |
| seal to a Postgres server | TLS before sending; SCRAM with the server's signature, and channel binding when the server offers it; no login without the password being asked for | `the_server_must_offer_tls_and_prove_its_name`, `a_server_that_cannot_prove_it_knows_the_password_is_refused`, `a_server_that_never_asks_for_the_password_is_refused`, Postgres 14–18 in containers |
| Provider's response to the caller | Response sealing of declared fields, refusing what it cannot parse for certain | `response_seal_*` fuzz targets, `xml_that_could_hide_a_token_is_refused` |
| Everything seal writes or returns | No secret in logs, audit, metrics, errors or response heads | The canary scan after every test |

## What a compromised application gets

| Mode | Where the private keys are | What a compromised application gets |
|---|---|---|
| **Library** (in-process) | In the application's memory | Everything, as with symmetric encryption in the application. The only gain: plaintext stays inside seal's code, so it does not leak by accident into logs, errors or responses |
| **Process on the same host** | In another process, under another OS user | Use, not copies, unless the attacker also gets root on the host |
| **Separate machine** | On the seal host | Use, not copies, even with root on the application's host |

## Residual risks

Known risks the design accepts. Each needs to stay true and documented as seal is built.

### Accepted by design

- **Root on seal's host** can read everything in seal's memory, including every key.
- **Whoever runs seal can change a policy.** `seal reseal --rewrite-policies` gives
  stored values the policies its input names. It needs the keys, so it is within what
  root on seal's host can do anyway. Its input comes from the application: an operator
  who runs it unread lets a compromised application choose where secrets go.
- **Library mode** gives a compromised application every credential. The application
  logs this at startup and reports the mode.
- **A provider that returns a credential in another form.** seal drops a response
  header that repeats a secret it put in the request, and fails a response whose body
  repeats one, passing on none of it. It looks for the secret as it was sealed and as
  it was written in the request, for a sealed part that went with it, and for a JWT
  assertion it signed, each if at least eight bytes. A response in two parts, such as
  two ranges, each holding half of one, is not caught. A provider that
  returns it encoded some other way, compressed, or escaped inside JSON, still gives it
  to the caller, and one that means to can always do so. Policies should name API
  hosts, not services that reflect requests.
- **Response sealing covers declared fields at declared locations only.** The same
  value elsewhere in a response passes through, as does anything else a provider
  returns, such as a presigned URL it generates itself.
- **Exposed claims are what the sealer chose, unverified.** A policy may name claims of
  a sealed JWT to return in plaintext. seal reads them without checking the token's
  signature, so they are as trustworthy as the provider's response; a token whose
  header says it is unsigned, or that has no signature, exposes nothing. The sealer
  should name only claims that are not secret. Rules presented together must agree on
  them exactly, as on the rest of response sealing, so another value cannot add any.
- **A presigned URL is a copy, where a rule allows one.** A rule with `allow_presign`
  lets its caller have a presigned S3 URL or a Blob shared access signature. That is a
  credential for one object and one kind of request, which works without seal and
  unaudited until it expires, at most seven days and no longer than the rule says. For
  such a rule "use, not copies" becomes "copies that expire": a compromised application
  can collect URLs for every object and method the rule allows, and they outlive the
  breach by up to the rule's lifetime. The option is off unless the sealer sets it, the
  rule must list its methods, and seal records each URL it issues, though not its use.
  Keep the lifetime short and the path prefix narrow, and where the object need not leave
  the application, do not set it.
- **A caller can check codes, not make them.** With a value whose policy has `verify`,
  a caller learns whether a message and a code go together, which the provider's own
  webhooks already show it. seal computes the code and never returns it, compares
  the whole of it in constant time and refuses a shorter one, so the answers do not
  add up to a forgery. A compromised application can still accept a forged webhook by
  not asking; that was always its own decision.
- **A Postgres rule can give up the server's identity, or TLS, but not the password.**
  With `tls` set to `"unverified"` or `"plaintext"`, someone on the path to the server
  can relay the login and then read or change the session, as with libpq's
  `sslmode=require` and `disable`. The login is SCRAM only in those modes, so the
  password and anything that could stand in for it stay with seal, and a server that
  does not know the password is not logged in to. Under `"unverified"` only a rule with
  `require_channel_binding` catches an impostor: without it, one that presents a
  certificate with no hash to bind to, such as Ed25519, is logged in to unbound, and can
  relay the login to the real server. Whoever receives a SCRAM proof can try passwords
  against it offline, at the cost of the iterations the server asked for, so seal
  refuses fewer than 4096, and a password for such a rule should be generated, not
  chosen. `"plaintext"` also needs the
  operator's `honour_plaintext_postgres_rules`. Both are the sealer's choice per value,
  and the default verifies.
- **A credential whose service the caller names is bounded by its own permissions.**
  With a fixed `service` and `region`, a SigV4 signature is good for one service in one
  region. Where the rule lets the caller name them, a compromised application can have a
  request signed for any service, at any host the rule allows, and the
  credential's IAM policy is the only limit left. The secret access key still never
  leaves seal, and every request is still audited with its host and path.
- **A host pattern trusts a whole domain.** A rule for `*.example.com` sends its secret
  to any name under `example.com` that a compromised application asks for, so whoever
  can serve one such name with a valid certificate, by registering it or taking over a
  dangling one, receives the secret. seal matches on label boundaries and refuses a
  pattern for a top-level name, but cannot know who may register names under a domain:
  the sealer chooses the domain, and an exact host remains the default.
- **A value that allows an injected path goes wherever that prefix leads.** With
  `allow_injected_path`, a value is sent under a path prefix filled by another sealed
  value, and anyone with the public key can seal one. A compromised application can
  therefore send it under a prefix of its choosing, such as another Telegram bot's. The
  sealer sets the option only where the rule is safe for any filling, and holds the rest
  of the request with `path_prefix` and `require_form`.
- **A caller can guess a token.** With `"verify": "equals"`, each answer says whether
  one guess is the secret. seal compares the whole token in constant time, so an answer
  says nothing of where a guess went wrong, and the keyset's rate limit bounds the
  guesses. That is enough for a generated token and not for a short or chosen one.
- **What a credential may do is its own permissions' to say.** seal limits where a
  credential goes, not what the provider returns for an allowed request, nor what an
  allowed request does there. A caller may use any method, set any `X-Amz-*` or `x-ms-*`
  header but those that say how seal signs, name any region or service where the rule
  lets it name them, and connect to any database as the policy's Postgres user. So a
  copy reads whatever the key can read, an ACL is set if the key may set it, and a
  replication session opens if the role may replicate. seal is not the provider's access
  control: scope a credential where it is issued, in IAM, an API key's scopes or a role's
  privileges, and seal only what the application may use in full.
- **An Azure account key is good for its whole account, whatever the rule's path.** With
  Shared Key a caller may set any `x-ms-*` header but the date, so a copy or rename can
  read a blob outside the rule's path prefix into it, and a container can be made
  public. An account key cannot be scoped at Azure, and seal does not stand in for that:
  a path prefix on a Shared Key rule holds the URL of each request, not what the account
  key can reach. Seal an account key only where the application may have the account.
- **An internal range the operator opens is open to every caller.** Anyone can seal a
  value whose rule names an internal host and sets `allow_private_destination`, so a
  compromised application can send any request to any address in
  `private_rule_cidrs` or `allow_private_cidrs` and read the answer. Nothing internal
  is reachable until the operator names a range, and link-local and metadata addresses
  need `allow_private_cidrs`. The operator names only the ranges that hold services
  credentials are sealed for.
- **Sealed values are usable by anyone who can call seal with them,** so applications
  should not expose them in bulk, even though they are not readable.
- **Anyone with the public key can seal a new value, with any policy.** HPKE's base
  mode does not authenticate the sealer. A new value holds only what its sealer
  already knew, so this exposes no existing secret, and a value's policy limits only
  that value. A compromised application can therefore store or present values of its
  own, including alongside genuine ones, so seal must treat every value it opens as
  untrusted input when combining them.
- **A shared value serves every record its callers can name.** A platform credential
  sealed with `shared` set, such as a shared OAuth app's client secret, can be used
  with any tenant's request by a caller allowed the platform keyset, for whatever its
  rules allow. So its rules should allow only what a tenant may do: the builder's
  shared OAuth secret allows the code and refresh grants and nothing that acts as the
  platform. A value of the caller's own cannot widen this, because every matched rule's
  required form fields are checked. Which tenant may use which shared app is the
  application's decision.
- **A Postgres session is the policy's user, for as long as it lasts.** After the login
  seal relays without reading, so the caller can do anything that user can do, in any
  database the role may connect to. Startup parameters other than the user and database pass
  through, so `options` can set what that user may set anyway. Give a sealed Postgres
  credential the privileges its sessions need, and no more.
- **A cancel request needs no password.** Postgres cancels by process ID and cancel
  key, and seal forwards them for any caller whose values the policy allows. A caller
  can cancel only a query whose key it has, but could try guesses at the server; the
  service's rate limits bound how fast.
- **Channel binding needs a hash.** For a server certificate signed with an algorithm
  that has none, such as Ed25519, seal logs in with SCRAM without binding and tells
  the server so. The login still needs TLS and checks the server's signature.
- **Channel binding is the server's choice unless the rule requires it.** A server
  that offers only `SCRAM-SHA-256` gets a login without binding, unless the rule sets
  `require_channel_binding`. The audit record's `pg_auth` says which it was.
- **OAuth callbacks reach the application.** seal is never a public endpoint, so the
  authorization code passes through the application. It is not enough alone:
  redeeming it needs the sealed client secret and the flow's PKCE verifier.
- **Signing follows the providers' canonical forms.** A mistake would make requests
  fail, not leak a key; SigV4 is checked against the AWS test suite and SDK, and both
  schemes against RustFS and Azurite.
- **A running application controls its browser sealer.** A compromised application
  that serves the console's script can change it to capture a secret as it is typed.
  Sealing in the browser protects against server-side capture, not this.

### Copies seal cannot erase

- **Third-party copies.** Dependencies copy values seal cannot zeroize: `hyper` header
  values and write buffers, `bytes::Bytes` (a private key on its way to or from a KMS
  passes through both, and through `serde_json`'s reading of the KMS's answer, or with AWS KMS through the AWS SDK, which wipes none of its buffers), `ring`'s key pairs and HMAC keys,
  `serde_json`'s reading of a field of a response being sealed, or of the claims a policy
  names in a JWT's payload. Headers are marked sensitive, and
  plaintext may remain in freed memory until it is reused. This matters to someone
  who can read seal's memory, who is already out of scope. seal's own buffers that
  hold a secret are sized up front, so none leaves an unwiped allocation behind as it
  grows; [the review](reviews/secret-handling.md) lists every place a secret is read.
- **Secrets in requests.** A query parameter or path holding a secret is copied into a
  `Uri`, and a header into a `HeaderValue`. A body with an injected secret is wiped when its last
  reference goes, but `hyper` may have copied it into a write buffer.
- **Client-certificate keys in TLS configurations** stay in memory while the identity
  exists, an explicit exception to "plaintext lasts one request", and may also be
  copied by the TLS library. An identity goes when its sealing key leaves the keyring,
  when it is unused for the idle timeout, or to make room, and its configuration with
  its last connection.
- **A Postgres password** stays in seal's memory from when the session opens until its
  login ends, not just for one request; the caller's preamble comes in between, under
  the idle timeout. `postgres-protocol`'s SCRAM also keeps copies derived from the
  password, which seal cannot wipe.
- **A presigned URL** is wiped when seal, the message that carries it and
  `seal-client` drop it. What remains is the transport's write and read buffers, as
  for every header above, and whatever copies the application makes.
- **SigV4 signing keys** are derived from the secret access key for one day, region and
  service. A chunked upload holds one for as long as the upload streams; it is wiped
  when the upload ends.
- **Swap.** If memory locking is unavailable or off, key pages can reach swap. Where
  it matters, require locking, and disable or encrypt swap.
- **The wrapping key in memory.** A `FileKeyWrap` holds its AES key in `ring`'s key type
  for the life of the process, which seal cannot wipe.
- **Peer credentials name a uid, not a program.** On a shared host, any process running as
  the application's uid can call seal as the application. Give the application its own
  user.

### Timing limits

- **A deleted key keeps working for a bounded time.** Other instances see a deletion
  within `max_stale`, and an unwrapped key is dropped after `max_unwrap_age`.
- **The wrapping key file is read once.** seal holds it for the life of the process,
  so deleting or replacing the file takes effect only at a restart, and
  `max_unwrap_age` does not revoke it. Each stored key names the wrapping key that
  wrapped it, and seal reads it only with that one, so the wrapping key is replaced by
  configuring the new one beside the old and wrapping every key again with
  `seal rewrap`. Copies of the keys wrapped with the old wrapping key, in backups or in
  the earlier versions a bucket keeps, stay readable to whoever has it, until they are
  deleted or it is destroyed.
- **An older wrapping key that is still configured still opens.** While a wrapping key
  is in `keys.unwrap_also`, taking away the current one does not stop seal reading the
  keys the older one wrapped. seal reads any stored key that names it, not only those
  that existed when it was replaced, so someone who has a leaked older wrapping key and
  can write to the key source can add a key of their own until it is taken out.
- **A key's place among its keyset's keys is held by its name.** The newest key is the
  current one, and a key's time is stored beside it in the key source. A name seal made
  has the time in it and is authenticated with the wrapped key, so a changed time is
  refused; a key named by hand has no such check, and whoever holds the source can say
  when it was made.
- **A wrapping key in a KMS is revoked within `max_unwrap_age`.** seal asks the KMS
  each time it unwraps a key, so taking away its access, or deleting the service key,
  stops it once the keys it has unwrapped are dropped. OVHcloud credentials are read
  once and AWS credentials for each request; either way a stolen one is revoked at the
  KMS, not by replacing the file. A role's temporary credentials work until they
  expire, wherever they were copied to, unless the role's sessions are revoked in IAM.
- **Running operations are not interrupted** by a deletion or by revoking a wrapping
  key. They end on their own limits, up to `pg_max_session` for Postgres.
- **A killed process records nothing more.** A record is written when a request ends.
  Told to stop, seal ends what is still running after `shutdown_grace` and records it;
  killed outright, or crashed, it leaves no record of the requests then under way. A
  Postgres session is the exception that would matter most, lasting hours, so it is
  also recorded when it begins.
- **Destruction needs every copy gone.** Deleting wrapped keys does not protect backups
  that also hold copies of them, unless the wrapping key is destroyed too.
- **A refused response can follow a credential's use.** Refusing a response as over its
  cap or unparseable happens after the provider has received the request, and possibly
  acted on it.

## Open

- **The fuzzing campaign** of at least 24 hours per target
  ([`reviews/fuzzing.md`](reviews/fuzzing.md)).
- **Run-bound capabilities**, so a compromised caller cannot use credentials outside a
  real run (planned).
