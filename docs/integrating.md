# Integrating an application with seal

For developers of an application that stores credentials and uses them through seal.
[`policy.md`](policy.md) has every policy option, [`oauth.md`](oauth.md) the OAuth
flows, and [`operations.md`](operations.md) running seal itself.

- **Store envelopes, not secrets.** Keep each secret field's envelope where the
  plaintext used to be; keep non-secret fields in plaintext.
- **Know the item id before sealing.** Allocate the record's id first, then seal, in
  the browser with the WASM sealer where possible. The envelope is bound to the item,
  so it cannot be moved to another record.
- **Build policies with the builder**, from the integration's definition: base URL,
  auth scheme, token endpoint. The application owns the mapping from its connection
  types to policies.
- **Changing a destination means re-entering the secret, or asking the operator.** The
  application cannot change a policy, by design. Whoever runs seal can, with `seal
  reseal --rewrite-policies`, from a file the application writes and the operator
  reads first ([Changing policies](operations.md#changing-policies)). Name hosts, and
  path prefixes only where they limit something, so that fewer changes need it.
- **Cache sealed tokens** with their plaintext `expires_in`, refresh through seal, and
  store the new envelopes atomically with the connection. If a refresh returns no new
  refresh token, keep the existing one.
- **Do not log envelopes in bulk.** They are not secret in the cryptographic sense, but
  anyone who can call seal can use them.
- **Treat seal's error codes as the interface.** `POLICY_DENIED` is a bug or an attack,
  not a retryable error; `KEYS_UNAVAILABLE` and `UPSTREAM_*` may be retried. The codes
  are in [`protocol.md`](protocol.md).
- **Pick the mode deliberately, and surface it.** In-process mode means the application
  can read every credential.
- **Manage each keyset's lifecycle.** Generate one when a tenant is created (an admin
  caller); rotate on schedule and on suspicion; wait `max_stale`, stop sealing to the
  old public key, reseal, then delete the old wrapped keys. When a tenant leaves,
  destroy all of its wrapped keys, with `destroy_keyset` from a caller allowed to and
  then in the key source's backups, or destroy the key that wraps them. Once that has taken effect ([Destroying a
  keyset](operations.md#destroying-a-keyset)), its backups hold nothing usable. Running
  requests and Postgres sessions end on their own limits.
- **Check webhooks through seal.** Seal a signing secret with `verify` and no rules,
  then call `verify` with the message as the provider signs it and the code decoded to
  bytes. Check the timestamp yourself, before or after: seal answers only whether the
  code is right. Treat an error as a failed check. Where the provider sends back a
  token instead of signing, as Telegram does, seal it with `"verify": "equals"` and
  present the token as the code, with no message.
- **Presign only what must leave.** A presigned URL is the one credential seal gives
  back, and only for a rule sealed with `allow_presign`. Use it to hand an object to a
  browser or another party; read and write objects of your own through `send`. Ask for
  the shortest lifetime that works, never log the URL, and give such rules a narrow
  `path_prefix` and only the methods they need.
- **OAuth callbacks land on the application**, not on seal, which need not be reachable
  from the internet. The authorization code alone is not enough to redeem: that needs
  the sealed client secret and the PKCE verifier, and the tokens come back sealed.
