# Integrating an application with seal

For developers of an application that stores credentials and uses them through seal.
[`policy.md`](policy.md) has every policy option, [`oauth.md`](oauth.md) the OAuth
flows, and [`operations.md`](operations.md) running seal itself.

- **Store envelopes, not secrets.** Keep each secret field's envelope where the
  plaintext used to be; keep non-secret fields in plaintext.
- **Know the item id before sealing.** Allocate the record's id first, then seal. The
  envelope is bound to the item, so it cannot be moved to another record.
- **Do not receive a secret readable where you can avoid it.** Have it sealed where it
  is entered, as [below](#taking-in-a-secret-without-holding-it), and refuse one that
  arrives readable.
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
  not a retryable error; `KEYS_UNAVAILABLE` and `UPSTREAM_*` may be retried;
  `INTAKE_STALE` means the secret has to be sealed again under a new offer. The codes
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
  `path_prefix` and only the methods they need, which for presigned URLs the rule's
  `methods` still hold.
- **OAuth callbacks land on the application**, not on seal, which need not be reachable
  from the internet. The authorization code alone is not enough to redeem: that needs
  the sealed client secret and the PKCE verifier, and the tokens come back sealed.

## Taking in a secret without holding it

An application that receives a secret readable holds it for that long, and so does
whatever carried it there: a proxy, a request log. Sealing in the browser alone does not
fix that, because whoever seals chooses the policy, and the application cannot read what
was chosen. So the application chooses first, and seal holds the sealer to it:

1. **The page sends the fields that are not secret**, such as a base URL, when the form
   is submitted. Nothing changes for the person filling it in.
2. **The application answers with an offer.** It allocates the record's id, derives the
   policy of each secret field as it always has, reads the keyset's current public key
   (`public_keys`, which it may cache), and calls `Offer::for_intake` with a `not_after`
   a few minutes ahead. The offer is JSON with nothing secret in it: `public_key`, `kid`,
   `keyset`, `item`, `field` and `policy`.
3. **The page seals the secrets as one JSON object** of field name to value, with the
   WASM sealer and the parts of the offer, which it need not understand:

   ```js
   const object = new TextEncoder().encode(JSON.stringify({ api_key, api_secret }));
   const envelope = seal(offer.public_key, offer.kid, offer.keyset, offer.item,
                         offer.field, object, JSON.stringify(offer.policy));
   ```

   A field the user left blank is left out. Bytes that are not text go in as
   `{"b64": "…"}`, in base64url. A script or an API client does the same with
   [`seal-sealer`](operations.md#sealing-from-a-terminal).
4. **The page saves** the envelope with the same fields that are not secret.
5. **The application derives the policies again** from what it received and calls
   `admit` with them. It gets one envelope per field, each bound to the record and to
   the field of its name, and stores them as it stores any other.

What to hold to:

- **Derive, do not remember.** The application keeps nothing between the offer and the
  save. If what it derives the second time differs, because the fields changed or the
  application was deployed in between, seal answers `INTAKE_STALE`: make a new offer and
  have the page seal again. The same for a form left open past `not_after`.
- **Mark a field `optional`** where it may be left blank. An absent field that is not
  optional fails the whole call with `INTAKE_INVALID`, and nothing is stored.
- **Keep `not_after` short.** Minutes, within the operator's
  `limits.max_intake_lifetime`. The application's clock sets it and seal's checks it.
- **Serve the WASM module of the seal you run.** An older module refuses an intake
  policy, and an older seal refuses an intake envelope. Each release has the module as
  `seal-wasm.tar.gz`: `web/` for a page to load as it is, and `bundler/` for webpack or
  Vite. `scripts/package-wasm.sh` builds the same from source.
- **What this is for.** An application compromised after a secret was sealed cannot
  send it anywhere but where the offer said: an intake envelope in a log is worth no
  more than the values it becomes, and nothing once it is past its time. An application
  already compromised when it makes the offer names a destination of its own, as one
  that serves a changed page reads what is typed
  ([`threat-model.md`](threat-model.md#accepted-by-design)).
