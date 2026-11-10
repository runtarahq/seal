# seal: OAuth 2.0

How an application runs each OAuth flow with seal. seal stays stateless: the application
stores the sealed tokens seal returns, and keeps non-secret metadata such as `expires_in`
and `scope` in plaintext to schedule refreshes.

The policies come from the builder, `seal_format::policy::builder::oauth_client`, which
produces:

- `client`: the policy of the client secret, or the signing key. It allows the token
  endpoint, with response sealing, and the revocation endpoint if there is one.
- `password`: the policy of a resource owner's password, for the password grant.

Both name two definitions that response sealing uses:

- `api`, for access tokens: `Bearer` at the API, and the revocation endpoint.
- `refresh`, for refresh tokens: the token endpoint, with the same response sealing, so
  the next refresh token gets the same policy. Rotation can go on indefinitely, and the
  policy never grows.

```rust
let policies = builder::oauth_client(&OAuthConfig {
    token_url: "https://auth.example.com/oauth/token".into(),
    revoke_url: Some("https://auth.example.com/oauth/revoke".into()),
    api_base: "https://api.example.com/".into(),
    auth: OAuthClientAuth::ClientSecretPost,
    response_format: ResponseFormat::Json, // Form for GitHub's legacy responses
    shared: false, // true for a platform app every tenant uses; see below
    access_token_claims: Vec::new(), // claims of a JWT access token to return in plaintext
})?;
```

In every flow the caller sends a form body with the non-secret fields, such as
`grant_type`, `client_id`, `code` and `scope`. seal adds the secret ones, sends the
request, and replaces `access_token` and `refresh_token` in the response with sealed
values. It returns those values in the reply's `sealed_fields` too, so the application
need not parse the body.

Where the access token is a JWT and the application needs a claim of it, such as Xero's
`authentication_event_id`, list the claim in `access_token_claims`. seal returns those
claims in the reply's `claims`, in plaintext, on every grant; see
[Response sealing](policy.md#response-sealing).

## The flows

| Flow | The caller sends to | Sealed in | Sealed out |
|---|---|---|---|
| Authorization code with PKCE | Token endpoint: `grant_type=authorization_code`, `code`, `code_verifier`, `client_id`, `redirect_uri` | Client secret | Access and refresh token |
| Refresh | Token endpoint: `grant_type=refresh_token`, `client_id` | Refresh token, and client secret | New access token, and a new refresh token if the server rotates |
| Client credentials | Token endpoint: `grant_type=client_credentials` | Client secret | Access token |
| Resource owner password | Token endpoint: `grant_type=password`, `username`, `client_id` | Password and client secret | Access and refresh token |
| JWT bearer grant | Token endpoint: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` | Signing key | Access token |
| Revocation (RFC 7009) | Revocation endpoint: `client_id` | The token, and client secret | Nothing |
| Using the token | The API | Access token, as `Bearer` | Nothing |

The authorize URL and the callback stay with the application, since `client_id` is not
secret. The application generates the PKCE verifier, sends its challenge in the authorize
URL, and sends the verifier with the code.

A refresh that returns no new refresh token is normal. Keep the sealed refresh token you
have: it still works.

## A shared platform app

Usually one OAuth app serves every tenant: the platform registers it with the provider
once, and each tenant connects their own account through it. seal keeps the app's client
secret from every tenant while each of them uses it.

1. Build the policies with `shared: true`, and seal the client secret once, to the
   platform's own keyset and record, for example keyset `platform`, item `oauth-app`.
2. Each tenant's flow presents that value alongside its own request, naming the record it
   is bound to. The request names the tenant's keyset and item.
3. seal seals the tokens it gets to the tenant's keyset and item. They are not shared:
   another tenant's request cannot use them.

```rust
let secret = SealedValue::from_record(platform_secret, ItemId::new("oauth-app")?);
let mut request = SendRequest {
    keyset: tenant_keyset,      // the tenant's
    item: connection_id,        // the tenant's record, where the tokens will be stored
    sealed: BTreeMap::from([(FieldName::new("client_secret")?, secret)]),
    plain: BTreeMap::new(),
    request: token_request,     // grant_type=authorization_code&code=…&client_id=…
};
```

What keeps the secret the platform's:

- A tenant can use the secret only with the token endpoint, as its rules say, and never
  receives it: it reaches only the provider.
- Its token-endpoint rule requires `grant_type` to be `authorization_code` or
  `refresh_token`, each exactly once in a plain form body. A client credentials grant
  would give the tenant a token acting as the platform, so seal refuses it before any
  DNS lookup. The password grant's policy is never shared.
- A JWT bearer grant key always acts as the platform, so the builder refuses to share
  one.
- The service allows a caller a shared value only if its configuration allows the
  value's keyset (`keysets = ["acme", "platform"]`).
- The audit record lists each shared value used, as `field=keyset/item`.

Which tenant may use which shared app is the application's decision: seal checks that
the value is shared, not who the tenant is.

## Client authentication

| Method | `OAuthClientAuth` | What seal adds |
|---|---|---|
| `client_secret_post` | `ClientSecretPost` | `client_secret` in the body |
| `client_secret_basic` | `ClientSecretBasic { client_id }` | `Authorization: Basic` |
| `private_key_jwt` | `PrivateKeyJwt(options)` | `client_assertion` and `client_assertion_type` |

For the JWT bearer grant, such as Google service accounts, use `JwtBearerGrant(options)`.
seal adds `assertion`.

## Signed assertions

seal signs a short-lived JWT with the sealed private key: RS256, PS256 or ES256, from a
PKCS#8, PKCS#1 or SEC1 PEM key, with an RSA key of at least 2048 bits or a P-256 key. It
adds `aud`, `iat`, `nbf`, `exp` and a random `jti` to the rule's claims, and sends the JWT
only to the token endpoint, never back to the caller. A rule's destination must be the
token endpoint's full path, and seal refuses a request to any other path, even one below
it.

The audience is required, because providers expect different values:

| Provider | `aud` | Notes |
|---|---|---|
| Google | `token_endpoint` | `https://oauth2.googleapis.com/token`; `kid` is the key's `private_key_id` |
| Okta | `token_endpoint` | The URL being called |
| Microsoft Entra | `token_endpoint` | `PS256`, and `x5t#S256` with the certificate's thumbprint |
| Auth0 | `{ "value": "https://<tenant>/" }` | The tenant URL, with its trailing slash |
| Salesforce | `{ "value": "https://login.salesforce.com" }` | The login URL, not the token path; `sub` is the username |

An exact value is sent byte for byte, since servers compare audiences as plain strings. The
tests in [`crates/seal-broker/tests/jwt.rs`](../crates/seal-broker/tests/jwt.rs) check each
of these shapes.

Sources: [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523),
[Google](https://developers.google.com/identity/protocols/oauth2/service-account),
[Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials),
[Okta](https://support.okta.com/help/s/article/the-audience-claim-for-client-assertion-must-be-the-endpoint-invoked-for-the-request),
[Auth0](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authenticate-with-private-key-jwt),
[Salesforce](https://help.salesforce.com/s/articleView?language=en_US&id=sf.remoteaccess_oauth_jwt_flow.htm&type=5).
The draft revision of RFC 7523 would require the issuer as the only audience for client
authentication. Providers do not all follow it yet, so seal supports both forms.

## What seal guarantees, and what it does not

- Tokens in declared response fields never reach the caller in plaintext. A value sealed
  by someone else, presented alongside a genuine one, cannot strip that sealing.
- Each sealed token works only where its definition says: an access token at the API and
  the revocation endpoint, a refresh token at the token endpoint and the revocation
  endpoint.
- seal does not inspect the rest of a response. A provider that returns a token anywhere
  else, or echoes a credential, gives it to the caller. Policies should name real token
  and API endpoints.
