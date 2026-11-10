//! Sealing a secret to a public key, and opening it with the private key.
//!
//! HPKE (RFC 9180), base mode: `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`,
//! `AES-256-GCM`, with the constant `info` of [`INFO`]. `docs/format.md`
//! describes the format, and `vectors/` has test vectors.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, HpkeError, Kem, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::envelope::{Envelope, MAX_CT_BYTES, TAG_BYTES, VERSION};
use crate::error::FormatError;
use crate::id::{FieldName, ItemId, KeyId, KeysetId};
use crate::policy::Policy;

/// HPKE's `info`, fixed for this version of the format.
pub const INFO: &[u8] = b"seal/v1";
/// The prefix of the associated data.
const AAD_PREFIX: &[u8] = b"seal/v1/aad";

/// The length of an X25519 key.
pub const KEY_BYTES: usize = 32;

type EncappedKey = <X25519HkdfSha256 as Kem>::EncappedKey;
type HpkePublicKey = <X25519HkdfSha256 as Kem>::PublicKey;

/// Where a value is stored. A value does not open anywhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding<'a> {
    /// The keyset the value is sealed to.
    pub keyset: &'a KeysetId,
    /// The application's identifier for the record.
    pub item: &'a ItemId,
    /// The field on the record.
    pub field: &'a FieldName,
}

/// A keyset's public key. Sealing needs nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; KEY_BYTES]);

impl PublicKey {
    /// Wraps a public key's bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidKey`] if the length is wrong.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FormatError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| FormatError::InvalidKey)
    }

    /// Parses a public key from base64url.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidKey`] if it is malformed.
    pub fn from_base64url(encoded: &str) -> Result<Self, FormatError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| FormatError::InvalidKey)?;
        Self::from_bytes(&bytes)
    }

    /// The public key's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    /// The public key in base64url.
    #[must_use]
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    fn to_hpke(self) -> Result<HpkePublicKey, FormatError> {
        HpkePublicKey::from_bytes(&self.0).map_err(|_| FormatError::InvalidKey)
    }
}

/// The associated data that binds a value to where it is stored:
/// `"seal/v1/aad" || u8(v) || lp(keyset) || lp(kid) || lp(item) || lp(field)`,
/// where `lp(x)` is `x` prefixed by its length as a big-endian `u16`.
///
/// # Errors
///
/// Returns [`FormatError::InvalidIdentifier`] if an identifier is too long to
/// encode, which validated identifiers never are.
pub fn associated_data(
    version: u8,
    kid: &KeyId,
    binding: Binding<'_>,
) -> Result<Vec<u8>, FormatError> {
    let parts = [
        binding.keyset.as_str(),
        kid.as_str(),
        binding.item.as_str(),
        binding.field.as_str(),
    ];
    let mut aad = Vec::with_capacity(
        AAD_PREFIX.len() + 1 + parts.iter().map(|part| 2 + part.len()).sum::<usize>(),
    );
    aad.extend_from_slice(AAD_PREFIX);
    aad.push(version);
    for part in parts {
        let length = u16::try_from(part.len())
            .map_err(|_| FormatError::InvalidIdentifier("associated data part"))?;
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    Ok(aad)
}

/// Seals a secret and its policy to a public key.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if the policy is not valid,
/// [`FormatError::PlaintextTooLarge`] if the secret and policy do not fit in an
/// envelope, and [`FormatError::SealFailed`] if encryption fails.
pub fn seal(
    public_key: &PublicKey,
    kid: &KeyId,
    binding: Binding<'_>,
    secret: &[u8],
    policy: &Policy,
) -> Result<Envelope, FormatError> {
    seal_with(
        public_key,
        kid,
        binding,
        secret,
        policy,
        |key, plaintext, aad| {
            hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
                &OpModeS::Base,
                key,
                INFO,
                plaintext,
                aad,
            )
        },
    )
}

fn seal_with(
    public_key: &PublicKey,
    kid: &KeyId,
    binding: Binding<'_>,
    secret: &[u8],
    policy: &Policy,
    encrypt: impl FnOnce(&HpkePublicKey, &[u8], &[u8]) -> Result<(EncappedKey, Vec<u8>), HpkeError>,
) -> Result<Envelope, FormatError> {
    policy.validate()?;
    let plaintext = encode_plaintext(secret, policy)?;
    let aad = associated_data(VERSION, kid, binding)?;
    let (enc, ct) =
        encrypt(&public_key.to_hpke()?, &plaintext, &aad).map_err(|_| FormatError::SealFailed)?;
    Ok(Envelope {
        v: VERSION,
        keyset: binding.keyset.clone(),
        kid: kid.clone(),
        enc: enc.to_bytes().to_vec(),
        ct,
    })
}

/// Writes `{"policy":…,"secret":{"b64":"…"}}` into a buffer sized up front, so
/// that it never reallocates and leaves a copy of the secret behind.
fn encode_plaintext(secret: &[u8], policy: &Policy) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    const BEFORE_POLICY: &[u8] = b"{\"policy\":";
    const BEFORE_SECRET: &[u8] = b",\"secret\":{\"b64\":\"";
    const AFTER_SECRET: &[u8] = b"\"}}";

    let policy = policy.canonical_json()?;
    let secret_len = secret.len().div_ceil(3) * 4;
    let capacity =
        BEFORE_POLICY.len() + policy.len() + BEFORE_SECRET.len() + secret_len + AFTER_SECRET.len();
    if capacity + TAG_BYTES > MAX_CT_BYTES {
        return Err(FormatError::PlaintextTooLarge);
    }

    let mut encoded = Zeroizing::new(vec![0_u8; secret_len]);
    let written = URL_SAFE_NO_PAD
        .encode_slice(secret, &mut encoded)
        .map_err(|_| FormatError::SealFailed)?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(capacity));
    plaintext.extend_from_slice(BEFORE_POLICY);
    plaintext.extend_from_slice(&policy);
    plaintext.extend_from_slice(BEFORE_SECRET);
    plaintext.extend_from_slice(&encoded[..written]);
    plaintext.extend_from_slice(AFTER_SECRET);
    Ok(plaintext)
}

#[cfg(feature = "test-vectors")]
pub use deterministic::seal_with_ephemeral_ikm;

/// Sealing with fixed randomness, for test vectors only.
#[cfg(feature = "test-vectors")]
mod deterministic {
    use std::convert::Infallible;

    use hpke::rand_core::{TryCryptoRng, TryRng};

    use super::{
        AesGcm256, Binding, Envelope, FormatError, HkdfSha256, INFO, KeyId, OpModeS, Policy,
        PublicKey, X25519HkdfSha256, seal_with,
    };

    /// Hands out fixed bytes. Never use this outside test vectors.
    struct FixedBytes<'a>(&'a [u8]);

    impl TryRng for FixedBytes<'_> {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Infallible> {
            let (now, later) = self.0.split_at(destination.len());
            destination.copy_from_slice(now);
            self.0 = later;
            Ok(())
        }
    }

    impl TryCryptoRng for FixedBytes<'_> {}

    /// Seals with a fixed ephemeral key, derived from `ikm` as RFC 9180 does.
    ///
    /// Available only with the `test-vectors` feature, which nothing but tests
    /// enables: reusing an ephemeral key breaks the encryption.
    ///
    /// # Errors
    ///
    /// As for [`seal`](super::seal).
    pub fn seal_with_ephemeral_ikm(
        public_key: &PublicKey,
        kid: &KeyId,
        binding: Binding<'_>,
        secret: &[u8],
        policy: &Policy,
        ikm: &[u8; super::KEY_BYTES],
    ) -> Result<Envelope, FormatError> {
        seal_with(
            public_key,
            kid,
            binding,
            secret,
            policy,
            |key, plaintext, aad| {
                hpke::single_shot_seal_with_rng::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
                    &OpModeS::Base,
                    key,
                    INFO,
                    plaintext,
                    aad,
                    &mut FixedBytes(ikm),
                )
            },
        )
    }
}

#[cfg(feature = "open")]
pub use opening::{PrivateKey, Sealed, open};

/// Opening. Not compiled without the `open` feature, so that a sealing-only
/// build has no code path to a plaintext.
#[cfg(feature = "open")]
mod opening {
    use std::fmt;

    use hpke::OpModeR;
    use serde::Deserialize;
    use zeroize::Zeroize;

    use super::{
        AesGcm256, Binding, Deserializable, EncappedKey, Engine, Envelope, FormatError, HkdfSha256,
        INFO, KEY_BYTES, Kem, Policy, PublicKey, Serializable, URL_SAFE_NO_PAD, VERSION,
        X25519HkdfSha256, Zeroizing, associated_data,
    };
    use crate::envelope::ENC_BYTES;
    use crate::secret::Secret;

    type HpkePrivateKey = <X25519HkdfSha256 as Kem>::PrivateKey;

    /// A keyset's private key. Like [`Secret`], it wipes itself on drop, redacts
    /// `Debug`, and can be read only through an explicit `expose`.
    pub struct PrivateKey(Secret);

    impl PrivateKey {
        /// Generates a new key pair from the operating system's random source.
        #[must_use]
        pub fn generate() -> (Self, PublicKey) {
            let (private, public) = X25519HkdfSha256::gen_keypair();
            let mut bytes = private.to_bytes();
            let key = Self(Secret::new(&bytes));
            bytes.as_mut_slice().zeroize();
            (key, PublicKey(public.to_bytes().into()))
        }

        /// Wraps a private key's bytes. The caller still owns the original.
        ///
        /// # Errors
        ///
        /// Returns [`FormatError::InvalidKey`] if the length is wrong.
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, FormatError> {
            if bytes.len() != KEY_BYTES {
                return Err(FormatError::InvalidKey);
            }
            Ok(Self(Secret::new(bytes)))
        }

        /// The matching public key.
        ///
        /// # Errors
        ///
        /// Returns [`FormatError::InvalidKey`] if the key is malformed.
        pub fn public_key(&self) -> Result<PublicKey, FormatError> {
            let public = X25519HkdfSha256::sk_to_pk(&self.to_hpke()?);
            Ok(PublicKey(public.to_bytes().into()))
        }

        /// Runs `read` with the key's bytes, such as to wrap them. The bytes
        /// must not outlive the call.
        pub fn expose<R>(&self, read: impl FnOnce(&[u8]) -> R) -> R {
            self.0.expose(read)
        }

        fn to_hpke(&self) -> Result<HpkePrivateKey, FormatError> {
            self.expose(HpkePrivateKey::from_bytes)
                .map_err(|_| FormatError::InvalidKey)
        }
    }

    impl fmt::Debug for PrivateKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("PrivateKey([REDACTED])")
        }
    }

    /// The contents of an opened value.
    pub struct Sealed {
        /// The secret.
        pub secret: Secret,
        /// The rules for using it.
        pub policy: Policy,
    }

    impl fmt::Debug for Sealed {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Sealed")
                .field("secret", &self.secret)
                .field("policy", &self.policy)
                .finish()
        }
    }

    /// Opens a value presented for `binding`.
    ///
    /// The envelope's keyset is checked against the binding before any
    /// cryptography, and the associated data covers it again. A value whose
    /// policy is not valid does not open.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::KeysetMismatch`] if the keyset differs, and
    /// [`FormatError::OpenFailed`] if the value does not decrypt under this key
    /// and binding or its contents are not valid.
    pub fn open(
        private_key: &PrivateKey,
        envelope: &Envelope,
        binding: Binding<'_>,
    ) -> Result<Sealed, FormatError> {
        if envelope.keyset != *binding.keyset {
            return Err(FormatError::KeysetMismatch);
        }
        if envelope.v != VERSION || envelope.enc.len() != ENC_BYTES {
            return Err(FormatError::OpenFailed);
        }
        let aad = associated_data(envelope.v, &envelope.kid, binding)?;
        let enc = EncappedKey::from_bytes(&envelope.enc).map_err(|_| FormatError::OpenFailed)?;
        let plaintext = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &private_key.to_hpke()?,
            &enc,
            INFO,
            &envelope.ct,
            &aad,
        )
        .map(Zeroizing::new)
        .map_err(|_| FormatError::OpenFailed)?;
        decode_plaintext(&plaintext)
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RawPlaintext<'a> {
        policy: Policy,
        #[serde(borrow)]
        secret: RawSecret<'a>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RawSecret<'a> {
        // Borrowed, so that parsing makes no copy of the secret. Base64url needs
        // no JSON escapes, so a value that has them is refused.
        b64: &'a str,
    }

    fn decode_plaintext(plaintext: &[u8]) -> Result<Sealed, FormatError> {
        let raw: RawPlaintext<'_> =
            serde_json::from_slice(plaintext).map_err(|_| FormatError::OpenFailed)?;
        raw.policy.validate().map_err(|_| FormatError::OpenFailed)?;
        let mut secret = Zeroizing::new(vec![0_u8; raw.secret.b64.len() / 4 * 3 + 3]);
        let length = URL_SAFE_NO_PAD
            .decode_slice(raw.secret.b64, &mut secret)
            .map_err(|_| FormatError::OpenFailed)?;
        Ok(Sealed {
            secret: Secret::new(&secret[..length]),
            policy: raw.policy,
        })
    }
}

// The crate's tests always have `open`, through its self dev-dependency.
#[cfg(test)]
mod tests;
