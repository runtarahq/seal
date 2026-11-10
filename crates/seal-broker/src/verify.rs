//! Checks a message's authentication code against a secret, and says only yes or no.
//!
//! A caller that could have a code computed could forge messages, and one that could
//! compare a prefix could find a code a byte at a time. So the code is never returned,
//! and only a code of the hash's full length can match, compared in constant time.

use ring::hmac;
use seal_format::policy::HmacHash;

/// Whether `mac` is the HMAC of `message` under `key`.
#[must_use]
pub fn hmac_matches(hash: HmacHash, key: &[u8], message: &[u8], mac: &[u8]) -> bool {
    let algorithm = match hash {
        HmacHash::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HmacHash::Sha256 => hmac::HMAC_SHA256,
        HmacHash::Sha512 => hmac::HMAC_SHA512,
    };
    // `ring` compares the whole code in constant time, and refuses another length.
    hmac::verify(&hmac::Key::new(algorithm, key), message, mac).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    /// RFC 2202 and RFC 4231, test case 2: key "Jefe".
    #[test]
    fn matches_the_published_test_vectors() {
        let message = b"what do ya want for nothing?";
        for (hash, mac) in [
            (HmacHash::Sha1, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
            (
                HmacHash::Sha256,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                HmacHash::Sha512,
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                 9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            ),
        ] {
            let mac = unhex(mac);
            assert!(hmac_matches(hash, b"Jefe", message, &mac), "{hash:?}");
            assert!(!hmac_matches(hash, b"Jefe", b"another message", &mac));
            assert!(!hmac_matches(hash, b"jefe", message, &mac));
        }
    }

    /// A shorter code that is right as far as it goes would let a caller find a code
    /// one byte at a time.
    #[test]
    fn a_truncated_or_padded_code_never_matches() {
        let message = b"what do ya want for nothing?";
        let mac = unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        for length in 0..mac.len() {
            assert!(!hmac_matches(
                HmacHash::Sha256,
                b"Jefe",
                message,
                &mac[..length]
            ));
        }
        let mut padded = mac.clone();
        padded.push(0);
        assert!(!hmac_matches(HmacHash::Sha256, b"Jefe", message, &padded));
        // Nor does a code made with another hash.
        assert!(!hmac_matches(HmacHash::Sha512, b"Jefe", message, &mac));
    }
}
