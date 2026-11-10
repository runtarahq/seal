#!/usr/bin/env python3
"""Checks vectors/envelope.json with an independent implementation.

This implements RFC 9180 base mode from primitives, sharing no code with
seal-format or the Rust `hpke` crate, so that the vectors cannot pass merely by
agreeing with the code that wrote them. It also shows what another
implementation of the format has to do.

Needs `pip install cryptography`, for X25519 and AES-GCM.
"""

import base64
import hashlib
import hmac
import json
import pathlib
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0002
KEM_SUITE = b"KEM" + struct.pack(">H", KEM_ID)
HPKE_SUITE = b"HPKE" + struct.pack(">HHH", KEM_ID, KDF_ID, AEAD_ID)
INFO = b"seal/v1"
HASH_BYTES, KEY_BYTES, NONCE_BYTES = 32, 32, 12
MODE_BASE = 0


def extract(salt, ikm):
    return hmac.new(salt or b"\0" * HASH_BYTES, ikm, hashlib.sha256).digest()


def expand(prk, info, length):
    output, block, counter = b"", b"", 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def labeled_extract(suite, salt, label, ikm):
    return extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return expand(prk, struct.pack(">H", length) + b"HPKE-v1" + suite + label + info, length)


def derive_key_pair(ikm):
    prk = labeled_extract(KEM_SUITE, b"", b"dkp_prk", ikm)
    private = labeled_expand(KEM_SUITE, prk, b"sk", b"", 32)
    return private, public_bytes(private)


def public_bytes(private):
    key = X25519PrivateKey.from_private_bytes(private).public_key()
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def shared_secret(dh, enc, recipient_public):
    prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return labeled_expand(KEM_SUITE, prk, b"shared_secret", enc + recipient_public, HASH_BYTES)


def key_schedule(secret):
    psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", INFO)
    context = bytes([MODE_BASE]) + psk_id_hash + info_hash
    prk = labeled_extract(HPKE_SUITE, secret, b"secret", b"")
    key = labeled_expand(HPKE_SUITE, prk, b"key", context, KEY_BYTES)
    nonce = labeled_expand(HPKE_SUITE, prk, b"base_nonce", context, NONCE_BYTES)
    return key, nonce


def seal(recipient_public, ephemeral_ikm, aad, plaintext):
    ephemeral_private, enc = derive_key_pair(ephemeral_ikm)
    recipient = X25519PublicKey.from_public_bytes(recipient_public)
    dh = X25519PrivateKey.from_private_bytes(ephemeral_private).exchange(recipient)
    key, nonce = key_schedule(shared_secret(dh, enc, recipient_public))
    return enc, AESGCM(key).encrypt(nonce, plaintext, aad)


def open_value(private, enc, aad, ciphertext):
    dh = X25519PrivateKey.from_private_bytes(private).exchange(
        X25519PublicKey.from_public_bytes(enc)
    )
    key, nonce = key_schedule(shared_secret(dh, enc, public_bytes(private)))
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def associated_data(version, keyset, kid, item, field):
    aad = b"seal/v1/aad" + bytes([version])
    for part in (keyset, kid, item, field):
        encoded = part.encode()
        aad += struct.pack(">H", len(encoded)) + encoded
    return aad


def check_rfc_vector():
    """The base mode vector for this suite, from the CFRG HPKE test vectors."""
    ikm_r = bytes.fromhex("dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee")
    ikm_e = bytes.fromhex("2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9")
    expected_ct = "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a"
    private, public = derive_key_pair(ikm_r)
    assert public.hex() == "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c"
    ephemeral_private, enc = derive_key_pair(ikm_e)
    assert enc.hex() == "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256"

    dh = X25519PrivateKey.from_private_bytes(ephemeral_private).exchange(
        X25519PublicKey.from_public_bytes(public)
    )
    secret = shared_secret(dh, enc, public)
    psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
    info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    context = bytes([MODE_BASE]) + psk_id_hash + info_hash
    prk = labeled_extract(HPKE_SUITE, secret, b"secret", b"")
    key = labeled_expand(HPKE_SUITE, prk, b"key", context, KEY_BYTES)
    nonce = labeled_expand(HPKE_SUITE, prk, b"base_nonce", context, NONCE_BYTES)
    plaintext = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
    aad = bytes.fromhex("436f756e742d30")
    assert AESGCM(key).encrypt(nonce, plaintext, aad).hex() == expected_ct


def check_case(vectors, case):
    private = bytes.fromhex(vectors["private_key_hex"])
    public = bytes.fromhex(vectors["public_key_hex"])
    envelope = case["envelope"]

    assert envelope["v"] == 1
    assert envelope["keyset"] == case["keyset"]
    assert envelope["kid"] == case["kid"]
    aad = associated_data(1, case["keyset"], case["kid"], case["item"], case["field"])
    assert aad.hex() == case["aad_hex"]

    plaintext = case["plaintext"].encode()
    enc, ciphertext = seal(public, bytes.fromhex(case["ephemeral_ikm_hex"]), aad, plaintext)
    assert b64url(enc) == envelope["enc"], "enc differs"
    assert b64url(ciphertext) == envelope["ct"], "ct differs"

    opened = open_value(private, unb64url(envelope["enc"]), aad, unb64url(envelope["ct"]))
    assert opened == plaintext
    secret = unb64url(json.loads(opened)["secret"]["b64"])
    assert secret.hex() == case["secret_hex"]

    for change in case["must_not_open"]:
        parts = {key: case[key] for key in ("keyset", "kid", "item", "field")}
        key = private
        if change["change"] == "private_key_hex":
            key = bytes.fromhex(change["value"])
        else:
            parts[change["change"]] = change["value"]
        changed = associated_data(1, parts["keyset"], parts["kid"], parts["item"], parts["field"])
        try:
            open_value(key, unb64url(envelope["enc"]), changed, unb64url(envelope["ct"]))
        except InvalidTag:
            continue
        raise AssertionError(f"opened with a changed {change['change']}")


def main():
    path = pathlib.Path(__file__).with_name("envelope.json")
    vectors = json.loads(path.read_text())
    check_rfc_vector()
    assert public_bytes(bytes.fromhex(vectors["private_key_hex"])).hex() == vectors["public_key_hex"]
    for case in vectors["cases"]:
        check_case(vectors, case)
        print(f"ok: {case['name']}")
    print(f"verified the RFC 9180 vector and {len(vectors['cases'])} cases")


if __name__ == "__main__":
    sys.exit(main())
