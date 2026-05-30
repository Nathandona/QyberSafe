"""Tests for the QyberSafe Python bindings (the envelope-first API)."""

import pytest

import qybersafe as qs


# --- Encryption ------------------------------------------------------------

def test_seal_open_roundtrip():
    kp = qs.generate_encryption_keypair()
    envelope = qs.seal(kp.public_key, b"hello python")
    assert qs.open(kp.private_key, envelope) == b"hello python"


def test_aad_must_match():
    kp = qs.generate_encryption_keypair()
    envelope = qs.seal(kp.public_key, b"secret", b"ctx")
    assert qs.open(kp.private_key, envelope, b"ctx") == b"secret"
    with pytest.raises(qs.CryptoError):
        qs.open(kp.private_key, envelope, b"wrong")
    with pytest.raises(qs.CryptoError):
        qs.open(kp.private_key, envelope)


def test_wrong_key_raises():
    kp = qs.generate_encryption_keypair()
    other = qs.generate_encryption_keypair()
    envelope = qs.seal(kp.public_key, b"x")
    with pytest.raises(qs.CryptoError):
        qs.open(other.private_key, envelope)


def test_empty_and_large_messages():
    kp = qs.generate_encryption_keypair()
    for message in (b"", b"A" * 8192):
        assert qs.open(kp.private_key, qs.seal(kp.public_key, message)) == message


def test_encryption_key_serialization():
    kp = qs.generate_encryption_keypair()
    pub = qs.EncryptionPublicKey.from_bytes(kp.public_key.to_bytes())
    priv = qs.EncryptionPrivateKey.from_bytes(kp.private_key.to_bytes())
    envelope = qs.seal(pub, b"roundtrip")
    assert qs.open(priv, envelope) == b"roundtrip"


def test_derived_public_key():
    kp = qs.generate_encryption_keypair()
    assert kp.private_key.public_key().to_bytes() == kp.public_key.to_bytes()


def test_rejects_malformed_envelope():
    kp = qs.generate_encryption_keypair()
    with pytest.raises(qs.CryptoError):
        qs.open(kp.private_key, b"\x01\x02")


# --- Signatures ------------------------------------------------------------

@pytest.mark.parametrize(
    "alg",
    [
        qs.SignAlg.ML_DSA_44,
        qs.SignAlg.ML_DSA_65,
        qs.SignAlg.ML_DSA_87,
        qs.SignAlg.SLH_DSA_128s,
        qs.SignAlg.SLH_DSA_192s,
        qs.SignAlg.SLH_DSA_256s,
    ],
)
def test_sign_verify(alg):
    kp = qs.generate_signing_keypair(alg)
    signature = qs.sign(kp.private_key, b"message")
    assert qs.verify(kp.public_key, b"message", signature)
    assert not qs.verify(kp.public_key, b"other", signature)


def test_default_algorithm_is_ml_dsa_65():
    kp = qs.generate_signing_keypair()
    assert kp.public_key.algorithm == qs.SignAlg.ML_DSA_65


def test_signing_key_serialization():
    kp = qs.generate_signing_keypair(qs.SignAlg.ML_DSA_65)
    pub = qs.SigningPublicKey.from_bytes(kp.public_key.to_bytes())
    priv = qs.SigningPrivateKey.from_bytes(kp.private_key.to_bytes())
    assert pub.algorithm == qs.SignAlg.ML_DSA_65
    assert priv.algorithm == qs.SignAlg.ML_DSA_65
    signature = qs.sign(priv, b"m")
    assert qs.verify(pub, b"m", signature)


def test_slh_dsa_serialization():
    kp = qs.generate_signing_keypair(qs.SignAlg.SLH_DSA_192s)
    pub = qs.SigningPublicKey.from_bytes(kp.public_key.to_bytes())
    assert pub.algorithm == qs.SignAlg.SLH_DSA_192s
    signature = qs.sign(kp.private_key, b"m")
    assert qs.verify(pub, b"m", signature)
