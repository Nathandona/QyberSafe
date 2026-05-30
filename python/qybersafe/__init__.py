"""QyberSafe - post-quantum cryptography for Python.

A thin, Pythonic surface over the QyberSafe C++ core (the same audited liboqs
backend). Two high-level operations:

    seal / open    - hybrid public-key encryption (X25519 + ML-KEM-768)
    sign / verify  - post-quantum signatures (ML-DSA or SLH-DSA)

Example:
    >>> import qybersafe as qs
    >>> kp = qs.generate_encryption_keypair()
    >>> envelope = qs.seal(kp.public_key, b"secret", aad=b"context")
    >>> qs.open(kp.private_key, envelope, aad=b"context")
    b'secret'

    >>> sk = qs.generate_signing_keypair()          # ML-DSA-65 by default
    >>> sig = qs.sign(sk.private_key, b"message")
    >>> qs.verify(sk.public_key, b"message", sig)
    True

Operations raise qybersafe.CryptoError on failure; verify() returns a bool.
"""

from __future__ import annotations

from ._core import (
    CryptoError,
    SignAlg,
    EncryptionKeyPair,
    EncryptionPublicKey,
    EncryptionPrivateKey,
    SigningKeyPair,
    SigningPublicKey,
    SigningPrivateKey,
    generate_encryption_keypair,
    seal,
    open,
    generate_signing_keypair,
    sign,
    verify,
)

__version__ = "0.1.0"

__all__ = [
    "CryptoError",
    "SignAlg",
    "EncryptionKeyPair",
    "EncryptionPublicKey",
    "EncryptionPrivateKey",
    "SigningKeyPair",
    "SigningPublicKey",
    "SigningPrivateKey",
    "generate_encryption_keypair",
    "seal",
    "open",
    "generate_signing_keypair",
    "sign",
    "verify",
    "__version__",
]
