"""
Kyber Key Encapsulation Mechanism (KEM)

Kyber is a lattice-based key encapsulation mechanism selected for standardization
by NIST as part of the PQC standardization process.
"""

from typing import Tuple, Optional
from . import _core
from .exceptions import QyberSafeError


class KyberKeyPair:
    """Kyber key pair containing public and private keys."""

    def __init__(self, public_key: bytes, private_key: bytes):
        self.public_key = public_key
        self.private_key = private_key

    def __repr__(self) -> str:
        return f"KyberKeyPair(public_key_len={len(self.public_key)}, private_key_len={len(self.private_key)})"


class SecurityLevel:
    """Kyber security levels."""
    KYBER512 = 1    # ~128-bit quantum security
    KYBER768 = 2    # ~192-bit quantum security (recommended)
    KYBER1024 = 3   # ~256-bit quantum security


def generate_keypair(level: int = SecurityLevel.KYBER768) -> KyberKeyPair:
    """
    Generate a Kyber key pair.

    Args:
        level: Security level (SecurityLevel.KYBER512, KYBER768, or KYBER1024)

    Returns:
        KyberKeyPair: The generated key pair

    Raises:
        QyberSafeError: If key generation fails
    """
    try:
        public_key, private_key = _core.kyber_generate_keypair(level)
        return KyberKeyPair(public_key, private_key)
    except Exception as e:
        raise QyberSafeError(f"Failed to generate Kyber key pair: {e}") from e


def encrypt(public_key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt data using Kyber.

    Args:
        public_key: The public key to encrypt with
        plaintext: The data to encrypt

    Returns:
        bytes: The encrypted ciphertext

    Raises:
        QyberSafeError: If encryption fails
    """
    try:
        return _core.kyber_encrypt(public_key, plaintext)
    except Exception as e:
        raise QyberSafeError(f"Kyber encryption failed: {e}") from e


def decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt data using Kyber.

    Args:
        private_key: The private key to decrypt with
        ciphertext: The ciphertext to decrypt

    Returns:
        bytes: The decrypted plaintext

    Raises:
        QyberSafeError: If decryption fails
    """
    try:
        return _core.kyber_decrypt(private_key, ciphertext)
    except Exception as e:
        raise QyberSafeError(f"Kyber decryption failed: {e}") from e


def encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using Kyber KEM.

    Args:
        public_key: The public key to encapsulate with

    Returns:
        Tuple[bytes, bytes]: (ciphertext, shared_secret)

    Raises:
        QyberSafeError: If encapsulation fails
    """
    try:
        ciphertext, shared_secret = _core.kyber_encapsulate(public_key)
        return ciphertext, shared_secret
    except Exception as e:
        raise QyberSafeError(f"Kyber encapsulation failed: {e}") from e


def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate a shared secret using Kyber KEM.

    Args:
        private_key: The private key to decapsulate with
        ciphertext: The ciphertext from encapsulate()

    Returns:
        bytes: The shared secret

    Raises:
        QyberSafeError: If decapsulation fails
    """
    try:
        return _core.kyber_decapsulate(private_key, ciphertext)
    except Exception as e:
        raise QyberSafeError(f"Kyber decapsulation failed: {e}") from e


# KEM interface for compatibility
class KyberKEM:
    """Key Encapsulation Mechanism interface for Kyber."""

    def __init__(self, level: int = SecurityLevel.KYBER768):
        self.level = level
        self._keypair = None

    def generate_keypair(self) -> KyberKeyPair:
        """Generate a new key pair."""
        self._keypair = generate_keypair(self.level)
        return self._keypair

    def set_keypair(self, keypair: KyberKeyPair):
        """Set an existing key pair."""
        self._keypair = keypair

    def encapsulate(self, public_key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret.

        Args:
            public_key: Public key to use (uses stored key if None)

        Returns:
            Tuple[bytes, bytes]: (ciphertext, shared_secret)
        """
        if public_key is None:
            if self._keypair is None:
                raise QyberSafeError("No key pair available. Call generate_keypair() first.")
            public_key = self._keypair.public_key

        return encapsulate(public_key)

    def decapsulate(self, ciphertext: bytes, private_key: Optional[bytes] = None) -> bytes:
        """
        Decapsulate a shared secret.

        Args:
            ciphertext: Ciphertext from encapsulate()
            private_key: Private key to use (uses stored key if None)

        Returns:
            bytes: The shared secret
        """
        if private_key is None:
            if self._keypair is None:
                raise QyberSafeError("No key pair available. Call generate_keypair() first.")
            private_key = self._keypair.private_key

        return decapsulate(private_key, ciphertext)