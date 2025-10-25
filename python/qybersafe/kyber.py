"""
Kyber Key Encapsulation Mechanism (KEM)

Kyber is a lattice-based key encapsulation mechanism selected for standardization
by NIST as part of the PQC standardization process.

This module provides a high-level Python interface for Kyber operations
including key generation, encryption/decryption, and KEM operations.
"""

from __future__ import annotations

from typing import Tuple, Optional, Union, Final
from dataclasses import dataclass

from . import _core
from .exceptions import (
    QyberSafeError,
    KeyGenerationError,
    EncryptionError,
    DecryptionError,
    InvalidKeyError,
    InvalidParameterError,
)


@dataclass(frozen=True)
class KyberKeyPair:
    """Kyber key pair containing public and private keys.

    This class is immutable to ensure key security. Keys are stored as bytes
    and cannot be modified after creation.
    """
    public_key: bytes
    private_key: bytes

    def __post_init__(self) -> None:
        """Validate key pair after initialization."""
        if not isinstance(self.public_key, (bytes, bytearray)):
            raise InvalidKeyError("Public key must be bytes")
        if not isinstance(self.private_key, (bytes, bytearray)):
            raise InvalidKeyError("Private key must be bytes")
        if len(self.public_key) == 0:
            raise InvalidKeyError("Public key cannot be empty")
        if len(self.private_key) == 0:
            raise InvalidKeyError("Private key cannot be empty")

    def __repr__(self) -> str:
        """Return a string representation that doesn't expose key material."""
        return (f"KyberKeyPair(public_key_len={len(self.public_key)}, "
                f"private_key_len={len(self.private_key)})")

    def __str__(self) -> str:
        """Return a safe string representation."""
        return self.__repr__()


class SecurityLevel:
    """
    Kyber security levels.

    These constants define the security levels for Kyber operations:
    - KYBER512: ~128-bit quantum security, fastest performance
    - KYBER768: ~192-bit quantum security, recommended balance
    - KYBER1024: ~256-bit quantum security, highest security
    """
    KYBER512: Final[int] = 1    # ~128-bit quantum security
    KYBER768: Final[int] = 2    # ~192-bit quantum security (recommended)
    KYBER1024: Final[int] = 3   # ~256-bit quantum security

    # Mapping for validation
    _VALID_LEVELS = {KYBER512, KYBER768, KYBER1024}

    @classmethod
    def is_valid(cls, level: int) -> bool:
        """Check if a security level is valid."""
        return level in cls._VALID_LEVELS

    @classmethod
    def get_name(cls, level: int) -> str:
        """Get the name of a security level."""
        names = {
            cls.KYBER512: "Kyber512",
            cls.KYBER768: "Kyber768",
            cls.KYBER1024: "Kyber1024",
        }
        return names.get(level, "Unknown")

    @classmethod
    def get_description(cls, level: int) -> str:
        """Get the description of a security level."""
        descriptions = {
            cls.KYBER512: "~128-bit quantum security",
            cls.KYBER768: "~192-bit quantum security (recommended)",
            cls.KYBER1024: "~256-bit quantum security",
        }
        return descriptions.get(level, "Unknown security level")


def generate_keypair(level: int = SecurityLevel.KYBER768) -> KyberKeyPair:
    """
    Generate a Kyber key pair.

    Args:
        level: Security level (SecurityLevel.KYBER512, KYBER768, or KYBER1024)

    Returns:
        KyberKeyPair: The generated key pair

    Raises:
        InvalidParameterError: If the security level is invalid
        KeyGenerationError: If key generation fails
    """
    if not SecurityLevel.is_valid(level):
        raise InvalidParameterError(
            f"Invalid security level: {level}. "
            f"Valid levels are: {', '.join(str(l) for l in SecurityLevel._VALID_LEVELS)}"
        )

    try:
        public_key, private_key = _core.kyber_generate_keypair(level)
        return KyberKeyPair(public_key, private_key)
    except Exception as e:
        raise KeyGenerationError(
            f"Failed to generate Kyber key pair with {SecurityLevel.get_name(level)}: {e}"
        ) from e


def encrypt(public_key: Union[bytes, bytearray], plaintext: Union[bytes, bytearray]) -> bytes:
    """
    Encrypt data using Kyber.

    Args:
        public_key: The public key to encrypt with
        plaintext: The data to encrypt

    Returns:
        bytes: The encrypted ciphertext

    Raises:
        InvalidKeyError: If the public key is invalid
        InvalidParameterError: If the plaintext is invalid
        EncryptionError: If encryption fails
    """
    if not isinstance(public_key, (bytes, bytearray)):
        raise InvalidKeyError("Public key must be bytes or bytearray")
    if len(public_key) == 0:
        raise InvalidKeyError("Public key cannot be empty")

    if not isinstance(plaintext, (bytes, bytearray)):
        raise InvalidParameterError("Plaintext must be bytes or bytearray")
    if len(plaintext) == 0:
        raise InvalidParameterError("Plaintext cannot be empty")

    try:
        return _core.kyber_encrypt(bytes(public_key), bytes(plaintext))
    except Exception as e:
        raise EncryptionError(f"Kyber encryption failed: {e}") from e


def decrypt(private_key: Union[bytes, bytearray], ciphertext: Union[bytes, bytearray]) -> bytes:
    """
    Decrypt data using Kyber.

    Args:
        private_key: The private key to decrypt with
        ciphertext: The ciphertext to decrypt

    Returns:
        bytes: The decrypted plaintext

    Raises:
        InvalidKeyError: If the private key is invalid
        InvalidParameterError: If the ciphertext is invalid
        DecryptionError: If decryption fails
    """
    if not isinstance(private_key, (bytes, bytearray)):
        raise InvalidKeyError("Private key must be bytes or bytearray")
    if len(private_key) == 0:
        raise InvalidKeyError("Private key cannot be empty")

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise InvalidParameterError("Ciphertext must be bytes or bytearray")
    if len(ciphertext) == 0:
        raise InvalidParameterError("Ciphertext cannot be empty")

    try:
        return _core.kyber_decrypt(bytes(private_key), bytes(ciphertext))
    except Exception as e:
        raise DecryptionError(f"Kyber decryption failed: {e}") from e


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