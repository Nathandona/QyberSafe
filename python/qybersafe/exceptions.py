"""
QyberSafe exception classes.

This module defines all the custom exceptions used by the QyberSafe library.
"""


class QyberSafeError(Exception):
    """Base exception class for all QyberSafe errors."""
    pass


class KeyGenerationError(QyberSafeError):
    """Raised when key generation fails."""
    pass


class EncryptionError(QyberSafeError):
    """Raised when encryption operation fails."""
    pass


class DecryptionError(QyberSafeError):
    """Raised when decryption operation fails."""
    pass


class SignatureError(QyberSafeError):
    """Raised when signing operation fails."""
    pass


class VerificationError(QyberSafeError):
    """Raised when signature verification fails."""
    pass


class InvalidKeyError(QyberSafeError):
    """Raised when an invalid key is provided."""
    pass


class InvalidParameterError(QyberSafeError):
    """Raised when invalid parameters are provided."""
    pass


class UnsupportedAlgorithmError(QyberSafeError):
    """Raised when an unsupported algorithm is requested."""
    pass


class MemoryError(QyberSafeError):
    """Raised when memory allocation fails."""
    pass


class SecurityLevelError(QyberSafeError):
    """Raised when an invalid security level is specified."""
    pass