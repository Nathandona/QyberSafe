"""
QyberSafe exception classes.

This module defines all the custom exceptions used by the QyberSafe library.
Each exception provides specific context about the type of error that occurred
during cryptographic operations.
"""

from __future__ import annotations

from typing import Any, Optional


class QyberSafeError(Exception):
    """
    Base exception class for all QyberSafe errors.

    All QyberSafe-specific exceptions inherit from this class, making it easy
    to catch all QyberSafe-related errors with a single except clause.
    """

    def __init__(self, message: str, error_code: Optional[str] = None, context: Optional[dict[str, Any]] = None) -> None:
        """
        Initialize the exception.

        Args:
            message: Human-readable error message
            error_code: Machine-readable error code for programmatic handling
            context: Additional context information about the error
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}

    def __str__(self) -> str:
        """Return the error message."""
        return self.message

    def __repr__(self) -> str:
        """Return a detailed representation of the error."""
        parts = [f"{self.__class__.__name__}({self.message!r}"]
        if self.error_code:
            parts.append(f"error_code={self.error_code!r}")
        if self.context:
            parts.append(f"context={self.context!r}")
        return f"{', '.join(parts)})"


class KeyGenerationError(QyberSafeError):
    """
    Raised when key generation fails.

    This exception is used when there's an error during the generation of
    cryptographic keys, which could be due to insufficient entropy,
    memory allocation failures, or implementation-specific errors.
    """

    def __init__(self, message: str, algorithm: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the key generation error.

        Args:
            message: Human-readable error message
            algorithm: The algorithm for which key generation failed
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if algorithm:
            context["algorithm"] = algorithm
        kwargs["context"] = context
        super().__init__(message, **kwargs)


class EncryptionError(QyberSafeError):
    """
    Raised when encryption operation fails.

    This exception is used when there's an error during encryption,
    which could be due to invalid input data, key issues, or
    implementation-specific errors.
    """

    def __init__(self, message: str, algorithm: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the encryption error.

        Args:
            message: Human-readable error message
            algorithm: The algorithm that failed encryption
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if algorithm:
            context["algorithm"] = algorithm
        kwargs["context"] = context
        super().__init__(message, **kwargs)


class DecryptionError(QyberSafeError):
    """
    Raised when decryption operation fails.

    This exception is used when there's an error during decryption,
    which could be due to invalid ciphertext, key issues, or
    implementation-specific errors.
    """

    def __init__(self, message: str, algorithm: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the decryption error.

        Args:
            message: Human-readable error message
            algorithm: The algorithm that failed decryption
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if algorithm:
            context["algorithm"] = algorithm
        kwargs["context"] = context
        super().__init__(message, **kwargs)


class SignatureError(QyberSafeError):
    """
    Raised when signing operation fails.

    This exception is used when there's an error during digital signature
    generation, which could be due to invalid input data, key issues,
    or implementation-specific errors.
    """

    def __init__(self, message: str, algorithm: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the signature error.

        Args:
            message: Human-readable error message
            algorithm: The signature algorithm that failed
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if algorithm:
            context["algorithm"] = algorithm
        kwargs["context"] = context
        super().__init__(message, **kwargs)


class VerificationError(QyberSafeError):
    """
    Raised when signature verification fails.

    This exception is used when signature verification fails, which could be
    due to an invalid signature, mismatching message, or other verification issues.
    """

    def __init__(self, message: str, algorithm: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the verification error.

        Args:
            message: Human-readable error message
            algorithm: The verification algorithm that failed
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if algorithm:
            context["algorithm"] = algorithm
        kwargs["context"] = context
        super().__init__(message, **kwargs)


class InvalidKeyError(QyberSafeError):
    """
    Raised when an invalid key is provided.

    This exception is used when a provided key doesn't meet the required
    format, size, or other validation criteria.
    """

    def __init__(self, message: str, key_type: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the invalid key error.

        Args:
            message: Human-readable error message
            key_type: The type of key that was invalid (e.g., "public", "private")
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if key_type:
            context["key_type"] = key_type
        kwargs["context"] = context
        super().__init__(message, **kwargs)


class InvalidParameterError(QyberSafeError):
    """
    Raised when invalid parameters are provided.

    This exception is used when function parameters don't meet the required
    validation criteria, such as invalid ranges, types, or values.
    """

    def __init__(self, message: str, parameter_name: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the invalid parameter error.

        Args:
            message: Human-readable error message
            parameter_name: The name of the invalid parameter
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if parameter_name:
            context["parameter_name"] = parameter_name
        kwargs["context"] = context
        super().__init__(message, **kwargs)


class UnsupportedAlgorithmError(QyberSafeError):
    """
    Raised when an unsupported algorithm is requested.

    This exception is used when a requested cryptographic algorithm
    is not supported by the current implementation or build configuration.
    """

    def __init__(self, message: str, algorithm: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the unsupported algorithm error.

        Args:
            message: Human-readable error message
            algorithm: The unsupported algorithm name
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if algorithm:
            context["algorithm"] = algorithm
        kwargs["context"] = context
        super().__init__(message, **kwargs)


class MemoryError(QyberSafeError):
    """
    Raised when memory allocation fails.

    This exception is used when the library cannot allocate sufficient memory
    for cryptographic operations, which could be due to system memory limits
    or fragmentation issues.
    """

    def __init__(self, message: str, requested_size: Optional[int] = None, **kwargs: Any) -> None:
        """
        Initialize the memory error.

        Args:
            message: Human-readable error message
            requested_size: The size of memory that failed to allocate (in bytes)
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if requested_size is not None:
            context["requested_size"] = requested_size
        kwargs["context"] = context
        super().__init__(message, **kwargs)


class SecurityLevelError(QyberSafeError):
    """
    Raised when an invalid security level is specified.

    This exception is used when an invalid or unsupported security level
    is requested for a cryptographic operation.
    """

    def __init__(self, message: str, security_level: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize the security level error.

        Args:
            message: Human-readable error message
            security_level: The invalid security level that was requested
            **kwargs: Additional arguments passed to base class
        """
        context = kwargs.get("context", {})
        if security_level:
            context["security_level"] = security_level
        kwargs["context"] = context
        super().__init__(message, **kwargs)


# Convenience function for error handling
def handle_error(error: Exception, default_message: str = "An error occurred") -> QyberSafeError:
    """
    Convert a generic exception to a QyberSafe error.

    Args:
        error: The original exception
        default_message: Default message if no specific handling is available

    Returns:
        QyberSafeError: An appropriate QyberSafe exception
    """
    if isinstance(error, QyberSafeError):
        return error

    # Convert common Python exceptions to appropriate QyberSafe errors
    if isinstance(error, MemoryError):
        return MemoryError(f"Memory allocation failed: {error}")
    if isinstance(error, ValueError):
        return InvalidParameterError(f"Invalid parameter: {error}")
    if isinstance(error, TypeError):
        return InvalidParameterError(f"Invalid parameter type: {error}")
    if isinstance(error, OSError):
        return QyberSafeError(f"System error: {error}")

    # Default fallback
    return QyberSafeError(f"{default_message}: {error}")