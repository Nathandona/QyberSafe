"""
QyberSafe - Modern Post-Quantum Cryptography Library

QyberSafe provides easy-to-use post-quantum cryptographic primitives
including Kyber (KEM), Dilithium (signatures), and SPHINCS+ (hash-based signatures).

This Python package provides a high-level interface to the QyberSafe C++ library
with type safety, comprehensive error handling, and modern Python features.
"""

from __future__ import annotations

import sys
from typing import Final

# Version information
__version__: Final[str] = "0.1.0"
__version_info__: Final[tuple[int, int, int]] = (0, 1, 0)
__author__: Final[str] = "QyberSafe Team"
__email__: Final[str] = "info@qybersafe.io"
__license__: Final[str] = "MIT"
__copyright__: Final[str] = "2024 QyberSafe Team"
__url__: Final[str] = "https://github.com/qybersafe/qybersafe"

# Check Python version compatibility
if sys.version_info < (3, 8):
    raise RuntimeError(
        f"QyberSafe requires Python 3.8 or newer, but you are using Python {sys.version}"
    )

# Import the core C++ module
try:
    from . import _core
except ImportError as e:
    raise ImportError(
        "Failed to import QyberSafe C++ core. Please ensure the library is properly built.\n"
        "You may need to install from source with: pip install .\n"
        f"Error: {e}"
    ) from e

# Import public API modules
from . import kyber
from . import dilithium
from . import sphincsplus
from . import hybrid
from . import exceptions

# Import commonly used classes and functions for convenience
from .kyber import KyberKeyPair, SecurityLevel, generate_keypair, encrypt, decrypt
from .exceptions import (
    QyberSafeError,
    KeyGenerationError,
    EncryptionError,
    DecryptionError,
    SignatureError,
    VerificationError,
    InvalidKeyError,
    InvalidParameterError,
    UnsupportedAlgorithmError,
    MemoryError,
    SecurityLevelError,
)

# Package metadata
__all__ = [
    # Version info
    "__version__",
    "__version_info__",
    "__author__",
    "__email__",
    "__license__",
    "__copyright__",
    "__url__",

    # Core modules
    "kyber",
    "dilithium",
    "sphincsplus",
    "hybrid",
    "exceptions",

    # Main API classes and functions (from kyber module)
    "KyberKeyPair",
    "SecurityLevel",
    "generate_keypair",
    "encrypt",
    "decrypt",

    # Exception classes
    "QyberSafeError",
    "KeyGenerationError",
    "EncryptionError",
    "DecryptionError",
    "SignatureError",
    "VerificationError",
    "InvalidKeyError",
    "InvalidParameterError",
    "UnsupportedAlgorithmError",
    "MemoryError",
    "SecurityLevelError",
]

def get_version() -> str:
    """Get the version string of QyberSafe."""
    return __version__

def get_version_info() -> tuple[int, int, int]:
    """Get the version info tuple of QyberSafe."""
    return __version_info__

def get_build_info() -> dict[str, str]:
    """Get build information about the QyberSafe library."""
    try:
        # Try to get build info from the core module if available
        if hasattr(_core, "get_build_info"):
            return _core.get_build_info()
    except Exception:
        pass

    return {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "qybersafe_version": __version__,
        "platform": sys.platform,
    }

# Module-level documentation
def __doc__():
    """
    QyberSafe Python API Documentation
    ==================================

    Quick Start:
        >>> import qybersafe
        >>> # Generate a Kyber key pair
        >>> keypair = qybersafe.generate_keypair()
        >>> # Encrypt and decrypt data
        >>> plaintext = b"Hello, post-quantum world!"
        >>> ciphertext = qybersafe.encrypt(keypair.public_key, plaintext)
        >>> decrypted = qybersafe.decrypt(keypair.private_key, ciphertext)
        >>> assert plaintext == decrypted

    For more detailed documentation, see:
    - https://qybersafe.readthedocs.io/
    - Individual module documentation (kyber, dilithium, etc.)
    """