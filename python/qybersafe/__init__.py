"""
QyberSafe - Modern Post-Quantum Cryptography Library

QyberSafe provides easy-to-use post-quantum cryptographic primitives
including Kyber (KEM), Dilithium (signatures), and SPHINCS+ (hash-based signatures).
"""

from . import kyber
from . import dilithium
from . import sphincsplus
from . import hybrid
from . import exceptions

__version__ = "0.1.0"
__author__ = "QyberSafe Team"
__email__ = "info@qybersafe.io"

# Import the core C++ module
try:
    from . import _core
except ImportError as e:
    raise ImportError(
        "Failed to import QyberSafe C++ core. Please ensure the library is properly built.\n"
        f"Error: {e}"
    ) from e

__all__ = [
    "kyber",
    "dilithium",
    "sphincsplus",
    "hybrid",
    "exceptions",
    "__version__",
]