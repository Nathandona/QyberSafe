"""
Setup script for QyberSafe Python bindings.

This script builds the Python interface to the QyberSafe C++ library
using pybind11 for modern C++/Python interoperability.
"""

import os
import sys
from pathlib import Path
from typing import List

from pybind11.setup_helpers import Pybind11Extension, build_ext
from pybind11 import get_cmake_dir
import pybind11
from setuptools import setup, Extension, find_packages


def get_long_description() -> str:
    """Read the long description from README.md."""
    readme_path = Path(__file__).parent / "README.md"
    if readme_path.exists():
        return readme_path.read_text(encoding="utf-8")
    return "Modern post-quantum cryptography library for Python"


def get_source_files() -> List[str]:
    """Get all C++ source files needed for the extension."""
    base_dir = Path(__file__).parent.parent
    sources = [
        str(base_dir / "src" / "bindings.cpp"),
        # Core source files
        str(base_dir / "src" / "src" / "core" / "crypto_types.cpp"),
        str(base_dir / "src" / "src" / "core" / "secure_random.cpp"),
        str(base_dir / "src" / "src" / "core" / "memory.cpp"),
        # Algorithm implementations
        str(base_dir / "src" / "src" / "kyber" / "kyber_kem.cpp"),
        str(base_dir / "src" / "src" / "dilithium" / "dilithium_sig.cpp"),
        str(base_dir / "src" / "src" / "sphincsplus" / "sphincsplus_sig.cpp"),
        str(base_dir / "src" / "src" / "hybrid" / "hybrid_encryption.cpp"),
    ]

    # Filter to only include files that exist
    return [src for src in sources if Path(src).exists()]


def get_include_dirs() -> List[str]:
    """Get all include directories for the compilation."""
    base_dir = Path(__file__).parent.parent
    include_dirs = [
        pybind11.get_include(),
        str(base_dir / "src" / "include"),
        str(base_dir / "src" / "src"),
    ]

    # Add OpenSSL include directory if available
    openssl_dirs = [
        "/usr/include/openssl",
        "/usr/local/include/openssl",
        "/opt/homebrew/include/openssl",
    ]

    for openssl_dir in openssl_dirs:
        if Path(openssl_dir).exists():
            include_dirs.append(openssl_dir)
            break

    return include_dirs


def get_libraries() -> List[str]:
    """Get required libraries for linking."""
    libraries = ["ssl", "crypto"]

    # Add platform-specific libraries if needed
    if sys.platform == "win32":
        libraries.extend(["ws2_32", "advapi32"])

    return libraries


# Define the extension module
ext_modules = [
    Pybind11Extension(
        "qybersafe._core",
        sources=get_source_files(),
        include_dirs=get_include_dirs(),
        libraries=get_libraries(),
        cxx_std=17,
        define_macros=[
            ("VERSION_INFO", '"dev"'),
            ("PYBIND11_DETAILED_ERROR_MESSAGES", None),
        ],
        extra_compile_args=["-O3"] if sys.platform != "win32" else ["/O2"],
    ),
]

# Read version from __init__.py
def get_version() -> str:
    """Extract version from __init__.py."""
    init_path = Path(__file__).parent / "qybersafe" / "__init__.py"
    if init_path.exists():
        with open(init_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    return line.split("=")[1].strip().strip('"\'')
    return "0.1.0"


setup(
    name="qybersafe",
    version=get_version(),
    author="QyberSafe Team",
    author_email="info@qybersafe.io",
    maintainer="QyberSafe Team",
    maintainer_email="info@qybersafe.io",
    description="Modern post-quantum cryptography library",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/qybersafe/qybersafe",
    project_urls={
        "Bug Reports": "https://github.com/qybersafe/qybersafe/issues",
        "Source": "https://github.com/qybersafe/qybersafe",
        "Documentation": "https://qybersafe.readthedocs.io/",
    },
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[
        "pybind11>=2.10.0",
        "typing-extensions>=3.10.0; python_version<'3.10'",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "pytest-benchmark>=4.0",
            "black>=22.0",
            "flake8>=5.0",
            "mypy>=0.991",
            "isort>=5.10",
            "pre-commit>=2.20",
        ],
        "docs": [
            "sphinx>=5.0",
            "sphinx-rtd-theme>=1.0",
            "myst-parser>=0.18",
        ],
        "benchmark": [
            "pytest-benchmark>=4.0",
            "memory-profiler>=0.60",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: C++",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering",
    ],
    keywords="cryptography post-quantum kyber dilithium sphincsplus security",
    zip_safe=False,
    include_package_data=True,
    package_data={
        "qybersafe": ["py.typed"],
    },
)