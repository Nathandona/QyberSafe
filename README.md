<p align="center">
  <img src="assets/banner.svg" alt="QyberSafe" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Nathandona/QyberSafe/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Nathandona/QyberSafe/ci.yml?branch=main&style=flat-square&label=build&logo=github&logoColor=white" alt="Build status"></a>
  <img src="https://img.shields.io/badge/version-0.1.0--alpha-38bdf8?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-3b82f6?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square&logo=cplusplus&logoColor=white" alt="C++17">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-475569?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/NIST-FIPS%20203%20%2F%20204%20%2F%20205-1e293b?style=flat-square" alt="NIST FIPS">
  <img src="https://img.shields.io/badge/PRs-welcome-6366f1?style=flat-square" alt="PRs welcome">
</p>

# QyberSafe

QyberSafe is a modern C++ and Python library for integrating post-quantum cryptography into real applications. It provides modular, crypto-agile primitives for quantum-resistant key exchange, digital signatures, and hybrid encryption, built for fintech, cloud, and enterprise systems that need to stay secure against future quantum attacks.

Classical algorithms such as RSA and ECC are vulnerable to large-scale quantum computers. QyberSafe implements the NIST-standardized lattice and hash based schemes so you can defend against "harvest now, decrypt later" attacks today, with an API designed to swap algorithms as standards evolve.

> Status: 0.1.0 alpha. The API is stabilizing and not yet recommended for production deployments.

## Features

- One small, misuse-resistant API: `seal` / `open` for encryption, `sign` / `verify` for signatures
- First-class C++17 and Python, sharing a single audited core (liboqs)
- NIST-standardized algorithms: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
- Hybrid encryption by default: X25519 combined with ML-KEM-768, so confidentiality holds even if one half is broken
- Self-describing, versioned key and ciphertext formats for crypto agility
- Authenticated encryption (AES-256-GCM) with optional associated data
- Security-focused: audited primitives, secure memory zeroing, no homemade cryptography
- Continuous integration on Linux and macOS, including an AddressSanitizer/UBSan build

## Algorithms

| Algorithm (alias)     | Type                  | NIST standard | Parameter sets                       |
|-----------------------|-----------------------|---------------|--------------------------------------|
| ML-KEM (Kyber)        | Key encapsulation     | FIPS 203      | ML-KEM-512 / 768 / 1024              |
| ML-DSA (Dilithium)    | Signature             | FIPS 204      | ML-DSA-44 / 65 / 87                  |
| SLH-DSA (SPHINCS+)    | Hash-based signature  | FIPS 205      | SLH-DSA-SHA2-128s / 192s / 256s      |
| Hybrid                | Classical + PQC       | -             | X25519 + ML-KEM-768 + AES-256-GCM    |

Parameter sets map to roughly 128, 192, and 256 bit security. The defaults
(ML-KEM-768, ML-DSA-65) suit most workloads.

## Installation

Requirements: a C++17 compiler (GCC 11+, Clang, or MSVC), CMake 3.16+, and
OpenSSL. liboqs is fetched and built automatically. Python 3.8+ is needed for
the Python package.

### Python

From a clone (liboqs is statically bundled into the extension):

```bash
git clone https://github.com/Nathandona/QyberSafe.git
cd QyberSafe
pip install .
```

### C++

```bash
git clone https://github.com/Nathandona/QyberSafe.git
cd QyberSafe
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The C++ headers and library install with `cmake --install build`.

## Quick start

### C++

```cpp
#include <qybersafe/qybersafe.h>

using namespace qybersafe;

int main() {
    // Hybrid encryption (X25519 + ML-KEM-768)
    auto enc = generate_encryption_keypair();
    bytes message = {'h', 'e', 'l', 'l', 'o'};
    bytes envelope = seal(enc.public_key, message);
    bytes recovered = open(enc.private_key, envelope);

    // Signatures (ML-DSA-65 by default)
    auto signer = generate_signing_keypair();
    bytes signature = sign(signer.private_key, message);
    bool valid = verify(signer.public_key, message, signature);

    return (recovered == message && valid) ? 0 : 1;
}
```

### Python

```python
import qybersafe as qs

# Hybrid encryption, with optional associated data
enc = qs.generate_encryption_keypair()
envelope = qs.seal(enc.public_key, b"Hello, post-quantum world!", aad=b"context")
assert qs.open(enc.private_key, envelope, aad=b"context") == b"Hello, post-quantum world!"

# Signatures (ML-DSA-65 by default)
signer = qs.generate_signing_keypair()
signature = qs.sign(signer.private_key, b"message")
assert qs.verify(signer.public_key, b"message", signature)
```

Operations raise `CryptoError` on failure; `verify` returns a bool. Keys are
opaque objects that serialize with `to_bytes()` / `from_bytes()`.

## Why post-quantum

A sufficiently powerful quantum computer running Shor's algorithm would break the public-key cryptography that secures most of the internet today. Attackers can already record encrypted traffic now and decrypt it later once such hardware exists, which is why long-lived secrets need quantum-resistant protection immediately. QyberSafe lets you adopt NIST PQC standards incrementally through hybrid modes, keeping classical guarantees while adding a post-quantum layer.

## Roadmap

- Additional language bindings (Go, Rust, JavaScript and WebAssembly)
- TLS and SSH hybrid protocol modules
- Hardware security module (HSM) integration
- Hardware acceleration and SIMD optimizations
- Benchmark suite and formal verification of critical components

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Documentation

The design and wire formats are documented in [SPEC.md](SPEC.md). The test
suites are usable as examples: [src/tests](src/tests) for C++ and
[python/tests](python/tests) for Python. API reference can be generated with
Doxygen via `cmake --build build --target docs`.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and file an issue for bugs, integration questions, or feature requests.

## Security

QyberSafe is alpha software and has not undergone an independent security audit. Do not rely on it to protect production secrets yet. Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/Nathandona/QyberSafe/security/advisories/new) rather than through public issues.

## License

Released under the MIT License.
