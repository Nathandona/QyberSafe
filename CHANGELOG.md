# Changelog

All notable changes to QyberSafe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SPEC.md describing the v1 design (audience, liboqs backend, hybrid scheme, API, scope).
- liboqs vendored through CMake FetchContent (cmake/liboqs.cmake), pinned to 0.15.0.
- GoogleTest fetched through FetchContent so the C++ test suite is no longer skipped.
- Real ML-KEM (FIPS 203) key encapsulation backed by liboqs, with a passing test suite.
- Real ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) signatures backed by liboqs, with
  rewritten test suites for both.
- Hybrid public-key encryption (suite 0x0301: X25519 + ML-KEM-768 + AES-256-GCM)
  with an HKDF-SHA-256 combiner and a self-describing, versioned wire format.
- Envelope-first public API (`qybersafe.h`): `seal`/`open` and `sign`/`verify`
  with opaque keys, self-describing serialization, and a `CryptoError` exception
  model. The lower-level per-algorithm modules remain available.
- Associated-data (AAD) support for hybrid encryption / `seal`.
- LICENSE file (MIT).

### Changed
- Kyber and hybrid encrypt/decrypt are now an authenticated KEM-DEM (ML-KEM
  encapsulation, HKDF-SHA-256 key derivation, AES-256-GCM) instead of placeholders.
- Factored the shared symmetric layer (HKDF-SHA-256, CSPRNG, AES-256-GCM) into
  `core/aead` and routed the KEM-DEM and hybrid constructions through it.
- Strict compiler warnings are scoped to QyberSafe's own targets, not vendored code.

### Removed
- The non-secure "simplified for demonstration" lattice code that stood in for Kyber.

### Fixed
- Secure aligned allocation now works on Windows (MinGW/MSVC), not only POSIX.
- Removed an invalid `constexpr` on `Result<void>` and base64 char-subscript/type-limits
  warnings that broke a strict (`-Werror`) build under newer compilers.

### Security
- Cryptographic primitives are now provided by audited liboqs implementations rather
  than in-house code. The library is still pre-audit and not for production use.

## [0.1.0] - 2024-01-XX

### Added
- Initial release of QyberSafe post-quantum cryptography library
- Support for NIST-standard PQC algorithms:
  - Kyber (KEM)
  - Dilithium (signatures)
  - SPHINCS+ (hash-based signatures)
- Hybrid encryption modes combining classical and PQC algorithms
- C++17 API with modern C++ design
- Python bindings for easy integration
- Performance optimizations
- Security-focused implementation
- Comprehensive documentation
- Example applications

### Security
- Side-channel attack protection
- Secure memory management
- Constant-time operations
- FIPS 140-2 compliance considerations

### Performance
- Optimized implementations for x86-64 and ARM
- SIMD optimizations where applicable
- Hardware acceleration support

### Documentation
- API reference documentation
- Migration guides
- Best practices guide
- Security considerations

## [Upcoming]

### Planned Features
- Extended language bindings (Go, Rust, JavaScript/WebAssembly)
- Additional PQC algorithms (FrodoKEM, NTRU)
- Hardware security module (HSM) integration
- TLS/SSH hybrid protocol support
- Cloud-specific integrations
- Advanced testing and benchmarking suite
- Formal verification of critical components

### Performance Improvements
- Assembly-level optimizations
- GPU acceleration support
- Enhanced parallel processing
- Memory usage optimizations

### Security Enhancements
- Additional side-channel protections
- Quantum random number generator integration
- Advanced key management features
- Audit logging and compliance tools

---

## Version History

### Version 0.1.0 (Alpha)
- Initial public release
- Core PQC algorithm implementations
- Basic Python bindings
- Documentation and examples

### Future Roadmap
- Q1 2024: Additional language bindings
- Q2 2024: Performance optimization suite
- Q3 2024: Enterprise features and HSM support
- Q4 2024: Production-ready 1.0 release

---

For detailed release notes and migration guides, see our [documentation](docs/).