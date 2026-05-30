# QyberSafe v1 Specification

Status: draft. Target: 1.0.0. Last updated: 2026-05-30.

This document is the build spec for QyberSafe v1. It captures the decisions made
during scoping and is the source of truth for what v1 is and is not.

## 1. Summary

QyberSafe is a C++ and Python library that lets backend engineers add
post-quantum cryptography to their systems without being cryptographers. It
provides a small, misuse-resistant API for hybrid encryption and digital
signatures, backed by audited implementations from liboqs (Open Quantum Safe).

The current repository contains a from-scratch lattice implementation that is
explicitly "simplified for demonstration" (see `src/src/kyber/kyber_kem.cpp`).
It is not secure and will be removed. v1 does not ship homemade cryptography.

## 2. Audience

Primary user: backend and platform engineers at fintech, cloud, and enterprise
companies who are not cryptographers. They need to add a quantum-safe layer to
existing systems (data-at-rest, sessions, service-to-service messages) and want
safe defaults with minimal knobs. Every API decision optimizes for "hard to
hold wrong."

Secondary users (not a v1 design driver): security/migration engineers,
application developers, students.

## 3. Goals and non-goals

### Goals

- Real, audited PQC via liboqs. No self-written primitives.
- Full algorithm suite: ML-KEM, ML-DSA, SLH-DSA, plus hybrid encryption.
- A high-level envelope API as the front door, with raw primitives available.
- Self-describing, versioned artifacts for crypto-agility.
- C++ as the canonical implementation; Python bindings on top.
- Easy install: pip wheels with liboqs bundled, plus vcpkg/conan for C++.

### Non-goals for v1 (explicit)

- Key storage, rotation, versioning, or distribution. The caller owns key
  lifecycle. The library only generates, serializes, and uses keys.
- KMS / HSM integration.
- TLS, SSH, or other protocol integration.
- FIPS validation. liboqs is not FIPS-validated; see section 9.
- A CLI, a hosted service, or migration/inventory tooling. Library/SDK only.

## 4. Algorithms and naming

Canonical names follow the finalized NIST standards. Round-3 names are accepted
as aliases in the API and appear in docs for discoverability.

| Canonical (FIPS) | Alias       | Type              | Standard |
|------------------|-------------|-------------------|----------|
| ML-KEM-512/768/1024 | Kyber512/768/1024 | Key encapsulation | FIPS 203 |
| ML-DSA-44/65/87  | Dilithium2/3/5 | Signature         | FIPS 204 |
| SPHINCS+-SHA2-128s/192s/256s (simple) | SLH-DSA | Hash-based signature | FIPS 205 family |

Defaults: ML-KEM-768, ML-DSA-65, SPHINCS+-SHA2-192s-simple.

The hash-based signatures use liboqs' SPHINCS+-SHA2 "simple" parameter sets (the
NIST round-3 submission underlying FIPS 205 SLH-DSA). liboqs' FIPS-205 "pure"
SLH-DSA variants are not used yet because they fail to verify under MSVC/Windows
in liboqs 0.15.0; the "pure" variant will be adopted once that is resolved.

## 5. Architecture

```
        Python API (pybind11)
                |
        C++ public API  (envelope + primitives)
                |
        QyberSafe core  (wire format, hybrid combiner, KEM-DEM, RNG)
                |
            liboqs            OpenSSL (X25519, AES-256-GCM, HKDF, CSPRNG)
```

- C++ core is the single implementation. Python binds the C++ layer; it does not
  reimplement logic. Ship C++ first, Python immediately after with API parity.
- liboqs provides ML-KEM, ML-DSA, SLH-DSA. OpenSSL provides the classical half
  (X25519), the AEAD (AES-256-GCM), the KDF (HKDF-SHA-256), and the CSPRNG.
- No custom RNG. All randomness comes from the OpenSSL CSPRNG.

## 6. Hybrid encryption design

Hybrid suite for v1: `X25519 + ML-KEM-768` (the de-facto industry hybrid, as in
TLS 1.3 hybrid and the X-Wing construction).

Construction is KEM-DEM:

1. Encapsulate to both halves:
   - X25519: ephemeral keypair, ECDH against the recipient X25519 public key,
     yielding `ss_x`.
   - ML-KEM-768: encapsulate against the recipient ML-KEM public key, yielding
     `ss_pq` and KEM ciphertext `ct_pq`.
2. Derive the data key with a secure combiner:
   `K = HKDF-SHA-256(ikm = ss_pq || ss_x, salt = "", info = transcript)`
   where `transcript = suite_id || eph_x25519_pub || ct_pq || recipient_pub_ids`.
   The post-quantum secret is placed first; the classical secret and the full
   transcript are bound in so neither half can be stripped or substituted.
3. DEM: encrypt the plaintext with AES-256-GCM using `K`, a fresh 96-bit random
   nonce, and the caller-supplied AAD.

Decryption reverses this and fails closed if either decapsulation, the KDF
context, or the GCM tag does not check out.

AEAD: AES-256-GCM (AES-NI is ubiquitous on the target deployment surface).
ChaCha20-Poly1305 is a candidate for a later suite, not v1.

## 7. Wire format

All public artifacts are self-describing so they can be decoded without
out-of-band metadata, and so algorithms can change without breaking parsers.
All multi-byte integers are big-endian.

Common header (4 bytes):

| Offset | Size | Field        | Notes                                   |
|--------|------|--------------|-----------------------------------------|
| 0      | 1    | version      | 0x01 for this spec                      |
| 1      | 1    | artifact type| see registry below                      |
| 2      | 2    | algorithm id | see registry below                      |

Artifact types: `1` public key, `2` private key, `3` KEM ciphertext,
`4` signature, `5` hybrid envelope.

Algorithm id registry (uint16):

| Id     | Meaning                          |
|--------|----------------------------------|
| 0x0002 | ML-KEM-768                       |
| 0x0001 / 0x0003 | ML-KEM-512 / ML-KEM-1024 |
| 0x0101 / 0x0102 / 0x0103 | ML-DSA-44 / ML-DSA-65 / ML-DSA-87 |
| 0x0201 / 0x0202 / 0x0203 | SLH-DSA-SHA2-128s / 192s / 256s |
| 0x0301 | Hybrid suite: X25519 + ML-KEM-768 + AES-256-GCM |

Body is a sequence of length-prefixed fields (`uint32 length` then bytes; a
32-bit length avoids capping payloads at 64 KiB). For a hybrid envelope
(type 5, alg 0x0301) the fields, in order, are:

1. X25519 ephemeral public key (32 bytes)
2. ML-KEM-768 ciphertext
3. AES-256-GCM nonce (12 bytes)
4. AES-256-GCM tag (16 bytes)
5. ciphertext (encrypted payload)

AAD is authenticated but never stored in the envelope; the caller must supply
the same AAD to open.

## 8. Public API

Error model: the high-level API throws on failure (`qybersafe::CryptoError` in
C++, a `QyberSafeError` hierarchy in Python). Verification returns a bool;
everything else throws on misuse or failure. This replaces the inconsistent
`bytes`-vs-`Result<>` returns in the current code. A `noexcept` `try_*` variant
may be added later but is not in v1.

### C++ envelope API (front door)

```cpp
#include <qybersafe/qybersafe.h>
namespace qybersafe {

// Encryption (hybrid X25519 + ML-KEM-768)
EncryptionKeyPair generate_encryption_keypair();
bytes seal(const EncryptionPublicKey& to, const bytes& plaintext,
           const bytes& aad = {});
bytes open(const EncryptionPrivateKey& key, const bytes& envelope,
           const bytes& aad = {});

// Signatures
enum class SignAlg { ML_DSA_65, ML_DSA_44, ML_DSA_87,
                     SLH_DSA_192s, /* ... */ };
SigningKeyPair generate_signing_keypair(SignAlg alg = SignAlg::ML_DSA_65);
bytes sign(const SigningPrivateKey& key, const bytes& message);
bool  verify(const SigningPublicKey& key, const bytes& message,
             const bytes& signature);

// Serialization: every key/artifact -> versioned blob (section 7)
bytes to_bytes(const EncryptionPublicKey&);
EncryptionPublicKey encryption_public_key_from_bytes(const bytes&);
// ... matching to_bytes / from_bytes for each key type
}
```

### C++ primitives (power users)

Raw KEM and signature operations live under `qybersafe::kem` and
`qybersafe::sig`, mirroring liboqs (generate_keypair, encapsulate, decapsulate,
sign, verify) with the same versioned serialization.

### Python API (parity)

```python
import qybersafe as qs

kp = qs.generate_encryption_keypair()
env = qs.seal(kp.public_key, b"secret", aad=b"context")
pt  = qs.open(kp.private_key, env, aad=b"context")

sk = qs.generate_signing_keypair()              # ML-DSA-65 default
sig = qs.sign(sk.private_key, b"msg")
ok  = qs.verify(sk.public_key, b"msg", sig)

raw = qs.to_bytes(kp.public_key)                # versioned blob
pub = qs.encryption_public_key_from_bytes(raw)
```

## 9. Security posture

- v1 ships real PQC via liboqs but is NOT FIPS-validated. This is documented
  prominently in the README and API docs. liboqs itself warns against relying on
  its PQC in production; hybrid mode is the mitigation, because the classical
  X25519 half keeps confidentiality intact even if a PQC parameter set is later
  weakened or an implementation bug is found.
- A pluggable backend seam is left in the core so a FIPS-validated provider
  (for example AWS-LC) can be added later behind a build/runtime flag. Designing
  the seam is in scope for v1; wiring a FIPS backend is not.
- Constant-time behavior is delegated to liboqs and OpenSSL. The library adds no
  secret-dependent branches.
- Secret material is zeroed on destruction (the existing secure-memory utility
  is kept and audited).
- Nonces are always generated internally from the CSPRNG; the caller cannot set
  them.

## 10. Packaging and distribution

- Python: prebuilt wheels for manylinux, macOS (x86_64 + arm64), and Windows,
  with liboqs statically vendored. `pip install qybersafe` requires nothing else.
- C++: vcpkg and conan packages, with liboqs as a managed dependency.
- Source builds remain supported via CMake for early adopters.
- System packages (apt/brew) are out of scope for v1.

## 11. Testing strategy

- Known-answer tests (KATs) against NIST/liboqs vectors for every algorithm and
  level.
- Round-trip and property tests for seal/open and sign/verify.
- Cross-language interop: artifacts sealed/signed in C++ open/verify in Python
  and vice versa, validating the wire format.
- Negative tests: corrupted envelopes, wrong keys, truncated artifacts, bad AAD,
  unknown algorithm ids, future format versions all fail closed.
- Memory safety: ASan/UBSan and Valgrind in CI (already wired).

## 12. Milestones

- M0: Integrate liboqs into the build. Remove the simplified lattice code.
  Replace Kyber with ML-KEM via liboqs. KATs pass.
- M1: Add ML-DSA and SLH-DSA via liboqs with KATs.
- M2: Implement the hybrid suite (X25519 + ML-KEM-768, HKDF combiner,
  AES-256-GCM) and the v1 wire format.
- M3: Build the envelope API (seal/open/sign/verify) and serialization, with the
  exception-based error model.
- M4: Python bindings to parity, plus cross-language interop tests.
- M5: Packaging (wheels, vcpkg/conan), docs, and README rewrite to FIPS naming.
- 1.0.0: tag and release once M0-M5 are green and the security posture doc is
  reviewed.

## 13. Open questions

- Exact SLH-DSA default parameter set (small vs fast tradeoff) for the signing
  default.
- Whether to expose ChaCha20-Poly1305 as a second AEAD suite in 1.x.
- Minimum supported liboqs version and how to pin it across wheels.
