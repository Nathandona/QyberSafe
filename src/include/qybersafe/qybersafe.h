#ifndef QYBERSAFE_QYBERSAFE_H
#define QYBERSAFE_QYBERSAFE_H

/**
 * @file qybersafe.h
 * @brief Public envelope-first API for QyberSafe.
 *
 * This is the front door for applications. It exposes two operations expressed
 * in misuse-resistant terms:
 *   - seal / open    : hybrid public-key encryption (X25519 + ML-KEM-768)
 *   - sign / verify  : post-quantum signatures (ML-DSA or SLH-DSA)
 *
 * Keys are opaque objects that serialize to self-describing byte strings via
 * to_bytes / *_from_bytes. Failures throw qybersafe::CryptoError; verify()
 * returns a bool. The lower-level per-algorithm primitives remain available in
 * the qybersafe::kyber, ::dilithium, ::sphincsplus, and ::hybrid namespaces.
 */

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "qybersafe/hybrid/hybrid_encryption.h"

namespace qybersafe {

using bytes = std::vector<uint8_t>;

/// Thrown by all operations on failure (verify() returns false instead).
class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// ===========================================================================
// Encryption: hybrid X25519 + ML-KEM-768
// ===========================================================================

class EncryptionPublicKey {
public:
    explicit EncryptionPublicKey(hybrid::HybridPublicKey key);
    const hybrid::HybridPublicKey& hybrid_key() const;

private:
    hybrid::HybridPublicKey key_;
};

class EncryptionPrivateKey {
public:
    explicit EncryptionPrivateKey(hybrid::HybridPrivateKey key);
    const hybrid::HybridPrivateKey& hybrid_key() const;
    EncryptionPublicKey public_key() const;

private:
    hybrid::HybridPrivateKey key_;
};

struct EncryptionKeyPair {
    EncryptionPublicKey public_key;
    EncryptionPrivateKey private_key;
};

/// Generate a hybrid encryption key pair.
EncryptionKeyPair generate_encryption_keypair();

/// Encrypt @p plaintext to @p to. The optional @p aad is authenticated but not
/// stored; the same aad must be supplied to open(). Throws CryptoError.
bytes seal(const EncryptionPublicKey& to, const bytes& plaintext,
           const bytes& aad = {});

/// Decrypt an envelope produced by seal(). Throws CryptoError on failure
/// (wrong key, tampering, or aad mismatch).
bytes open(const EncryptionPrivateKey& key, const bytes& envelope,
           const bytes& aad = {});

bytes to_bytes(const EncryptionPublicKey& key);
bytes to_bytes(const EncryptionPrivateKey& key);
EncryptionPublicKey encryption_public_key_from_bytes(const bytes& data);
EncryptionPrivateKey encryption_private_key_from_bytes(const bytes& data);

// ===========================================================================
// Signatures: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205)
// ===========================================================================

enum class SignAlg {
    ML_DSA_44,
    ML_DSA_65,  // default
    ML_DSA_87,
    SLH_DSA_128s,
    SLH_DSA_192s,
    SLH_DSA_256s,
};

class SigningPublicKey {
public:
    SigningPublicKey(SignAlg algorithm, bytes key);
    SignAlg algorithm() const;
    const bytes& key_bytes() const;

private:
    SignAlg algorithm_;
    bytes key_;
};

class SigningPrivateKey {
public:
    SigningPrivateKey(SignAlg algorithm, bytes key);
    SignAlg algorithm() const;
    const bytes& key_bytes() const;

private:
    SignAlg algorithm_;
    bytes key_;
};

struct SigningKeyPair {
    SigningPublicKey public_key;
    SigningPrivateKey private_key;
};

/// Generate a signing key pair for @p algorithm (default ML-DSA-65).
SigningKeyPair generate_signing_keypair(SignAlg algorithm = SignAlg::ML_DSA_65);

/// Sign @p message. Throws CryptoError on failure.
bytes sign(const SigningPrivateKey& key, const bytes& message);

/// Verify @p signature over @p message. Returns true if valid.
bool verify(const SigningPublicKey& key, const bytes& message,
            const bytes& signature);

bytes to_bytes(const SigningPublicKey& key);
bytes to_bytes(const SigningPrivateKey& key);
SigningPublicKey signing_public_key_from_bytes(const bytes& data);
SigningPrivateKey signing_private_key_from_bytes(const bytes& data);

}  // namespace qybersafe

#endif  // QYBERSAFE_QYBERSAFE_H
