#ifndef QYBERSAFE_HYBRID_HYBRID_ENCRYPTION_H
#define QYBERSAFE_HYBRID_HYBRID_ENCRYPTION_H

#include <vector>
#include <memory>
#include <variant>
#include "../core/crypto_types.h"
#include "../kyber/kyber_kem.h"
#include "../dilithium/dilithium_sig.h"

namespace qybersafe::hybrid {

// Classical algorithms for hybrid mode
enum class ClassicalAlgorithm {
    RSA_OAEP_2048,
    RSA_OAEP_3072,
    RSA_OAEP_4096,
    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
    ECDH_P256,
    ECDH_P384,
    ECDH_P521,
    X25519,
    X448
};

// Hybrid encryption modes
enum class HybridMode {
    KEY_EXCHANGE,   // Classical + PQC key exchange
    SIGNATURE,       // Classical + PQC signatures
    ENCRYPTION       // Classical + PQC encryption
};

class HybridPublicKey {
public:
    HybridPublicKey(kyber::PublicKey pqc_key,
                  const bytes& classical_key,
                  ClassicalAlgorithm algorithm);

    const kyber::PublicKey& pqc_key() const { return pqc_key_; }
    const bytes& classical_key() const { return classical_key_; }
    ClassicalAlgorithm classical_algorithm() const { return classical_algorithm_; }

    bool is_valid() const;

private:
    kyber::PublicKey pqc_key_;
    bytes classical_key_;
    ClassicalAlgorithm classical_algorithm_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class HybridPrivateKey {
public:
    HybridPrivateKey(kyber::PrivateKey pqc_key,
                   const bytes& classical_key,
                   ClassicalAlgorithm algorithm);

    const kyber::PrivateKey& pqc_key() const { return pqc_key_; }
    const bytes& classical_key() const { return classical_key_; }
    ClassicalAlgorithm classical_algorithm() const { return classical_algorithm_; }

    bool is_valid() const;
    HybridPublicKey get_public_key() const;

private:
    kyber::PrivateKey pqc_key_;
    bytes classical_key_;
    ClassicalAlgorithm classical_algorithm_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class HybridKeyPair {
public:
    HybridKeyPair(HybridPublicKey public_key, HybridPrivateKey private_key);

    const HybridPublicKey& public_key() const { return public_key_; }
    const HybridPrivateKey& private_key() const { return private_key_; }

private:
    HybridPublicKey public_key_;
    HybridPrivateKey private_key_;
};

// Hybrid signature keys
class HybridVerifyingKey {
public:
    HybridVerifyingKey(dilithium::VerifyingKey pqc_key,
                     const bytes& classical_key,
                     ClassicalAlgorithm algorithm);

    const dilithium::VerifyingKey& pqc_key() const { return pqc_key_; }
    const bytes& classical_key() const { return classical_key_; }
    ClassicalAlgorithm classical_algorithm() const { return classical_algorithm_; }

    bool is_valid() const;

private:
    dilithium::VerifyingKey pqc_key_;
    bytes classical_key_;
    ClassicalAlgorithm classical_algorithm_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class HybridSigningKey {
public:
    HybridSigningKey(dilithium::SigningKey pqc_key,
                   const bytes& classical_key,
                   ClassicalAlgorithm algorithm);

    const dilithium::SigningKey& pqc_key() const { return pqc_key_; }
    const bytes& classical_key() const { return classical_key_; }
    ClassicalAlgorithm classical_algorithm() const { return classical_algorithm_; }

    bool is_valid() const;
    HybridVerifyingKey get_verifying_key() const;

private:
    dilithium::SigningKey pqc_key_;
    bytes classical_key_;
    ClassicalAlgorithm classical_algorithm_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class HybridSigningKeyPair {
public:
    HybridSigningKeyPair(HybridVerifyingKey verifying_key, HybridSigningKey signing_key);

    const HybridVerifyingKey& verifying_key() const { return verifying_key_; }
    const HybridSigningKey& signing_key() const { return signing_key_; }

private:
    HybridVerifyingKey verifying_key_;
    HybridSigningKey signing_key_;
};

// Core hybrid functions

// Generate hybrid key pairs
HybridKeyPair generate_hybrid_keypair(
    core::SecurityLevel pqc_level = core::SecurityLevel::MEDIUM,
    ClassicalAlgorithm classical_algorithm = ClassicalAlgorithm::X25519
);

HybridSigningKeyPair generate_hybrid_signing_keypair(
    core::SecurityLevel pqc_level = core::SecurityLevel::MEDIUM,
    ClassicalAlgorithm classical_algorithm = ClassicalAlgorithm::ECDSA_P256
);

// Hybrid encryption/decryption
Result<bytes> hybrid_encrypt(const HybridPublicKey& public_key, const bytes& plaintext);
Result<bytes> hybrid_decrypt(const HybridPrivateKey& private_key, const bytes& ciphertext);

// Hybrid KEM
Result<std::pair<bytes, bytes>> hybrid_encapsulate(const HybridPublicKey& public_key);
Result<bytes> hybrid_decapsulate(const HybridPrivateKey& private_key, const bytes& ciphertext);

// Hybrid signing/verification
Result<bytes> hybrid_sign(const HybridSigningKey& private_key, const bytes& message);
bool hybrid_verify(const HybridVerifyingKey& public_key, const bytes& message, const bytes& signature);

// Migration helpers
Result<HybridKeyPair> migrate_classical_keypair(
    const bytes& classical_private_key,
    ClassicalAlgorithm algorithm,
    core::SecurityLevel pqc_level = core::SecurityLevel::MEDIUM
);

Result<HybridSigningKeyPair> migrate_classical_signing_keypair(
    const bytes& classical_private_key,
    ClassicalAlgorithm algorithm,
    core::SecurityLevel pqc_level = core::SecurityLevel::MEDIUM
);

// Utility functions
size_t get_hybrid_public_key_size(ClassicalAlgorithm classical_algorithm, core::SecurityLevel pqc_level);
size_t get_hybrid_private_key_size(ClassicalAlgorithm classical_algorithm, core::SecurityLevel pqc_level);
size_t get_hybrid_ciphertext_size(ClassicalAlgorithm classical_algorithm, core::SecurityLevel pqc_level);
size_t get_hybrid_signature_size(ClassicalAlgorithm classical_algorithm, core::SecurityLevel pqc_level);

// Security level recommendations
ClassicalAlgorithm recommend_classical_algorithm(core::SecurityLevel pqc_level);
core::SecurityLevel recommend_pqc_level(ClassicalAlgorithm classical_algorithm);

} // namespace qybersafe::hybrid

#endif // QYBERSAFE_HYBRID_HYBRID_ENCRYPTION_H