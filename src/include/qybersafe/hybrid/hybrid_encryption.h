#ifndef QYBERSAFE_HYBRID_HYBRID_ENCRYPTION_H
#define QYBERSAFE_HYBRID_HYBRID_ENCRYPTION_H

#include <vector>
#include <memory>
#include <string>
#include <optional>
#include "qybersafe/core/crypto_types.h"
#include "qybersafe/kyber/kyber_kem.h"

namespace qybersafe::hybrid {

// Forward declaration
class HybridKeyPairImpl;

class HybridPublicKey {
public:
    HybridPublicKey(const kyber::PublicKey& pq_key, const core::bytes& classical_key);
    HybridPublicKey(const core::bytes& data);

    const kyber::PublicKey& pq_key() const;
    const core::bytes& classical_key() const;
    core::bytes data() const;
    size_t size() const;
    bool is_valid() const;

private:
    kyber::PublicKey pq_key_;
    core::bytes classical_key_;
    mutable core::bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class HybridPrivateKey {
public:
    HybridPrivateKey(const kyber::PrivateKey& pq_key, const core::bytes& classical_key);
    HybridPrivateKey(const core::bytes& data);

    const kyber::PrivateKey& pq_key() const;
    const core::bytes& classical_key() const;
    core::bytes data() const;
    size_t size() const;
    bool is_valid() const;
    HybridPublicKey get_public_key() const;

private:
    kyber::PrivateKey pq_key_;
    core::bytes classical_key_;
    mutable core::bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class HybridKeyPair {
public:
    HybridKeyPair(const HybridPublicKey& public_key, const HybridPrivateKey& private_key);

    const HybridPublicKey& public_key() const;
    const HybridPrivateKey& private_key() const;

private:
    mutable std::optional<HybridPublicKey> public_key_;
    mutable std::optional<HybridPrivateKey> private_key_;
    std::shared_ptr<HybridKeyPairImpl> impl_;
};

// Core hybrid encryption functions
HybridKeyPair generate_hybrid_keypair();
core::bytes hybrid_encrypt(const HybridPublicKey& public_key, const core::bytes& plaintext);
core::bytes hybrid_decrypt(const HybridPrivateKey& private_key, const core::bytes& ciphertext);

} // namespace qybersafe::hybrid

#endif // QYBERSAFE_HYBRID_HYBRID_ENCRYPTION_H