#ifndef QYBERSAFE_KYBER_KYBER_KEM_H
#define QYBERSAFE_KYBER_KYBER_KEM_H

/**
 * @file kyber_kem.h
 * @brief Kyber Key Encapsulation Mechanism implementation
 *
 * This header provides the C++ interface for Kyber, a lattice-based
 * key encapsulation mechanism (KEM) standardized by NIST in the
 * post-quantum cryptography competition.
 *
 * @author QyberSafe Team
 * @version 0.1.0
 * @since 0.1.0
 */

#include <vector>
#include <memory>
#include "qybersafe/core/crypto_types.h"

namespace qybersafe::kyber {

using core::SecurityLevel;
using core::bytes;

/**
 * @class PublicKey
 * @brief Kyber public key for encapsulation operations
 *
 * Represents a Kyber public key that can be used to encapsulate
 * shared secrets. The key includes validation to ensure it conforms
 * to Kyber specifications.
 */
class PublicKey {
public:
    /**
     * @brief Construct a PublicKey from raw key data
     * @param data Raw public key bytes
     */
    explicit PublicKey(const core::bytes& data);

    /**
     * @brief Get the raw public key data
     * @return Const reference to the key bytes
     */
    const core::bytes& data() const;

    /**
     * @brief Get the size of the public key in bytes
     * @return Size of the key data
     */
    size_t size() const;

    /**
     * @brief Check if the public key is valid
     * @return true if the key is valid, false otherwise
     */
    bool is_valid() const;

private:
    core::bytes data_;                      ///< Raw key data
    mutable bool validity_checked_{false};  ///< Cache validity check
    mutable bool is_valid_{false};          ///< Cached validity result
};

class PrivateKey {
public:
    explicit PrivateKey(const core::bytes& data);

    const core::bytes& data() const;
    size_t size() const;

    bool is_valid() const;

    // Derive public key from private key
    PublicKey get_public_key() const;

private:
    core::bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class KeyPair {
public:
    KeyPair(PublicKey public_key, PrivateKey private_key);

    const PublicKey& public_key() const;
    const PrivateKey& private_key() const;

private:
    PublicKey public_key_;
    PrivateKey private_key_;
};

// Core Kyber functions
KeyPair generate_keypair(core::SecurityLevel level = core::SecurityLevel::KYBER_768);

core::bytes encrypt(const PublicKey& public_key, const core::bytes& plaintext);
core::Result<core::bytes> decrypt(const PrivateKey& private_key, const core::bytes& ciphertext);

// KEM interface
core::Result<std::pair<core::bytes, core::bytes>> encapsulate(const PublicKey& public_key);
core::Result<core::bytes> decapsulate(const PrivateKey& private_key, const core::bytes& ciphertext);

// Utility functions
size_t get_public_key_size(SecurityLevel level);
size_t get_private_key_size(SecurityLevel level);
size_t get_ciphertext_size(SecurityLevel level);
size_t get_shared_secret_size();

} // namespace qybersafe::kyber

#endif // QYBERSAFE_KYBER_KYBER_KEM_H