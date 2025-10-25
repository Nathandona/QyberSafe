#ifndef QYBERSAFE_KYBER_KYBER_KEM_H
#define QYBERSAFE_KYBER_KYBER_KEM_H

#include <vector>
#include <memory>
#include "qybersafe/core/crypto_types.h"

namespace qybersafe::kyber {

using core::SecurityLevel;
using core::bytes;

class PublicKey {
public:
    explicit PublicKey(const core::bytes& data);

    const core::bytes& data() const;
    size_t size() const;

    bool is_valid() const;

private:
    core::bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
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