#ifndef QYBERSAFE_KYBER_KYBER_KEM_H
#define QYBERSAFE_KYBER_KYBER_KEM_H

#include <vector>
#include <memory>
#include "../core/crypto_types.h"

namespace qybersafe::kyber {

class PublicKey {
public:
    explicit PublicKey(const bytes& data);

    const bytes& data() const { return data_; }
    size_t size() const { return data_.size(); }

    bool is_valid() const;

private:
    bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class PrivateKey {
public:
    explicit PrivateKey(const bytes& data);

    const bytes& data() const { return data_; }
    size_t size() const { return data_.size(); }

    bool is_valid() const;

    // Derive public key from private key
    PublicKey get_public_key() const;

private:
    bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class KeyPair {
public:
    KeyPair(PublicKey public_key, PrivateKey private_key);

    const PublicKey& public_key() const { return public_key_; }
    const PrivateKey& private_key() const { return private_key_; }

private:
    PublicKey public_key_;
    PrivateKey private_key_;
};

// Core Kyber functions
KeyPair generate_keypair(core::SecurityLevel level = core::SecurityLevel::MEDIUM);

bytes encrypt(const PublicKey& public_key, const bytes& plaintext);
Result<bytes> decrypt(const PrivateKey& private_key, const bytes& ciphertext);

// KEM interface
Result<std::pair<bytes, bytes>> encapsulate(const PublicKey& public_key);
Result<bytes> decapsulate(const PrivateKey& private_key, const bytes& ciphertext);

// Utility functions
size_t get_public_key_size(core::SecurityLevel level);
size_t get_private_key_size(core::SecurityLevel level);
size_t get_ciphertext_size(core::SecurityLevel level);
size_t get_shared_secret_size();

} // namespace qybersafe::kyber

#endif // QYBERSAFE_KYBER_KYBER_KEM_H