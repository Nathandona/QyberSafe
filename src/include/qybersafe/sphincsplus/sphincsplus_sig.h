#ifndef QYBERSAFE_SPHINCSPLUS_SPHINCSPLUS_SIG_H
#define QYBERSAFE_SPHINCSPLUS_SPHINCSPLUS_SIG_H

#include <vector>
#include <memory>
#include "../core/crypto_types.h"

namespace qybersafe::sphincsplus {

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

// Core SPHINCS+ functions
KeyPair generate_keypair(core::SecurityLevel level = core::SecurityLevel::MEDIUM);

Result<bytes> sign(const PrivateKey& private_key, const bytes& message);
bool verify(const PublicKey& public_key, const bytes& message, const bytes& signature);

// Utility functions
size_t get_public_key_size(core::SecurityLevel level);
size_t get_private_key_size(core::SecurityLevel level);
size_t get_signature_size(core::SecurityLevel level);

// SPHINCS+ specific parameters
enum class HashFunction {
    SHA256,
    SHAKE256,
    HARAKA
};

struct Parameters {
    SecurityLevel level;
    HashFunction hash_func;
    size_t n;      // State size
    size_t w;      // Winternitz parameter
    size_t h;      // Height of hypertree
    size_t d;      // Layers of hypertree
    size_t k;      // Number of FORS trees
    size_t t;      // Number of FORS messages
};

Parameters get_parameters(SecurityLevel level, HashFunction hash_func = HashFunction::SHAKE256);

} // namespace qybersafe::sphincsplus

#endif // QYBERSAFE_SPHINCSPLUS_SPHINCSPLUS_SIG_H