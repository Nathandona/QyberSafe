#ifndef QYBERSAFE_SPHINCSPLUS_SPHINCSPLUS_SIG_H
#define QYBERSAFE_SPHINCSPLUS_SPHINCSPLUS_SIG_H

#include <vector>
#include <memory>
#include "qybersafe/core/crypto_types.h"

namespace qybersafe::sphincsplus {

using core::SecurityLevel;
using core::bytes;

class SPHINCSPublicKey {
public:
    explicit SPHINCSPublicKey(const core::bytes& data);

    const core::bytes& data() const;
    size_t size() const;

    bool is_valid() const;

private:
    core::bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class SPHINCSPrivateKey {
public:
    explicit SPHINCSPrivateKey(const core::bytes& data);

    const core::bytes& data() const;
    size_t size() const;

    bool is_valid() const;

    // Derive public key from private key
    SPHINCSPublicKey get_public_key() const;

private:
    core::bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class SPHINCSKeyPair {
public:
    SPHINCSKeyPair(SPHINCSPublicKey public_key, SPHINCSPrivateKey private_key);

    const SPHINCSPublicKey& public_key() const;
    const SPHINCSPrivateKey& private_key() const;

private:
    SPHINCSPublicKey public_key_;
    SPHINCSPrivateKey private_key_;
};

// Core SPHINCS+ functions
SPHINCSKeyPair generate_keypair(SecurityLevel level = SecurityLevel::SPHINCS_192);

core::bytes sign(const SPHINCSPrivateKey& private_key, const core::bytes& message);
bool verify(const SPHINCSPublicKey& public_key, const core::bytes& message, const core::bytes& signature);

// Utility functions
size_t get_public_key_size(SecurityLevel level);
size_t get_private_key_size(SecurityLevel level);
size_t get_signature_size(SecurityLevel level);



} // namespace qybersafe::sphincsplus

#endif // QYBERSAFE_SPHINCSPLUS_SPHINCSPLUS_SIG_H