#ifndef QYBERSAFE_DILITHIUM_DILITHIUM_SIG_H
#define QYBERSAFE_DILITHIUM_DILITHIUM_SIG_H

#include <vector>
#include <memory>
#include "qybersafe/core/crypto_types.h"

namespace qybersafe::dilithium {

using core::SecurityLevel;
using core::bytes;

class VerifyingKey {
public:
    explicit VerifyingKey(const core::bytes& data);

    const core::bytes& data() const;
    size_t size() const;

    bool is_valid() const;

private:
    core::bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class SigningKey {
public:
    explicit SigningKey(const core::bytes& data);

    const core::bytes& data() const;
    size_t size() const;

    bool is_valid() const;

    // Derive public key from private key
    VerifyingKey get_verifying_key() const;

private:
    core::bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class SigningKeyPair {
public:
    SigningKeyPair(VerifyingKey verifying_key, SigningKey signing_key);

    const VerifyingKey& verifying_key() const;
    const SigningKey& signing_key() const;

private:
    VerifyingKey verifying_key_;
    SigningKey signing_key_;
};

// Core Dilithium functions
SigningKeyPair generate_keypair(SecurityLevel level = SecurityLevel::DILITHIUM_3);

core::Result<core::bytes> sign(const SigningKey& private_key, const core::bytes& message);
bool verify(const VerifyingKey& public_key, const core::bytes& message, const core::bytes& signature);

// Utility functions
size_t get_verifying_key_size(SecurityLevel level);
size_t get_signing_key_size(SecurityLevel level);
size_t get_signature_size(SecurityLevel level);

// Message hashing for signing
core::bytes hash_message(const core::bytes& message);

} // namespace qybersafe::dilithium

#endif // QYBERSAFE_DILITHIUM_DILITHIUM_SIG_H