#ifndef QYBERSAFE_DILITHIUM_DILITHIUM_SIG_H
#define QYBERSAFE_DILITHIUM_DILITHIUM_SIG_H

#include <vector>
#include <memory>
#include "../core/crypto_types.h"

namespace qybersafe::dilithium {

class VerifyingKey {
public:
    explicit VerifyingKey(const bytes& data);

    const bytes& data() const { return data_; }
    size_t size() const { return data_.size(); }

    bool is_valid() const;

private:
    bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class SigningKey {
public:
    explicit SigningKey(const bytes& data);

    const bytes& data() const { return data_; }
    size_t size() const { return data_.size(); }

    bool is_valid() const;

    // Derive public key from private key
    VerifyingKey get_verifying_key() const;

private:
    bytes data_;
    mutable bool validity_checked_{false};
    mutable bool is_valid_{false};
};

class SigningKeyPair {
public:
    SigningKeyPair(VerifyingKey verifying_key, SigningKey signing_key);

    const VerifyingKey& verifying_key() const { return verifying_key_; }
    const SigningKey& signing_key() const { return signing_key_; }

private:
    VerifyingKey verifying_key_;
    SigningKey signing_key_;
};

// Core Dilithium functions
SigningKeyPair generate_keypair(core::SecurityLevel level = core::SecurityLevel::MEDIUM);

Result<bytes> sign(const SigningKey& private_key, const bytes& message);
bool verify(const VerifyingKey& public_key, const bytes& message, const bytes& signature);

// Utility functions
size_t get_verifying_key_size(core::SecurityLevel level);
size_t get_signing_key_size(core::SecurityLevel level);
size_t get_signature_size(core::SecurityLevel level);

// Message hashing for signing
bytes hash_message(const bytes& message);

} // namespace qybersafe::dilithium

#endif // QYBERSAFE_DILITHIUM_DILITHIUM_SIG_H