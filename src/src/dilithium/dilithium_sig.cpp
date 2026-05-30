#include "qybersafe/dilithium/dilithium_sig.h"

#include <oqs/oqs.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

/**
 * @file dilithium_sig.cpp
 * @brief ML-DSA (Dilithium) digital signatures, backed by liboqs.
 *
 * Wraps liboqs' ML-DSA (FIPS 204). The previous from-scratch code was a
 * non-secure placeholder and has been removed.
 */

namespace qybersafe::dilithium {

using core::SecurityLevel;
using core::bytes;

namespace {

const char* alg_name(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::DILITHIUM_2:
        case SecurityLevel::LOW:
            return OQS_SIG_alg_ml_dsa_44;
        case SecurityLevel::DILITHIUM_3:
        case SecurityLevel::MEDIUM:
            return OQS_SIG_alg_ml_dsa_65;
        case SecurityLevel::DILITHIUM_5:
        case SecurityLevel::HIGH:
            return OQS_SIG_alg_ml_dsa_87;
        default:
            throw std::invalid_argument("Unsupported ML-DSA security level");
    }
}

struct SigDeleter {
    void operator()(OQS_SIG* sig) const noexcept { OQS_SIG_free(sig); }
};
using SigPtr = std::unique_ptr<OQS_SIG, SigDeleter>;

SigPtr make_sig(SecurityLevel level) {
    SigPtr sig(OQS_SIG_new(alg_name(level)));
    if (!sig) {
        throw std::runtime_error(
            "ML-DSA algorithm not enabled in this liboqs build");
    }
    return sig;
}

constexpr SecurityLevel kLevels[] = {SecurityLevel::DILITHIUM_2,
                                     SecurityLevel::DILITHIUM_3,
                                     SecurityLevel::DILITHIUM_5};

bool level_for_public_key(size_t n, SecurityLevel& out) {
    for (const SecurityLevel level : kLevels) {
        if (make_sig(level)->length_public_key == n) {
            out = level;
            return true;
        }
    }
    return false;
}

bool level_for_secret_key(size_t n, SecurityLevel& out) {
    for (const SecurityLevel level : kLevels) {
        if (make_sig(level)->length_secret_key == n) {
            out = level;
            return true;
        }
    }
    return false;
}

}  // namespace

// --- VerifyingKey ----------------------------------------------------------

VerifyingKey::VerifyingKey(const bytes& data) : data_(data) {}

const bytes& VerifyingKey::data() const { return data_; }

size_t VerifyingKey::size() const { return data_.size(); }

bool VerifyingKey::is_valid() const {
    if (!validity_checked_) {
        SecurityLevel level;
        is_valid_ = level_for_public_key(data_.size(), level);
        validity_checked_ = true;
    }
    return is_valid_;
}

// --- SigningKey ------------------------------------------------------------

SigningKey::SigningKey(const bytes& data) : data_(data) {}

const bytes& SigningKey::data() const { return data_; }

size_t SigningKey::size() const { return data_.size(); }

bool SigningKey::is_valid() const {
    if (!validity_checked_) {
        SecurityLevel level;
        is_valid_ = level_for_secret_key(data_.size(), level);
        validity_checked_ = true;
    }
    return is_valid_;
}

VerifyingKey SigningKey::get_verifying_key() const {
    // ML-DSA secret keys (FIPS 204) do not embed the public key, so it cannot
    // be recovered from the signing key alone. Keep the VerifyingKey returned
    // by generate_keypair instead.
    throw std::runtime_error(
        "ML-DSA verifying key cannot be derived from the signing key alone");
}

// --- SigningKeyPair --------------------------------------------------------

SigningKeyPair::SigningKeyPair(VerifyingKey verifying_key, SigningKey signing_key)
    : verifying_key_(std::move(verifying_key)),
      signing_key_(std::move(signing_key)) {}

const VerifyingKey& SigningKeyPair::verifying_key() const {
    return verifying_key_;
}

const SigningKey& SigningKeyPair::signing_key() const { return signing_key_; }

// --- API -------------------------------------------------------------------

SigningKeyPair generate_keypair(SecurityLevel level) {
    SigPtr sig = make_sig(level);
    bytes pk(sig->length_public_key);
    bytes sk(sig->length_secret_key);
    if (OQS_SIG_keypair(sig.get(), pk.data(), sk.data()) != OQS_SUCCESS) {
        throw std::runtime_error("ML-DSA key generation failed");
    }
    return SigningKeyPair(VerifyingKey(pk), SigningKey(sk));
}

core::Result<bytes> sign(const SigningKey& private_key, const bytes& message) {
    if (!private_key.is_valid()) {
        return core::Result<bytes>::error("Invalid signing key");
    }
    try {
        SecurityLevel level;
        if (!level_for_secret_key(private_key.size(), level)) {
            return core::Result<bytes>::error("Unrecognized signing key size");
        }
        SigPtr sig = make_sig(level);
        bytes signature(sig->length_signature);
        size_t signature_len = signature.size();
        if (OQS_SIG_sign(sig.get(), signature.data(), &signature_len,
                         message.data(), message.size(),
                         private_key.data().data()) != OQS_SUCCESS) {
            return core::Result<bytes>::error("ML-DSA signing failed");
        }
        signature.resize(signature_len);
        return core::Result<bytes>::success(std::move(signature));
    } catch (const std::exception& e) {
        return core::Result<bytes>::error("sign", e.what());
    }
}

bool verify(const VerifyingKey& public_key, const bytes& message,
            const bytes& signature) {
    if (!public_key.is_valid()) {
        return false;
    }
    try {
        SecurityLevel level;
        if (!level_for_public_key(public_key.size(), level)) {
            return false;
        }
        SigPtr sig = make_sig(level);
        return OQS_SIG_verify(sig.get(), message.data(), message.size(),
                              signature.data(), signature.size(),
                              public_key.data().data()) == OQS_SUCCESS;
    } catch (...) {
        return false;
    }
}

size_t get_verifying_key_size(SecurityLevel level) {
    return make_sig(level)->length_public_key;
}

size_t get_signing_key_size(SecurityLevel level) {
    return make_sig(level)->length_secret_key;
}

size_t get_signature_size(SecurityLevel level) {
    return make_sig(level)->length_signature;
}

core::bytes hash_message(const core::bytes& message) {
    // ML-DSA signs the message directly. Retained for API compatibility.
    return message;
}

}  // namespace qybersafe::dilithium
