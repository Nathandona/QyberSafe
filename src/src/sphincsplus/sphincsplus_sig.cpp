#include "qybersafe/sphincsplus/sphincsplus_sig.h"

#include <oqs/oqs.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

/**
 * @file sphincsplus_sig.cpp
 * @brief SLH-DSA (SPHINCS+) hash-based signatures, backed by liboqs.
 *
 * Wraps liboqs' SLH-DSA (FIPS 205), using the "pure" SHA2 small-signature
 * variants. The previous from-scratch code was a non-secure placeholder and has
 * been removed.
 */

namespace qybersafe::sphincsplus {

using core::SecurityLevel;
using core::bytes;

namespace {

const char* alg_name(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::SPHINCS_128:
        case SecurityLevel::LOW:
            return OQS_SIG_alg_slh_dsa_pure_sha2_128s;
        case SecurityLevel::SPHINCS_192:
        case SecurityLevel::MEDIUM:
            return OQS_SIG_alg_slh_dsa_pure_sha2_192s;
        case SecurityLevel::SPHINCS_256:
        case SecurityLevel::HIGH:
            return OQS_SIG_alg_slh_dsa_pure_sha2_256s;
        default:
            throw std::invalid_argument("Unsupported SLH-DSA security level");
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
            "SLH-DSA algorithm not enabled in this liboqs build");
    }
    return sig;
}

constexpr SecurityLevel kLevels[] = {SecurityLevel::SPHINCS_128,
                                     SecurityLevel::SPHINCS_192,
                                     SecurityLevel::SPHINCS_256};

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

// --- SPHINCSPublicKey ------------------------------------------------------

SPHINCSPublicKey::SPHINCSPublicKey(const bytes& data) : data_(data) {}

const bytes& SPHINCSPublicKey::data() const { return data_; }

size_t SPHINCSPublicKey::size() const { return data_.size(); }

bool SPHINCSPublicKey::is_valid() const {
    if (!validity_checked_) {
        SecurityLevel level;
        is_valid_ = level_for_public_key(data_.size(), level);
        validity_checked_ = true;
    }
    return is_valid_;
}

// --- SPHINCSPrivateKey -----------------------------------------------------

SPHINCSPrivateKey::SPHINCSPrivateKey(const bytes& data) : data_(data) {}

const bytes& SPHINCSPrivateKey::data() const { return data_; }

size_t SPHINCSPrivateKey::size() const { return data_.size(); }

bool SPHINCSPrivateKey::is_valid() const {
    if (!validity_checked_) {
        SecurityLevel level;
        is_valid_ = level_for_secret_key(data_.size(), level);
        validity_checked_ = true;
    }
    return is_valid_;
}

SPHINCSPublicKey SPHINCSPrivateKey::get_public_key() const {
    // An SLH-DSA private key (FIPS 205) is (SK.seed || SK.prf || PK.seed ||
    // PK.root); the public key (PK.seed || PK.root) is its trailing bytes.
    SecurityLevel level;
    if (!level_for_secret_key(data_.size(), level)) {
        throw std::runtime_error("Unrecognized SLH-DSA private key size");
    }
    const size_t pk_size = make_sig(level)->length_public_key;
    if (data_.size() < pk_size) {
        throw std::runtime_error("Malformed SLH-DSA private key");
    }
    return SPHINCSPublicKey(bytes(data_.end() - pk_size, data_.end()));
}

// --- SPHINCSKeyPair --------------------------------------------------------

SPHINCSKeyPair::SPHINCSKeyPair(SPHINCSPublicKey public_key,
                               SPHINCSPrivateKey private_key)
    : public_key_(std::move(public_key)),
      private_key_(std::move(private_key)) {}

const SPHINCSPublicKey& SPHINCSKeyPair::public_key() const {
    return public_key_;
}

const SPHINCSPrivateKey& SPHINCSKeyPair::private_key() const {
    return private_key_;
}

// --- API -------------------------------------------------------------------

SPHINCSKeyPair generate_keypair(SecurityLevel level) {
    SigPtr sig = make_sig(level);
    bytes pk(sig->length_public_key);
    bytes sk(sig->length_secret_key);
    if (OQS_SIG_keypair(sig.get(), pk.data(), sk.data()) != OQS_SUCCESS) {
        throw std::runtime_error("SLH-DSA key generation failed");
    }
    return SPHINCSKeyPair(SPHINCSPublicKey(pk), SPHINCSPrivateKey(sk));
}

core::bytes sign(const SPHINCSPrivateKey& private_key, const bytes& message) {
    if (!private_key.is_valid()) {
        throw std::invalid_argument("Invalid SLH-DSA private key");
    }
    SecurityLevel level;
    if (!level_for_secret_key(private_key.size(), level)) {
        throw std::invalid_argument("Unrecognized SLH-DSA private key size");
    }
    SigPtr sig = make_sig(level);
    bytes signature(sig->length_signature);
    size_t signature_len = signature.size();
    if (OQS_SIG_sign(sig.get(), signature.data(), &signature_len,
                     message.data(), message.size(),
                     private_key.data().data()) != OQS_SUCCESS) {
        throw std::runtime_error("SLH-DSA signing failed");
    }
    signature.resize(signature_len);
    return signature;
}

bool verify(const SPHINCSPublicKey& public_key, const bytes& message,
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

size_t get_public_key_size(SecurityLevel level) {
    return make_sig(level)->length_public_key;
}

size_t get_private_key_size(SecurityLevel level) {
    return make_sig(level)->length_secret_key;
}

size_t get_signature_size(SecurityLevel level) {
    return make_sig(level)->length_signature;
}

}  // namespace qybersafe::sphincsplus
