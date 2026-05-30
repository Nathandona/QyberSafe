#include "qybersafe/kyber/kyber_kem.h"

#include <oqs/oqs.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "qybersafe/core/aead.h"

/**
 * @file kyber_kem.cpp
 * @brief ML-KEM (Kyber) key encapsulation, backed by liboqs.
 *
 * This module wraps liboqs' ML-KEM (FIPS 203) implementation. The previous
 * from-scratch lattice code was a non-secure placeholder and has been removed.
 *
 * encapsulate()/decapsulate() expose the raw KEM. encrypt()/decrypt() provide a
 * convenience KEM-DEM (ML-KEM encapsulation feeding an AES-256-GCM data
 * encryption, with the data key derived via HKDF-SHA-256). The canonical
 * encryption surface for applications is the hybrid envelope API (see SPEC.md);
 * this KEM-DEM is the single-algorithm convenience path.
 */

namespace qybersafe::kyber {

using core::SecurityLevel;
using core::bytes;

namespace {

// HKDF info string binding the derived key to this construction and version.
constexpr char KDF_INFO[] = "QyberSafe/ML-KEM-DEM/v1";

bytes kdf_info() { return bytes(KDF_INFO, KDF_INFO + sizeof(KDF_INFO) - 1); }

// Map a QyberSafe security level (including the legacy aliases) to the liboqs
// ML-KEM algorithm identifier.
const char* alg_name(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::KYBER_512:
        case SecurityLevel::LOW:
            return OQS_KEM_alg_ml_kem_512;
        case SecurityLevel::KYBER_768:
        case SecurityLevel::MEDIUM:
            return OQS_KEM_alg_ml_kem_768;
        case SecurityLevel::KYBER_1024:
        case SecurityLevel::HIGH:
            return OQS_KEM_alg_ml_kem_1024;
        default:
            throw std::invalid_argument("Unsupported ML-KEM security level");
    }
}

struct KemDeleter {
    void operator()(OQS_KEM* kem) const noexcept { OQS_KEM_free(kem); }
};
using KemPtr = std::unique_ptr<OQS_KEM, KemDeleter>;

KemPtr make_kem(SecurityLevel level) {
    KemPtr kem(OQS_KEM_new(alg_name(level)));
    if (!kem) {
        throw std::runtime_error(
            "ML-KEM algorithm not enabled in this liboqs build");
    }
    return kem;
}

SecurityLevel level_from_public_key_size(size_t n) {
    if (n == core::KYBER_PUBLIC_KEY_512) return SecurityLevel::KYBER_512;
    if (n == core::KYBER_PUBLIC_KEY_768) return SecurityLevel::KYBER_768;
    if (n == core::KYBER_PUBLIC_KEY_1024) return SecurityLevel::KYBER_1024;
    throw std::invalid_argument("Unrecognized ML-KEM public key size");
}

SecurityLevel level_from_private_key_size(size_t n) {
    if (n == core::KYBER_PRIVATE_KEY_512) return SecurityLevel::KYBER_512;
    if (n == core::KYBER_PRIVATE_KEY_768) return SecurityLevel::KYBER_768;
    if (n == core::KYBER_PRIVATE_KEY_1024) return SecurityLevel::KYBER_1024;
    throw std::invalid_argument("Unrecognized ML-KEM private key size");
}

}  // namespace

// --- PublicKey -------------------------------------------------------------

PublicKey::PublicKey(const bytes& data) : data_(data) {}

const bytes& PublicKey::data() const { return data_; }

size_t PublicKey::size() const { return data_.size(); }

bool PublicKey::is_valid() const {
    if (!validity_checked_) {
        is_valid_ = (data_.size() == core::KYBER_PUBLIC_KEY_512 ||
                     data_.size() == core::KYBER_PUBLIC_KEY_768 ||
                     data_.size() == core::KYBER_PUBLIC_KEY_1024);
        validity_checked_ = true;
    }
    return is_valid_;
}

// --- PrivateKey ------------------------------------------------------------

PrivateKey::PrivateKey(const bytes& data) : data_(data) {}

const bytes& PrivateKey::data() const { return data_; }

size_t PrivateKey::size() const { return data_.size(); }

bool PrivateKey::is_valid() const {
    if (!validity_checked_) {
        is_valid_ = (data_.size() == core::KYBER_PRIVATE_KEY_512 ||
                     data_.size() == core::KYBER_PRIVATE_KEY_768 ||
                     data_.size() == core::KYBER_PRIVATE_KEY_1024);
        validity_checked_ = true;
    }
    return is_valid_;
}

PublicKey PrivateKey::get_public_key() const {
    // An ML-KEM decapsulation key embeds the encapsulation key (public key):
    // dk = (dk_PKE || ek || H(ek) || z), where |dk_PKE| = 384*k = pk_size - 32.
    const SecurityLevel level = level_from_private_key_size(data_.size());
    const size_t pk_size = core::key_sizes::kyber_public_key_size(level);
    const size_t offset = pk_size - 32;
    if (data_.size() < offset + pk_size) {
        throw std::runtime_error("Malformed ML-KEM private key");
    }
    return PublicKey(bytes(data_.begin() + offset,
                           data_.begin() + offset + pk_size));
}

// --- KeyPair ---------------------------------------------------------------

KeyPair::KeyPair(PublicKey public_key, PrivateKey private_key)
    : public_key_(std::move(public_key)),
      private_key_(std::move(private_key)) {}

const PublicKey& KeyPair::public_key() const { return public_key_; }

const PrivateKey& KeyPair::private_key() const { return private_key_; }

// --- KEM -------------------------------------------------------------------

KeyPair generate_keypair(SecurityLevel level) {
    KemPtr kem = make_kem(level);

    bytes pk(kem->length_public_key);
    bytes sk(kem->length_secret_key);
    if (OQS_KEM_keypair(kem.get(), pk.data(), sk.data()) != OQS_SUCCESS) {
        throw std::runtime_error("ML-KEM key generation failed");
    }
    return KeyPair(PublicKey(pk), PrivateKey(sk));
}

core::Result<std::pair<bytes, bytes>> encapsulate(const PublicKey& public_key) {
    if (!public_key.is_valid()) {
        return core::Result<std::pair<bytes, bytes>>::error(
            "Invalid public key");
    }
    try {
        KemPtr kem = make_kem(level_from_public_key_size(public_key.size()));
        bytes ciphertext(kem->length_ciphertext);
        bytes shared_secret(kem->length_shared_secret);
        if (OQS_KEM_encaps(kem.get(), ciphertext.data(), shared_secret.data(),
                           public_key.data().data()) != OQS_SUCCESS) {
            return core::Result<std::pair<bytes, bytes>>::error(
                "ML-KEM encapsulation failed");
        }
        return core::Result<std::pair<bytes, bytes>>::success(
            std::make_pair(std::move(ciphertext), std::move(shared_secret)));
    } catch (const std::exception& e) {
        return core::Result<std::pair<bytes, bytes>>::error("encapsulate",
                                                            e.what());
    }
}

core::Result<bytes> decapsulate(const PrivateKey& private_key,
                                const bytes& ciphertext) {
    if (!private_key.is_valid()) {
        return core::Result<bytes>::error("Invalid private key");
    }
    try {
        KemPtr kem = make_kem(level_from_private_key_size(private_key.size()));
        if (ciphertext.size() != kem->length_ciphertext) {
            return core::Result<bytes>::error("Invalid ciphertext size");
        }
        bytes shared_secret(kem->length_shared_secret);
        // ML-KEM uses implicit rejection: a malformed ciphertext yields a
        // pseudo-random shared secret rather than an error.
        if (OQS_KEM_decaps(kem.get(), shared_secret.data(), ciphertext.data(),
                           private_key.data().data()) != OQS_SUCCESS) {
            return core::Result<bytes>::error("ML-KEM decapsulation failed");
        }
        return core::Result<bytes>::success(std::move(shared_secret));
    } catch (const std::exception& e) {
        return core::Result<bytes>::error("decapsulate", e.what());
    }
}

// --- KEM-DEM convenience encryption ----------------------------------------
//
// Wire layout: kem_ciphertext || nonce(12) || tag(16) || aes_gcm_ciphertext

core::bytes encrypt(const PublicKey& public_key, const core::bytes& plaintext) {
    if (!public_key.is_valid()) {
        throw std::invalid_argument("Invalid public key");
    }

    auto encaps = encapsulate(public_key);
    if (!encaps.is_success()) {
        throw std::runtime_error("encrypt: " + encaps.error());
    }
    const bytes& kem_ct = encaps.value().first;
    bytes key = core::hkdf_sha256(encaps.value().second, kdf_info(),
                                  core::AES_256_KEY_LEN);
    const bytes nonce = core::csprng_bytes(core::GCM_NONCE_LEN);

    bytes ct;
    bytes tag;
    try {
        core::aes256gcm_encrypt(key, nonce, /*aad=*/{}, plaintext, ct, tag);
    } catch (...) {
        core::secure_zero_memory(key.data(), key.size());
        throw;
    }
    core::secure_zero_memory(key.data(), key.size());

    bytes out;
    out.reserve(kem_ct.size() + nonce.size() + tag.size() + ct.size());
    out.insert(out.end(), kem_ct.begin(), kem_ct.end());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

core::Result<bytes> decrypt(const PrivateKey& private_key,
                            const bytes& ciphertext) {
    if (!private_key.is_valid()) {
        return core::Result<bytes>::error("Invalid private key");
    }
    try {
        KemPtr kem = make_kem(level_from_private_key_size(private_key.size()));
        const size_t kem_ct_len = kem->length_ciphertext;
        const size_t header = kem_ct_len + core::GCM_NONCE_LEN + core::GCM_TAG_LEN;
        if (ciphertext.size() < header) {
            return core::Result<bytes>::error("Ciphertext too short");
        }

        auto it = ciphertext.begin();
        bytes kem_ct(it, it + kem_ct_len);
        it += kem_ct_len;
        bytes nonce(it, it + core::GCM_NONCE_LEN);
        it += core::GCM_NONCE_LEN;
        bytes tag(it, it + core::GCM_TAG_LEN);
        it += core::GCM_TAG_LEN;
        bytes aes_ct(it, ciphertext.end());

        auto decaps = decapsulate(private_key, kem_ct);
        if (!decaps.is_success()) {
            return core::Result<bytes>::error(decaps.error());
        }
        bytes key = core::hkdf_sha256(decaps.value(), kdf_info(),
                                      core::AES_256_KEY_LEN);

        bytes plaintext;
        const bool ok =
            core::aes256gcm_decrypt(key, nonce, /*aad=*/{}, aes_ct, tag,
                                    plaintext);
        core::secure_zero_memory(key.data(), key.size());
        if (!ok) {
            return core::Result<bytes>::error("Authentication failed");
        }
        return core::Result<bytes>::success(std::move(plaintext));
    } catch (const std::exception& e) {
        return core::Result<bytes>::error("decrypt", e.what());
    }
}

// --- Sizes -----------------------------------------------------------------

size_t get_public_key_size(SecurityLevel level) {
    return core::key_sizes::kyber_public_key_size(level);
}

size_t get_private_key_size(SecurityLevel level) {
    return core::key_sizes::kyber_private_key_size(level);
}

size_t get_ciphertext_size(SecurityLevel level) {
    return core::key_sizes::kyber_ciphertext_size(level);
}

size_t get_shared_secret_size() { return 32; }

}  // namespace qybersafe::kyber
