#include "qybersafe/kyber/kyber_kem.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

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
constexpr size_t AES_KEY_LEN = 32;   // AES-256
constexpr size_t GCM_NONCE_LEN = 12; // 96-bit GCM nonce
constexpr size_t GCM_TAG_LEN = 16;   // 128-bit GCM tag

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

// HKDF-SHA-256 with an empty salt, extracting a fixed-length key.
bytes hkdf_sha256(const bytes& ikm, size_t out_len) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) throw std::runtime_error("HKDF: context allocation failed");

    if (EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(),
                                   static_cast<int>(ikm.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx.get(), reinterpret_cast<const unsigned char*>(KDF_INFO),
            static_cast<int>(sizeof(KDF_INFO) - 1)) <= 0) {
        throw std::runtime_error("HKDF: parameter setup failed");
    }

    bytes out(out_len);
    size_t len = out_len;
    if (EVP_PKEY_derive(ctx.get(), out.data(), &len) <= 0 || len != out_len) {
        throw std::runtime_error("HKDF: key derivation failed");
    }
    return out;
}

// AES-256-GCM. Appends nothing to inputs; tag is returned separately.
void aes_256_gcm_encrypt(const bytes& key, const bytes& nonce,
                         const bytes& plaintext, bytes& ciphertext,
                         bytes& tag) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("AES-GCM: context allocation failed");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM: encrypt init failed");
    }

    ciphertext.resize(plaintext.size());
    int out_len = 0;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("AES-GCM: encrypt update failed");
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len,
                            &final_len) != 1) {
        throw std::runtime_error("AES-GCM: encrypt final failed");
    }
    ciphertext.resize(static_cast<size_t>(out_len + final_len));

    tag.resize(GCM_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(GCM_TAG_LEN), tag.data()) != 1) {
        throw std::runtime_error("AES-GCM: get tag failed");
    }
}

// Returns false on authentication failure (does not throw on a bad tag).
bool aes_256_gcm_decrypt(const bytes& key, const bytes& nonce,
                         const bytes& ciphertext, const bytes& tag,
                         bytes& plaintext) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("AES-GCM: context allocation failed");

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM: decrypt init failed");
    }

    plaintext.resize(ciphertext.size());
    int out_len = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("AES-GCM: decrypt update failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()),
                            const_cast<unsigned char*>(tag.data())) != 1) {
        throw std::runtime_error("AES-GCM: set tag failed");
    }

    int final_len = 0;
    const int ok = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len,
                                       &final_len);
    if (ok != 1) {
        core::secure_zero_memory(plaintext.data(), plaintext.size());
        plaintext.clear();
        return false;
    }
    plaintext.resize(static_cast<size_t>(out_len + final_len));
    return true;
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
    bytes key = hkdf_sha256(encaps.value().second, AES_KEY_LEN);

    bytes nonce(GCM_NONCE_LEN);
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        core::secure_zero_memory(key.data(), key.size());
        throw std::runtime_error("encrypt: CSPRNG failure");
    }

    bytes ct;
    bytes tag;
    try {
        aes_256_gcm_encrypt(key, nonce, plaintext, ct, tag);
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
        const size_t header = kem_ct_len + GCM_NONCE_LEN + GCM_TAG_LEN;
        if (ciphertext.size() < header) {
            return core::Result<bytes>::error("Ciphertext too short");
        }

        auto it = ciphertext.begin();
        bytes kem_ct(it, it + kem_ct_len);
        it += kem_ct_len;
        bytes nonce(it, it + GCM_NONCE_LEN);
        it += GCM_NONCE_LEN;
        bytes tag(it, it + GCM_TAG_LEN);
        it += GCM_TAG_LEN;
        bytes aes_ct(it, ciphertext.end());

        auto decaps = decapsulate(private_key, kem_ct);
        if (!decaps.is_success()) {
            return core::Result<bytes>::error(decaps.error());
        }
        bytes key = hkdf_sha256(decaps.value(), AES_KEY_LEN);

        bytes plaintext;
        const bool ok = aes_256_gcm_decrypt(key, nonce, aes_ct, tag, plaintext);
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
