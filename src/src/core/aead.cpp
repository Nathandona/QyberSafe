#include "qybersafe/core/aead.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace qybersafe::core {

namespace {
// Last OpenSSL error as a string, for diagnostics in exception messages.
std::string openssl_error() {
    const unsigned long code = ERR_get_error();
    if (code == 0) return "no OpenSSL error on the queue";
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    return buf;
}
}  // namespace

bytes hkdf_sha256(const bytes& ikm, const bytes& info, size_t out_len) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(),
                                   static_cast<int>(ikm.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(),
                                    static_cast<int>(info.size())) <= 0) {
        throw std::runtime_error("HKDF setup failed: " + openssl_error());
    }
    bytes out(out_len);
    size_t len = out_len;
    if (EVP_PKEY_derive(ctx.get(), out.data(), &len) <= 0 || len != out_len) {
        throw std::runtime_error("HKDF derivation failed");
    }
    return out;
}

bytes csprng_bytes(size_t len) {
    bytes out(len);
    if (RAND_bytes(out.data(), static_cast<int>(len)) != 1) {
        throw std::runtime_error("CSPRNG failure");
    }
    return out;
}

void aes256gcm_encrypt(const bytes& key, const bytes& nonce, const bytes& aad,
                       const bytes& plaintext, bytes& ciphertext, bytes& tag) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx ||
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM encrypt init failed");
    }

    int out_len = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, aad.data(),
                          static_cast<int>(aad.size())) != 1) {
        throw std::runtime_error("AES-GCM AAD failed");
    }

    ciphertext.resize(plaintext.size());
    out_len = 0;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("AES-GCM encrypt failed");
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len,
                            &final_len) != 1) {
        throw std::runtime_error("AES-GCM encrypt final failed");
    }
    ciphertext.resize(static_cast<size_t>(out_len + final_len));

    tag.resize(GCM_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(GCM_TAG_LEN), tag.data()) != 1) {
        throw std::runtime_error("AES-GCM tag extraction failed");
    }
}

bool aes256gcm_decrypt(const bytes& key, const bytes& nonce, const bytes& aad,
                       const bytes& ciphertext, const bytes& tag,
                       bytes& plaintext) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx ||
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM decrypt init failed");
    }

    int out_len = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, aad.data(),
                          static_cast<int>(aad.size())) != 1) {
        throw std::runtime_error("AES-GCM AAD failed");
    }

    plaintext.resize(ciphertext.size());
    out_len = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("AES-GCM decrypt failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()),
                            const_cast<unsigned char*>(tag.data())) != 1) {
        throw std::runtime_error("AES-GCM set tag failed");
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len,
                            &final_len) != 1) {
        plaintext.clear();
        return false;
    }
    plaintext.resize(static_cast<size_t>(out_len + final_len));
    return true;
}

}  // namespace qybersafe::core
