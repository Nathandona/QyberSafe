#ifndef QYBERSAFE_CORE_AEAD_H
#define QYBERSAFE_CORE_AEAD_H

/**
 * @file aead.h
 * @brief Shared symmetric primitives: HKDF-SHA-256, a CSPRNG, and AES-256-GCM.
 *
 * These wrap OpenSSL and are used by the KEM-DEM and hybrid constructions so the
 * symmetric layer lives in one place.
 */

#include "qybersafe/core/crypto_types.h"

namespace qybersafe::core {

/// AES-256-GCM tag length in bytes.
constexpr size_t GCM_TAG_LEN = 16;
/// Recommended AES-GCM nonce length in bytes (96-bit).
constexpr size_t GCM_NONCE_LEN = 12;
/// AES-256 key length in bytes.
constexpr size_t AES_256_KEY_LEN = 32;

/// HKDF-SHA-256 (extract+expand) with an empty salt. Throws on failure.
bytes hkdf_sha256(const bytes& ikm, const bytes& info, size_t out_len);

/// Random bytes from the OpenSSL CSPRNG. Throws on failure.
bytes csprng_bytes(size_t len);

/// AES-256-GCM encryption. @p tag receives the GCM_TAG_LEN-byte tag. Throws on
/// misuse.
void aes256gcm_encrypt(const bytes& key, const bytes& nonce, const bytes& aad,
                       const bytes& plaintext, bytes& ciphertext, bytes& tag);

/// AES-256-GCM decryption. Returns false on authentication failure (does not
/// throw on a bad tag). Throws on misuse.
bool aes256gcm_decrypt(const bytes& key, const bytes& nonce, const bytes& aad,
                       const bytes& ciphertext, const bytes& tag,
                       bytes& plaintext);

}  // namespace qybersafe::core

#endif  // QYBERSAFE_CORE_AEAD_H
