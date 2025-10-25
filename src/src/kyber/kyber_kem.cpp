#include "qybersafe/kyber/kyber_kem.h"
#include "qybersafe/core/secure_random.h"
#include "qybersafe/utils/hex.h"
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>

namespace qybersafe::kyber {

using core::SecurityLevel;
using core::bytes;
using core::KYBER_PUBLIC_KEY_512;
using core::KYBER_PUBLIC_KEY_768;
using core::KYBER_PUBLIC_KEY_1024;
using core::KYBER_PRIVATE_KEY_512;
using core::KYBER_PRIVATE_KEY_768;
using core::KYBER_PRIVATE_KEY_1024;
using core::KYBER_CIPHERTEXT_512;
using core::KYBER_CIPHERTEXT_768;
using core::KYBER_CIPHERTEXT_1024;

// Kyber parameter sets
namespace {
    struct KyberParams {
        int k;  // Security parameter
        int n;  // Polynomial degree
        int q;  // Modulus
        int eta1; // Noise parameter
        int eta2; // Noise parameter
        int du;  // Encoding parameter
        int dv;  // Encoding parameter
        size_t public_key_size;
        size_t private_key_size;
        size_t ciphertext_size;
        size_t shared_secret_size;
    };

    const KyberParams KYBER512_PARAMS = {
        2, 256, 3329, 3, 2, 10, 4, 800, 1632, 768, 32
    };

    const KyberParams KYBER768_PARAMS = {
        3, 256, 3329, 2, 2, 10, 4, 1184, 2400, 1088, 32
    };

    const KyberParams KYBER1024_PARAMS = {
        4, 256, 3329, 2, 2, 11, 5, 1568, 3168, 1568, 32
    };

    const KyberParams* get_params(SecurityLevel level) {
        switch (level) {
            case SecurityLevel::KYBER_512:
                return &KYBER512_PARAMS;
            case SecurityLevel::KYBER_768:
                return &KYBER768_PARAMS;
            case SecurityLevel::KYBER_1024:
                return &KYBER1024_PARAMS;
            // Handle legacy compatibility
            case SecurityLevel::MEDIUM:
                return &KYBER768_PARAMS;
            default:
                throw std::invalid_argument("Invalid Kyber security level");
        }
    }
}

// PublicKey implementation
PublicKey::PublicKey(const bytes& data) : data_(data), validity_checked_(false), is_valid_(false) {}

const bytes& PublicKey::data() const {
    return data_;
}

size_t PublicKey::size() const {
    return data_.size();
}

bool PublicKey::is_valid() const {
    if (!validity_checked_) {
        // Validate based on expected sizes
        is_valid_ = (data_.size() == KYBER_PUBLIC_KEY_512 ||
                     data_.size() == KYBER_PUBLIC_KEY_768 ||
                     data_.size() == KYBER_PUBLIC_KEY_1024);
        validity_checked_ = true;
    }
    return is_valid_;
}

// PrivateKey implementation
PrivateKey::PrivateKey(const bytes& data) : data_(data), validity_checked_(false), is_valid_(false) {}

const bytes& PrivateKey::data() const {
    return data_;
}

size_t PrivateKey::size() const {
    return data_.size();
}

bool PrivateKey::is_valid() const {
    if (!validity_checked_) {
        // Validate based on expected sizes
        is_valid_ = (data_.size() == KYBER_PRIVATE_KEY_512 ||
                     data_.size() == KYBER_PRIVATE_KEY_768 ||
                     data_.size() == KYBER_PRIVATE_KEY_1024);
        validity_checked_ = true;
    }
    return is_valid_;
}

PublicKey PrivateKey::get_public_key() const {
    // In a real implementation, extract the public key from the private key
    // For now, return the first part of the private key
    if (data_.size() < 800) {
        throw std::runtime_error("Private key too small to extract public key");
    }

    size_t pk_size = 800; // Default to Kyber512 size
    if (data_.size() >= 1632) pk_size = 800;
    if (data_.size() >= 2400) pk_size = 1184;
    if (data_.size() >= 3168) pk_size = 1568;

    return PublicKey(bytes(data_.begin(), data_.begin() + pk_size));
}

// KeyPair implementation
KeyPair::KeyPair(PublicKey public_key, PrivateKey private_key)
    : public_key_(std::move(public_key)), private_key_(std::move(private_key)) {}

const PublicKey& KeyPair::public_key() const {
    return public_key_;
}

const PrivateKey& KeyPair::private_key() const {
    return private_key_;
}

// Helper functions
namespace {
    // SHAKE-256 hash function
    bytes shake256(const bytes& input, size_t output_length) {
        bytes output(output_length);

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create hash context");
        }

        if (EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize hash");
        }

        if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update hash");
        }

        if (EVP_DigestFinalXOF(ctx, output.data(), output_length) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize hash");
        }

        EVP_MD_CTX_free(ctx);
        return output;
    }

    // Simple polynomial operations (simplified for demonstration)
    bytes generate_polynomial(SecurityLevel level) {
        const KyberParams* params = get_params(level);
        auto random_result = core::random_bytes(params->n * 2); // 2 bytes per coefficient

        if (!random_result.is_success()) {
            throw std::runtime_error("Failed to generate random bytes: " + random_result.error());
        }

        return random_result.value();
    }

    // Simplified polynomial multiplication
    bytes polynomial_multiply(const bytes& a, const bytes& b, SecurityLevel level) {
        const KyberParams* params = get_params(level);
        bytes result(params->n * 2, 0); // 2 bytes per coefficient

        // This is a very simplified version - real implementation would use NTT
        for (size_t i = 0; i < std::min(a.size(), b.size()); i += 2) {
            for (size_t j = 0; j < std::min(a.size(), b.size()); j += 2) {
                int16_t coeff_a = static_cast<int16_t>(a[i]) | (static_cast<int16_t>(a[i + 1]) << 8);
                int16_t coeff_b = static_cast<int16_t>(b[j]) | (static_cast<int16_t>(b[j + 1]) << 8);

                // Simplified multiplication modulo q
                int32_t product = (coeff_a * coeff_b) % params->q;

                if (i + j < result.size() - 1) {
                    result[i + j] = static_cast<uint8_t>(product & 0xFF);
                    result[i + j + 1] = static_cast<uint8_t>((product >> 8) & 0xFF);
                }
            }
        }

        return result;
    }
}

// Core Kyber functions
KeyPair generate_keypair(SecurityLevel level) {
    const KyberParams* params = get_params(level);

    try {
        // Generate seed for key generation
        auto seed_result = core::random_bytes(32);
        if (!seed_result.is_success()) {
            throw std::runtime_error("Failed to generate seed: " + seed_result.error());
        }

        // Generate expanded key material
        bytes key_material = shake256(seed_result.value(), params->public_key_size + params->private_key_size);

        // Split into public and private key parts
        bytes pk_data(key_material.begin(), key_material.begin() + params->public_key_size);
        bytes sk_data(key_material.begin() + params->public_key_size, key_material.end());

        // Add public key to private key for Kyber
        sk_data.insert(sk_data.end(), pk_data.begin(), pk_data.end());

        PublicKey public_key(pk_data);
        PrivateKey private_key(sk_data);

        return KeyPair(std::move(public_key), std::move(private_key));

    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to generate Kyber keypair: " + std::string(e.what()));
    }
}

core::bytes encrypt(const PublicKey& public_key, const core::bytes& plaintext) {
    if (!public_key.is_valid()) {
        throw std::invalid_argument("Invalid public key");
    }

    SecurityLevel level;
    if (public_key.size() == KYBER_PUBLIC_KEY_512) {
        level = SecurityLevel::KYBER_512;
    } else if (public_key.size() == KYBER_PUBLIC_KEY_768) {
        level = SecurityLevel::KYBER_768;
    } else if (public_key.size() == KYBER_PUBLIC_KEY_1024) {
        level = SecurityLevel::KYBER_1024;
    } else {
        throw std::invalid_argument("Invalid public key size");
    }

    const KyberParams* params = get_params(level);

    try {
        // Generate random nonce and message
        auto random_result = core::random_bytes(32);
        if (!random_result.is_success()) {
            throw std::runtime_error("Failed to generate random bytes: " + random_result.error());
        }

        bytes nonce = random_result.value();

        // Generate temporary key pair for encapsulation
        KeyPair temp_keypair = generate_keypair(level);

        // Compute shared secret (simplified)
        bytes shared_secret = shake256(temp_keypair.private_key().data(), 32);

        // Encrypt the message (simplified)
        bytes ciphertext = shake256(nonce, params->ciphertext_size);

        // XOR plaintext with part of ciphertext
        for (size_t i = 0; i < std::min(plaintext.size(), ciphertext.size()); ++i) {
            ciphertext[i] ^= plaintext[i];
        }

        return ciphertext;

    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to encrypt with Kyber: " + std::string(e.what()));
    }
}

core::Result<bytes> decrypt(const PrivateKey& private_key, const bytes& ciphertext) {
    if (!private_key.is_valid()) {
        return core::Result<bytes>::error("Invalid private key");
    }

    SecurityLevel level;
    if (private_key.size() == KYBER_PRIVATE_KEY_512) {
        level = SecurityLevel::KYBER_512;
    } else if (private_key.size() == KYBER_PRIVATE_KEY_768) {
        level = SecurityLevel::KYBER_768;
    } else if (private_key.size() == KYBER_PRIVATE_KEY_1024) {
        level = SecurityLevel::KYBER_1024;
    } else {
        return core::Result<bytes>::error("Invalid private key size");
    }

    try {
        // Extract shared secret from private key (simplified)
        bytes shared_secret = shake256(private_key.data(), 32);

        // Decrypt by XORing with shared secret-derived key
        bytes plaintext(ciphertext.size(), 0);
        bytes decryption_key = shake256(shared_secret, ciphertext.size());

        for (size_t i = 0; i < ciphertext.size(); ++i) {
            plaintext[i] = ciphertext[i] ^ decryption_key[i];
        }

        return core::Result<bytes>::success(std::move(plaintext));

    } catch (const std::exception& e) {
        return core::Result<bytes>::error("Failed to decrypt with Kyber: " + std::string(e.what()));
    }
}

core::Result<std::pair<bytes, bytes>> encapsulate(const PublicKey& public_key) {
    if (!public_key.is_valid()) {
        return core::Result<std::pair<bytes, bytes>>::error("Invalid public key");
    }

    try {
        // Generate random shared secret
        auto secret_result = core::random_bytes(32);
        if (!secret_result.is_success()) {
            return core::Result<std::pair<bytes, bytes>>::error("Failed to generate shared secret: " + secret_result.error());
        }

        bytes shared_secret = secret_result.value();

        // Encrypt the shared secret
        bytes ciphertext = encrypt(public_key, shared_secret);

        return core::Result<std::pair<bytes, bytes>>::success(std::make_pair(std::move(ciphertext), std::move(shared_secret)));

    } catch (const std::exception& e) {
        return core::Result<std::pair<bytes, bytes>>::error("Failed to encapsulate with Kyber: " + std::string(e.what()));
    }
}

core::Result<bytes> decapsulate(const PrivateKey& private_key, const bytes& ciphertext) {
    auto decrypt_result = decrypt(private_key, ciphertext);
    if (!decrypt_result.is_success()) {
        return decrypt_result;
    }

    return core::Result<bytes>::success(decrypt_result.value());
}

// Utility functions
size_t get_public_key_size(SecurityLevel level) {
    const KyberParams* params = get_params(level);
    return params->public_key_size;
}

size_t get_private_key_size(SecurityLevel level) {
    const KyberParams* params = get_params(level);
    return params->private_key_size;
}

size_t get_ciphertext_size(SecurityLevel level) {
    const KyberParams* params = get_params(level);
    return params->ciphertext_size;
}

size_t get_shared_secret_size() {
    return 32; // 256-bit shared secret
}

} // namespace qybersafe::kyber