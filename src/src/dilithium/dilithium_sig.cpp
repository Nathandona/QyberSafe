#include "qybersafe/dilithium/dilithium_sig.h"
#include "qybersafe/core/secure_random.h"
#include "qybersafe/utils/hex.h"
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>

namespace qybersafe::dilithium {

using core::SecurityLevel;
using core::bytes;
using core::Algorithm;
using core::DILITHIUM_PUBLIC_KEY_2;
using core::DILITHIUM_PRIVATE_KEY_2;
using core::DILITHIUM_SIGNATURE_2;
using core::DILITHIUM_PUBLIC_KEY_3;
using core::DILITHIUM_PRIVATE_KEY_3;
using core::DILITHIUM_SIGNATURE_3;
using core::DILITHIUM_PUBLIC_KEY_5;
using core::DILITHIUM_PRIVATE_KEY_5;
using core::DILITHIUM_SIGNATURE_5;

// Dilithium parameter sets
namespace {
    struct DilithiumParams {
        int n;  // Polynomial degree
        int q;  // Modulus
        int d;  // Number of bits dropped
        int k;  // Number of polynomials in vector s1
        int l;  // Number of polynomials in vector s2
        int eta; // Noise parameter
        int beta; // Rejection sampling parameter
        int omega; // Number of rejections allowed
        size_t public_key_size;
        size_t private_key_size;
        size_t signature_size;
    };

    const DilithiumParams DILITHIUM2_PARAMS = {
        256, 8380417, 13, 4, 4, 2, 78, 80, 1312, 2528, 2420
    };

    const DilithiumParams DILITHIUM3_PARAMS = {
        256, 8380417, 13, 6, 5, 4, 196, 55, 1952, 4000, 3293
    };

    const DilithiumParams DILITHIUM5_PARAMS = {
        256, 8380417, 13, 8, 7, 2, 120, 75, 2592, 4864, 4595
    };

    const DilithiumParams* get_params(SecurityLevel level) {
        switch (level) {
            case SecurityLevel::DILITHIUM_2:
                return &DILITHIUM2_PARAMS;
            case SecurityLevel::DILITHIUM_3:
                return &DILITHIUM3_PARAMS;
            case SecurityLevel::DILITHIUM_5:
                return &DILITHIUM5_PARAMS;
            // Handle legacy compatibility
            case SecurityLevel::MEDIUM:
                return &DILITHIUM3_PARAMS;
            default:
                throw std::invalid_argument("Invalid Dilithium security level");
        }
    }
}

// VerifyingKey implementation
VerifyingKey::VerifyingKey(const bytes& data) : data_(data), validity_checked_(false), is_valid_(false) {}

const bytes& VerifyingKey::data() const {
    return data_;
}

size_t VerifyingKey::size() const {
    return data_.size();
}

bool VerifyingKey::is_valid() const {
    if (!validity_checked_) {
        // Validate based on expected sizes
        is_valid_ = (data_.size() == DILITHIUM_PUBLIC_KEY_2 ||
                     data_.size() == DILITHIUM_PUBLIC_KEY_3 ||
                     data_.size() == DILITHIUM_PUBLIC_KEY_5);
        validity_checked_ = true;
    }
    return is_valid_;
}

// SigningKey implementation
SigningKey::SigningKey(const bytes& data) : data_(data), validity_checked_(false), is_valid_(false) {}

const bytes& SigningKey::data() const {
    return data_;
}

size_t SigningKey::size() const {
    return data_.size();
}

bool SigningKey::is_valid() const {
    if (!validity_checked_) {
        // Validate based on expected sizes
        is_valid_ = (data_.size() == DILITHIUM_PRIVATE_KEY_2 ||
                     data_.size() == DILITHIUM_PRIVATE_KEY_3 ||
                     data_.size() == DILITHIUM_PRIVATE_KEY_5);
        validity_checked_ = true;
    }
    return is_valid_;
}

VerifyingKey SigningKey::get_verifying_key() const {
    // In a real implementation, extract the public key from the private key
    // For now, return the first part of the private key
    if (data_.size() < 1312) {
        throw std::runtime_error("Private key too small to extract public key");
    }

    size_t vk_size = 1312; // Default to Dilithium2 size
    if (data_.size() >= 1952) vk_size = 1952;
    if (data_.size() >= 2592) vk_size = 2592;

    return VerifyingKey(bytes(data_.begin(), data_.begin() + vk_size));
}

// SigningKeyPair implementation
SigningKeyPair::SigningKeyPair(VerifyingKey verifying_key, SigningKey signing_key)
    : verifying_key_(std::move(verifying_key)), signing_key_(std::move(signing_key)) {}

const VerifyingKey& SigningKeyPair::verifying_key() const {
    return verifying_key_;
}

const SigningKey& SigningKeyPair::signing_key() const {
    return signing_key_;
}

// Helper functions
namespace {
    // SHA3-256 hash function
    bytes sha3_256(const bytes& input) {
        bytes output(32);

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create hash context");
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize hash");
        }

        if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update hash");
        }

        unsigned int digest_len;
        if (EVP_DigestFinal_ex(ctx, output.data(), &digest_len) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize hash");
        }

        EVP_MD_CTX_free(ctx);
        return output;
    }

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
    bytes generate_polynomial_vector(size_t count, SecurityLevel level) {
        const DilithiumParams* params = get_params(level);
        auto random_result = core::random_bytes(count * params->n * 2); // 2 bytes per coefficient

        if (!random_result.is_success()) {
            throw std::runtime_error("Failed to generate random bytes: " + random_result.error());
        }

        return random_result.value();
    }

    // Rejection sampling for coefficient generation
    bytes rejection_sample(const bytes& seed, size_t count, SecurityLevel level) {
        const DilithiumParams* params = get_params(level);
        bytes result(count * params->n * 2, 0);

        // Simple rejection sampling (simplified)
        size_t result_index = 0;
        for (size_t i = 0; i < seed.size() && result_index < result.size(); i += 3) {
            if (i + 2 < seed.size()) {
                // Combine 3 bytes to get coefficients
                uint16_t val1 = (static_cast<uint16_t>(seed[i]) << 4) | (static_cast<uint16_t>(seed[i + 1]) >> 4);
                uint16_t val2 = ((static_cast<uint16_t>(seed[i + 1]) & 0x0F) << 8) | static_cast<uint16_t>(seed[i + 2]);

                if (val1 < params->q && result_index < result.size()) {
                    result[result_index++] = static_cast<uint8_t>(val1 & 0xFF);
                    if (result_index < result.size()) {
                        result[result_index++] = static_cast<uint8_t>((val1 >> 8) & 0xFF);
                    }
                }

                if (val2 < params->q && result_index < result.size()) {
                    result[result_index++] = static_cast<uint8_t>(val2 & 0xFF);
                    if (result_index < result.size()) {
                        result[result_index++] = static_cast<uint8_t>((val2 >> 8) & 0xFF);
                    }
                }
            }
        }

        return result;
    }
}

// Core Dilithium functions
SigningKeyPair generate_keypair(SecurityLevel level) {
    const DilithiumParams* params = get_params(level);

    try {
        // Generate seed for key generation
        auto seed_result = core::random_bytes(32);
        if (!seed_result.is_success()) {
            throw std::runtime_error("Failed to generate seed: " + seed_result.error());
        }

        // Generate expanded key material
        bytes key_material = shake256(seed_result.value(), params->public_key_size + params->private_key_size);

        // Generate matrix A (public key part)
        bytes matrix_a = generate_polynomial_vector(params->k, level);

        // Generate secret vectors s1 and s2
        bytes s1 = rejection_sample(shake256(seed_result.value(), 64), params->l, level);
        bytes s2 = rejection_sample(shake256(sha3_256(seed_result.value()), 64), params->k, level);

        // Compute public key: t = A * s1 + s2
        bytes public_key_data = matrix_a; // Simplified - real implementation would multiply

        // Private key contains s1, s2, and public key
        bytes private_key_data;
        private_key_data.reserve(params->private_key_size);
        private_key_data.insert(private_key_data.end(), s1.begin(), s1.end());
        private_key_data.insert(private_key_data.end(), s2.begin(), s2.end());
        private_key_data.insert(private_key_data.end(), public_key_data.begin(), public_key_data.end());

        VerifyingKey verifying_key(public_key_data);
        SigningKey signing_key(private_key_data);

        return SigningKeyPair(std::move(verifying_key), std::move(signing_key));

    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to generate Dilithium keypair: " + std::string(e.what()));
    }
}

core::Result<bytes> sign(const SigningKey& signing_key, const bytes& message) {
    if (!signing_key.is_valid()) {
        return core::Result<bytes>::error("Invalid signing key");
    }

    SecurityLevel level;
    if (signing_key.size() == DILITHIUM_PRIVATE_KEY_2) {
        level = SecurityLevel::DILITHIUM_2;
    } else if (signing_key.size() == DILITHIUM_PRIVATE_KEY_3) {
        level = SecurityLevel::DILITHIUM_3;
    } else if (signing_key.size() == DILITHIUM_PRIVATE_KEY_5) {
        level = SecurityLevel::DILITHIUM_5;
    } else {
        return core::Result<bytes>::error("Invalid signing key size");
    }

    const DilithiumParams* params = get_params(level);

    try {
        // Hash the message
        bytes message_hash = sha3_256(message);

        // Generate random nonce for this signature
        auto nonce_result = core::random_bytes(32);
        if (!nonce_result.is_success()) {
            return core::Result<bytes>::error("Failed to generate nonce: " + nonce_result.error());
        }

        bytes nonce = nonce_result.value();

        // Compute commitment (simplified)
        bytes combined_input;
        combined_input.reserve(nonce.size() + message_hash.size());
        combined_input.insert(combined_input.end(), nonce.begin(), nonce.end());
        combined_input.insert(combined_input.end(), message_hash.begin(), message_hash.end());
        bytes commitment = shake256(combined_input, 64);

        // Compute challenge
        bytes challenge = shake256(commitment, 64);

        // Generate response (simplified)
        bytes challenge_input;
        challenge_input.reserve(challenge.size() + message_hash.size());
        challenge_input.insert(challenge_input.end(), challenge.begin(), challenge.end());
        challenge_input.insert(challenge_input.end(), message_hash.begin(), message_hash.end());
        bytes response = shake256(challenge_input, params->signature_size);

        // Create signature: (response, commitment)
        bytes signature;
        signature.reserve(params->signature_size);
        signature.insert(signature.end(), response.begin(), response.end());
        signature.insert(signature.end(), commitment.begin(), commitment.end());

        // Ensure signature size is correct
        if (signature.size() > params->signature_size) {
            signature.resize(params->signature_size);
        } else if (signature.size() < params->signature_size) {
            auto padding_result = core::random_bytes(params->signature_size - signature.size());
            if (!padding_result.is_success()) {
                return core::Result<bytes>::error("Failed to generate padding: " + padding_result.error());
            }
            signature.insert(signature.end(), padding_result.value().begin(), padding_result.value().end());
        }

        return core::Result<bytes>::success(std::move(signature));

    } catch (const std::exception& e) {
        return core::Result<bytes>::error("Failed to sign with Dilithium: " + std::string(e.what()));
    }
}

bool verify(const VerifyingKey& verifying_key, const bytes& message, const bytes& signature) {
    if (!verifying_key.is_valid()) {
        return false;
    }

    SecurityLevel level;
    if (verifying_key.size() == DILITHIUM_PUBLIC_KEY_2) {
        level = SecurityLevel::DILITHIUM_2;
    } else if (verifying_key.size() == DILITHIUM_PUBLIC_KEY_3) {
        level = SecurityLevel::DILITHIUM_3;
    } else if (verifying_key.size() == DILITHIUM_PUBLIC_KEY_5) {
        level = SecurityLevel::DILITHIUM_5;
    } else {
        return false;
    }

    const DilithiumParams* params = get_params(level);

    try {
        // Check signature size
        if (signature.size() != params->signature_size) {
            return false;
        }

        // Hash the message
        bytes message_hash = sha3_256(message);

        // Split signature into response and commitment
        size_t split_point = signature.size() / 2;
        bytes response(signature.begin(), signature.begin() + split_point);
        bytes commitment(signature.begin() + split_point, signature.end());

        // Recompute challenge
        bytes expected_challenge = shake256(commitment, 64);

        // Verify the response matches the expected computation
        bytes verify_input;
        verify_input.reserve(expected_challenge.size() + message_hash.size());
        verify_input.insert(verify_input.end(), expected_challenge.begin(), expected_challenge.end());
        verify_input.insert(verify_input.end(), message_hash.begin(), message_hash.end());
        bytes expected_response = shake256(verify_input, response.size());

        // Constant-time comparison
        if (response.size() != expected_response.size()) {
            return false;
        }

        bool result = true;
        for (size_t i = 0; i < response.size(); ++i) {
            result &= (response[i] == expected_response[i]);
        }

        return result;

    } catch (const std::exception& e) {
        return false;
    }
}

// Utility functions
size_t get_verifying_key_size(SecurityLevel level) {
    const DilithiumParams* params = get_params(level);
    return params->public_key_size;
}

size_t get_signing_key_size(SecurityLevel level) {
    const DilithiumParams* params = get_params(level);
    return params->private_key_size;
}

size_t get_signature_size(SecurityLevel level) {
    const DilithiumParams* params = get_params(level);
    return params->signature_size;
}

// Message hashing for signing
bytes hash_message(const bytes& message) {
    return sha3_256(message);
}

} // namespace qybersafe::dilithium