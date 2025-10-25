#include "qybersafe/hybrid/hybrid_encryption.h"
#include "qybersafe/kyber/kyber_kem.h"
#include "qybersafe/core/secure_random.h"
#include "qybersafe/utils/hex.h"
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

namespace qybersafe::hybrid {

using core::bytes;

// Hybrid key pair combining classical and post-quantum algorithms
class HybridKeyPairImpl {
public:
    HybridKeyPairImpl(kyber::KeyPair pq_keypair, bytes classical_keypair)
        : pq_keypair_(std::move(pq_keypair)), classical_keypair_(std::move(classical_keypair)) {}

    const kyber::KeyPair& pq_keypair() const { return pq_keypair_; }
    const bytes& classical_keypair() const { return classical_keypair_; }

private:
    kyber::KeyPair pq_keypair_;
    bytes classical_keypair_;
};

// Hybrid public key implementation
HybridPublicKey::HybridPublicKey(const kyber::PublicKey& pq_key, const bytes& classical_key)
    : pq_key_(pq_key), classical_key_(classical_key), validity_checked_(false), is_valid_(false) {}

HybridPublicKey::HybridPublicKey(const bytes& data) : pq_key_(bytes{}), data_(data), validity_checked_(false), is_valid_(false) {
    // Parse combined key data
    if (data.size() >= 4) {
        size_t pq_size = (static_cast<size_t>(data[0]) << 24) |
                        (static_cast<size_t>(data[1]) << 16) |
                        (static_cast<size_t>(data[2]) << 8) |
                        static_cast<size_t>(data[3]);

        if (data.size() >= 4 + pq_size) {
            bytes pq_key_data(data.begin() + 4, data.begin() + 4 + pq_size);
            pq_key_ = kyber::PublicKey(pq_key_data);

            bytes classical_key_data(data.begin() + 4 + pq_size, data.end());
            classical_key_ = classical_key_data;
        }
    }
}

const kyber::PublicKey& HybridPublicKey::pq_key() const {
    return pq_key_;
}

const bytes& HybridPublicKey::classical_key() const {
    return classical_key_;
}

core::bytes HybridPublicKey::data() const {
    if (data_.empty()) {
        // Serialize combined key
        bytes pq_key_data = pq_key_.data();
        size_t pq_size = pq_key_data.size();

        data_.reserve(4 + pq_size + classical_key_.size());

        // Add size prefix
        data_.push_back(static_cast<uint8_t>((pq_size >> 24) & 0xFF));
        data_.push_back(static_cast<uint8_t>((pq_size >> 16) & 0xFF));
        data_.push_back(static_cast<uint8_t>((pq_size >> 8) & 0xFF));
        data_.push_back(static_cast<uint8_t>(pq_size & 0xFF));

        // Add PQC key
        data_.insert(data_.end(), pq_key_data.begin(), pq_key_data.end());

        // Add classical key
        data_.insert(data_.end(), classical_key_.begin(), classical_key_.end());
    }
    return data_;
}

size_t HybridPublicKey::size() const {
    return data().size();
}

bool HybridPublicKey::is_valid() const {
    if (!validity_checked_) {
        is_valid_ = pq_key_.is_valid() && !classical_key_.empty();
        validity_checked_ = true;
    }
    return is_valid_;
}

// Hybrid private key implementation
HybridPrivateKey::HybridPrivateKey(const kyber::PrivateKey& pq_key, const bytes& classical_key)
    : pq_key_(pq_key), classical_key_(classical_key), validity_checked_(false), is_valid_(false) {}

HybridPrivateKey::HybridPrivateKey(const bytes& data) : pq_key_(bytes{}), data_(data), validity_checked_(false), is_valid_(false) {
    // Parse combined key data
    if (data.size() >= 4) {
        size_t pq_size = (static_cast<size_t>(data[0]) << 24) |
                        (static_cast<size_t>(data[1]) << 16) |
                        (static_cast<size_t>(data[2]) << 8) |
                        static_cast<size_t>(data[3]);

        if (data.size() >= 4 + pq_size) {
            bytes pq_key_data(data.begin() + 4, data.begin() + 4 + pq_size);
            pq_key_ = kyber::PrivateKey(pq_key_data);

            bytes classical_key_data(data.begin() + 4 + pq_size, data.end());
            classical_key_ = classical_key_data;
        }
    }
}

const kyber::PrivateKey& HybridPrivateKey::pq_key() const {
    return pq_key_;
}

const bytes& HybridPrivateKey::classical_key() const {
    return classical_key_;
}

core::bytes HybridPrivateKey::data() const {
    if (data_.empty()) {
        // Serialize combined key
        bytes pq_key_data = pq_key_.data();
        size_t pq_size = pq_key_data.size();

        data_.reserve(4 + pq_size + classical_key_.size());

        // Add size prefix
        data_.push_back(static_cast<uint8_t>((pq_size >> 24) & 0xFF));
        data_.push_back(static_cast<uint8_t>((pq_size >> 16) & 0xFF));
        data_.push_back(static_cast<uint8_t>((pq_size >> 8) & 0xFF));
        data_.push_back(static_cast<uint8_t>(pq_size & 0xFF));

        // Add PQC key
        data_.insert(data_.end(), pq_key_data.begin(), pq_key_data.end());

        // Add classical key
        data_.insert(data_.end(), classical_key_.begin(), classical_key_.end());
    }
    return data_;
}

size_t HybridPrivateKey::size() const {
    return data().size();
}

bool HybridPrivateKey::is_valid() const {
    if (!validity_checked_) {
        is_valid_ = pq_key_.is_valid() && !classical_key_.empty();
        validity_checked_ = true;
    }
    return is_valid_;
}

HybridPublicKey HybridPrivateKey::get_public_key() const {
    kyber::PublicKey pq_public_key = pq_key_.get_public_key();
    return HybridPublicKey(pq_public_key, classical_key_);
}

// Hybrid key pair implementation
HybridKeyPair::HybridKeyPair(const HybridPublicKey& public_key, const HybridPrivateKey& private_key)
    : impl_(std::make_shared<HybridKeyPairImpl>(
        kyber::KeyPair(public_key.pq_key(), private_key.pq_key()),
        public_key.classical_key())) {}

const HybridPublicKey& HybridKeyPair::public_key() const {
    if (!public_key_) {
        kyber::PublicKey pq_public_key = impl_->pq_keypair().public_key();
        public_key_ = HybridPublicKey(pq_public_key, impl_->classical_keypair());
    }
    return *public_key_;
}

const HybridPrivateKey& HybridKeyPair::private_key() const {
    if (!private_key_) {
        kyber::PrivateKey pq_private_key = impl_->pq_keypair().private_key();
        private_key_ = HybridPrivateKey(pq_private_key, impl_->classical_keypair());
    }
    return *private_key_;
}

// Helper functions
namespace {
    // Generate classical (AES) key pair
    std::pair<core::bytes, core::bytes> generate_aes_keypair() {
        core::bytes public_key(32); // AES-256 key size
        core::bytes private_key(32);

        // Generate random key
        if (RAND_bytes(public_key.data(), 32) != 1) {
            throw std::runtime_error("Failed to generate AES key");
        }

        // For symmetric encryption, private key is the same as public key
        private_key = public_key;

        return std::make_pair(public_key, private_key);
    }

    // AES-256-GCM encryption
    core::bytes aes_encrypt(const core::bytes& key, const core::bytes& plaintext, core::bytes& iv, core::bytes& tag) {
        if (key.size() != 32) {
            throw std::invalid_argument("AES key must be 32 bytes");
        }

        // Generate random IV
        iv.resize(12); // GCM recommended IV size
        if (RAND_bytes(iv.data(), 12) != 1) {
            throw std::runtime_error("Failed to generate IV");
        }

        tag.resize(16); // GCM tag size

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        try {
            // Initialize encryption
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
                throw std::runtime_error("Failed to initialize encryption");
            }

            // Set IV length
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
                throw std::runtime_error("Failed to set IV length");
            }

            // Initialize key and IV
            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
                throw std::runtime_error("Failed to set key and IV");
            }

            core::bytes ciphertext(plaintext.size() + 16); // Extra space for tag
            int len;
            int ciphertext_len;

            // Encrypt plaintext
            if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
                throw std::runtime_error("Failed to encrypt data");
            }
            ciphertext_len = len;

            // Finalize encryption
            if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
                throw std::runtime_error("Failed to finalize encryption");
            }
            ciphertext_len += len;

            // Get tag
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
                throw std::runtime_error("Failed to get authentication tag");
            }

            ciphertext.resize(ciphertext_len);
            EVP_CIPHER_CTX_free(ctx);
            return ciphertext;

        } catch (const std::exception& e) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
    }

    // AES-256-GCM decryption
    core::bytes aes_decrypt(const core::bytes& key, const core::bytes& ciphertext, const core::bytes& iv, const core::bytes& tag) {
        if (key.size() != 32) {
            throw std::invalid_argument("AES key must be 32 bytes");
        }

        if (iv.size() != 12) {
            throw std::invalid_argument("IV must be 12 bytes");
        }

        if (tag.size() != 16) {
            throw std::invalid_argument("Tag must be 16 bytes");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        try {
            // Initialize decryption
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
                throw std::runtime_error("Failed to initialize decryption");
            }

            // Set IV length
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
                throw std::runtime_error("Failed to set IV length");
            }

            // Initialize key and IV
            if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
                throw std::runtime_error("Failed to set key and IV");
            }

            core::bytes plaintext(ciphertext.size());
            int len;
            int plaintext_len;

            // Decrypt ciphertext
            if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
                throw std::runtime_error("Failed to decrypt data");
            }
            plaintext_len = len;

            // Set expected tag value
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag.data())) != 1) {
                throw std::runtime_error("Failed to set authentication tag");
            }

            // Finalize decryption (this will verify the tag)
            if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
                throw std::runtime_error("Authentication failed - invalid tag");
            }
            plaintext_len += len;

            plaintext.resize(plaintext_len);
            EVP_CIPHER_CTX_free(ctx);
            return plaintext;

        } catch (const std::exception& e) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
    }
}

// Core hybrid encryption functions
HybridKeyPair generate_hybrid_keypair() {
    try {
        // Generate post-quantum key pair (Kyber)
        kyber::KeyPair pq_keypair = kyber::generate_keypair(core::SecurityLevel::KYBER_768);

        // Generate classical key pair (AES)
        auto aes_keypair = generate_aes_keypair();

        return HybridKeyPair(
            HybridPublicKey(pq_keypair.public_key(), aes_keypair.first),
            HybridPrivateKey(pq_keypair.private_key(), aes_keypair.second)
        );

    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to generate hybrid keypair: " + std::string(e.what()));
    }
}

core::bytes hybrid_encrypt(const HybridPublicKey& public_key, const core::bytes& plaintext) {
    if (!public_key.is_valid()) {
        throw std::invalid_argument("Invalid hybrid public key");
    }

    try {
        // Generate random symmetric key for message encryption
        auto sym_key_result = core::random_bytes(32);
        if (!sym_key_result.is_success()) {
            throw std::runtime_error("Failed to generate symmetric key: " + sym_key_result.error());
        }

        core::bytes sym_key = sym_key_result.value();

        // Encrypt the symmetric key with post-quantum algorithm
        bytes pq_encrypted_key = kyber::encrypt(public_key.pq_key(), sym_key);

        // Encrypt the message with classical algorithm
        bytes iv, tag;
        bytes classical_ciphertext = aes_encrypt(public_key.classical_key(), plaintext, iv, tag);

        // Combine all components
        bytes ciphertext;
        ciphertext.reserve(4 + pq_encrypted_key.size() + 12 + 16 + classical_ciphertext.size());

        // Add PQ encrypted key length
        size_t pq_size = pq_encrypted_key.size();
        ciphertext.push_back(static_cast<uint8_t>((pq_size >> 24) & 0xFF));
        ciphertext.push_back(static_cast<uint8_t>((pq_size >> 16) & 0xFF));
        ciphertext.push_back(static_cast<uint8_t>((pq_size >> 8) & 0xFF));
        ciphertext.push_back(static_cast<uint8_t>(pq_size & 0xFF));

        // Add PQ encrypted key
        ciphertext.insert(ciphertext.end(), pq_encrypted_key.begin(), pq_encrypted_key.end());

        // Add IV
        ciphertext.insert(ciphertext.end(), iv.begin(), iv.end());

        // Add authentication tag
        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

        // Add classical ciphertext
        ciphertext.insert(ciphertext.end(), classical_ciphertext.begin(), classical_ciphertext.end());

        return ciphertext;

    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to hybrid encrypt: " + std::string(e.what()));
    }
}

core::bytes hybrid_decrypt(const HybridPrivateKey& private_key, const core::bytes& ciphertext) {
    if (!private_key.is_valid()) {
        throw std::invalid_argument("Invalid hybrid private key");
    }

    if (ciphertext.size() < 4 + 12 + 16) {
        throw std::invalid_argument("Ciphertext too small");
    }

    try {
        // Parse ciphertext
        size_t offset = 0;

        // Extract PQ encrypted key length
        size_t pq_size = (static_cast<size_t>(ciphertext[offset]) << 24) |
                        (static_cast<size_t>(ciphertext[offset + 1]) << 16) |
                        (static_cast<size_t>(ciphertext[offset + 2]) << 8) |
                        static_cast<size_t>(ciphertext[offset + 3]);
        offset += 4;

        if (ciphertext.size() < offset + pq_size + 12 + 16) {
            throw std::invalid_argument("Invalid ciphertext format");
        }

        // Extract PQ encrypted key
        bytes pq_encrypted_key(ciphertext.begin() + offset, ciphertext.begin() + offset + pq_size);
        offset += pq_size;

        // Extract IV
        bytes iv(ciphertext.begin() + offset, ciphertext.begin() + offset + 12);
        offset += 12;

        // Extract authentication tag
        bytes tag(ciphertext.begin() + offset, ciphertext.begin() + offset + 16);
        offset += 16;

        // Extract classical ciphertext
        bytes classical_ciphertext(ciphertext.begin() + offset, ciphertext.end());

        // Decrypt symmetric key with post-quantum algorithm
        auto sym_key_result = kyber::decrypt(private_key.pq_key(), pq_encrypted_key);
        if (!sym_key_result.is_success()) {
            throw std::runtime_error("Failed to decrypt symmetric key: " + sym_key_result.error());
        }

        core::bytes sym_key = sym_key_result.value();

        // Decrypt message with classical algorithm
        core::bytes plaintext = aes_decrypt(private_key.classical_key(), classical_ciphertext, iv, tag);

        return plaintext;

    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to hybrid decrypt: " + std::string(e.what()));
    }
}

} // namespace qybersafe::hybrid