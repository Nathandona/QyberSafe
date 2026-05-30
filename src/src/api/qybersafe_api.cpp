#include "qybersafe/qybersafe.h"

#include <cstdint>
#include <stdexcept>
#include <utility>

#include "qybersafe/dilithium/dilithium_sig.h"
#include "qybersafe/sphincsplus/sphincsplus_sig.h"

/**
 * @file qybersafe_api.cpp
 * @brief Implementation of the envelope-first public API.
 *
 * A thin, exception-based facade over the per-algorithm modules. Encryption
 * delegates to the hybrid envelope; signatures dispatch to ML-DSA or SLH-DSA by
 * the key's algorithm tag.
 */

namespace qybersafe {

namespace {

enum class Family { Dilithium, Sphincs };

struct AlgInfo {
    Family family;
    core::SecurityLevel level;
    uint16_t id;  // wire-format algorithm identifier
};

AlgInfo info_of(SignAlg alg) {
    switch (alg) {
        case SignAlg::ML_DSA_44:
            return {Family::Dilithium, core::SecurityLevel::DILITHIUM_2, 0x0101};
        case SignAlg::ML_DSA_65:
            return {Family::Dilithium, core::SecurityLevel::DILITHIUM_3, 0x0102};
        case SignAlg::ML_DSA_87:
            return {Family::Dilithium, core::SecurityLevel::DILITHIUM_5, 0x0103};
        case SignAlg::SLH_DSA_128s:
            return {Family::Sphincs, core::SecurityLevel::SPHINCS_128, 0x0201};
        case SignAlg::SLH_DSA_192s:
            return {Family::Sphincs, core::SecurityLevel::SPHINCS_192, 0x0202};
        case SignAlg::SLH_DSA_256s:
            return {Family::Sphincs, core::SecurityLevel::SPHINCS_256, 0x0203};
    }
    throw CryptoError("Unknown signature algorithm");
}

SignAlg alg_from_id(uint16_t id) {
    switch (id) {
        case 0x0101: return SignAlg::ML_DSA_44;
        case 0x0102: return SignAlg::ML_DSA_65;
        case 0x0103: return SignAlg::ML_DSA_87;
        case 0x0201: return SignAlg::SLH_DSA_128s;
        case 0x0202: return SignAlg::SLH_DSA_192s;
        case 0x0203: return SignAlg::SLH_DSA_256s;
        default: throw CryptoError("Unknown signature algorithm id");
    }
}

// Minimal self-describing serialization for signing keys: a 4-byte header
// (version, artifact type, algorithm id) then a single uint32-length field.
constexpr uint8_t kVersion = 0x01;
constexpr uint8_t kTypePublicKey = 1;
constexpr uint8_t kTypePrivateKey = 2;

bytes serialize_signing_key(uint8_t type, uint16_t alg_id, const bytes& key) {
    bytes out;
    out.reserve(4 + 4 + key.size());
    out.push_back(kVersion);
    out.push_back(type);
    out.push_back(static_cast<uint8_t>(alg_id >> 8));
    out.push_back(static_cast<uint8_t>(alg_id & 0xFF));
    const uint32_t n = static_cast<uint32_t>(key.size());
    out.push_back(static_cast<uint8_t>(n >> 24));
    out.push_back(static_cast<uint8_t>(n >> 16));
    out.push_back(static_cast<uint8_t>(n >> 8));
    out.push_back(static_cast<uint8_t>(n));
    out.insert(out.end(), key.begin(), key.end());
    return out;
}

// Returns (algorithm, key bytes). Throws CryptoError on a malformed input.
std::pair<SignAlg, bytes> parse_signing_key(uint8_t expected_type,
                                            const bytes& data) {
    if (data.size() < 8) throw CryptoError("truncated signing key");
    if (data[0] != kVersion) throw CryptoError("unsupported key version");
    if (data[1] != expected_type) throw CryptoError("unexpected key type");
    const uint16_t alg_id = static_cast<uint16_t>((data[2] << 8) | data[3]);
    const SignAlg alg = alg_from_id(alg_id);
    const uint32_t n = (static_cast<uint32_t>(data[4]) << 24) |
                       (static_cast<uint32_t>(data[5]) << 16) |
                       (static_cast<uint32_t>(data[6]) << 8) |
                       static_cast<uint32_t>(data[7]);
    if (data.size() - 8 != n) throw CryptoError("signing key length mismatch");
    return {alg, bytes(data.begin() + 8, data.end())};
}

}  // namespace

// ===========================================================================
// Encryption
// ===========================================================================

EncryptionPublicKey::EncryptionPublicKey(hybrid::HybridPublicKey key)
    : key_(std::move(key)) {}

const hybrid::HybridPublicKey& EncryptionPublicKey::hybrid_key() const {
    return key_;
}

EncryptionPrivateKey::EncryptionPrivateKey(hybrid::HybridPrivateKey key)
    : key_(std::move(key)) {}

const hybrid::HybridPrivateKey& EncryptionPrivateKey::hybrid_key() const {
    return key_;
}

EncryptionPublicKey EncryptionPrivateKey::public_key() const {
    return EncryptionPublicKey(key_.get_public_key());
}

EncryptionKeyPair generate_encryption_keypair() {
    hybrid::HybridKeyPair kp = hybrid::generate_hybrid_keypair();
    return EncryptionKeyPair{EncryptionPublicKey(kp.public_key()),
                             EncryptionPrivateKey(kp.private_key())};
}

bytes seal(const EncryptionPublicKey& to, const bytes& plaintext,
           const bytes& aad) {
    try {
        return hybrid::hybrid_encrypt(to.hybrid_key(), plaintext, aad);
    } catch (const std::exception& e) {
        throw CryptoError(e.what());
    }
}

bytes open(const EncryptionPrivateKey& key, const bytes& envelope,
           const bytes& aad) {
    try {
        return hybrid::hybrid_decrypt(key.hybrid_key(), envelope, aad);
    } catch (const std::exception& e) {
        throw CryptoError(e.what());
    }
}

bytes to_bytes(const EncryptionPublicKey& key) {
    return key.hybrid_key().data();
}

bytes to_bytes(const EncryptionPrivateKey& key) {
    return key.hybrid_key().data();
}

EncryptionPublicKey encryption_public_key_from_bytes(const bytes& data) {
    try {
        return EncryptionPublicKey(hybrid::HybridPublicKey(data));
    } catch (const std::exception& e) {
        throw CryptoError(e.what());
    }
}

EncryptionPrivateKey encryption_private_key_from_bytes(const bytes& data) {
    try {
        return EncryptionPrivateKey(hybrid::HybridPrivateKey(data));
    } catch (const std::exception& e) {
        throw CryptoError(e.what());
    }
}

// ===========================================================================
// Signatures
// ===========================================================================

SigningPublicKey::SigningPublicKey(SignAlg algorithm, bytes key)
    : algorithm_(algorithm), key_(std::move(key)) {}

SignAlg SigningPublicKey::algorithm() const { return algorithm_; }

const bytes& SigningPublicKey::key_bytes() const { return key_; }

SigningPrivateKey::SigningPrivateKey(SignAlg algorithm, bytes key)
    : algorithm_(algorithm), key_(std::move(key)) {}

SignAlg SigningPrivateKey::algorithm() const { return algorithm_; }

const bytes& SigningPrivateKey::key_bytes() const { return key_; }

SigningKeyPair generate_signing_keypair(SignAlg algorithm) {
    const AlgInfo info = info_of(algorithm);
    try {
        if (info.family == Family::Dilithium) {
            dilithium::SigningKeyPair kp = dilithium::generate_keypair(info.level);
            return SigningKeyPair{
                SigningPublicKey(algorithm, kp.verifying_key().data()),
                SigningPrivateKey(algorithm, kp.signing_key().data())};
        }
        sphincsplus::SPHINCSKeyPair kp = sphincsplus::generate_keypair(info.level);
        return SigningKeyPair{
            SigningPublicKey(algorithm, kp.public_key().data()),
            SigningPrivateKey(algorithm, kp.private_key().data())};
    } catch (const CryptoError&) {
        throw;
    } catch (const std::exception& e) {
        throw CryptoError(e.what());
    }
}

bytes sign(const SigningPrivateKey& key, const bytes& message) {
    const AlgInfo info = info_of(key.algorithm());
    try {
        if (info.family == Family::Dilithium) {
            dilithium::SigningKey sk(key.key_bytes());
            auto result = dilithium::sign(sk, message);
            if (!result.is_success()) throw CryptoError(result.error());
            return result.value();
        }
        sphincsplus::SPHINCSPrivateKey sk(key.key_bytes());
        return sphincsplus::sign(sk, message);
    } catch (const CryptoError&) {
        throw;
    } catch (const std::exception& e) {
        throw CryptoError(e.what());
    }
}

bool verify(const SigningPublicKey& key, const bytes& message,
            const bytes& signature) {
    const AlgInfo info = info_of(key.algorithm());
    if (info.family == Family::Dilithium) {
        dilithium::VerifyingKey vk(key.key_bytes());
        return dilithium::verify(vk, message, signature);
    }
    sphincsplus::SPHINCSPublicKey vk(key.key_bytes());
    return sphincsplus::verify(vk, message, signature);
}

bytes to_bytes(const SigningPublicKey& key) {
    return serialize_signing_key(kTypePublicKey, info_of(key.algorithm()).id,
                                 key.key_bytes());
}

bytes to_bytes(const SigningPrivateKey& key) {
    return serialize_signing_key(kTypePrivateKey, info_of(key.algorithm()).id,
                                 key.key_bytes());
}

SigningPublicKey signing_public_key_from_bytes(const bytes& data) {
    auto [alg, key] = parse_signing_key(kTypePublicKey, data);
    return SigningPublicKey(alg, std::move(key));
}

SigningPrivateKey signing_private_key_from_bytes(const bytes& data) {
    auto [alg, key] = parse_signing_key(kTypePrivateKey, data);
    return SigningPrivateKey(alg, std::move(key));
}

}  // namespace qybersafe
