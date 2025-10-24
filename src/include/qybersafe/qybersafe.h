#ifndef QYBERSAFE_QYBERSAFE_H
#define QYBERSAFE_QYBERSAFE_H

#include <memory>
#include <vector>
#include <string>

namespace qybersafe {

// Core types
using bytes = std::vector<uint8_t>;

namespace core {
    class SecureRandom;
    class SecureMemory;
}

namespace kyber {
    class KeyPair;
    class PublicKey;
    class PrivateKey;

    enum class SecurityLevel {
        Kyber512 = 1,
        Kyber768 = 2,
        Kyber1024 = 3
    };

    KeyPair generate_keypair(SecurityLevel level = SecurityLevel::Kyber768);
    bytes encrypt(const PublicKey& public_key, const bytes& plaintext);
    bytes decrypt(const PrivateKey& private_key, const bytes& ciphertext);
    bytes encapsulate(const PublicKey& public_key, bytes& shared_secret);
    bytes decapsulate(const PrivateKey& private_key, const bytes& ciphertext);
}

namespace dilithium {
    class SigningKeyPair;
    class SigningPublicKey;
    class SigningPrivateKey;

    enum class SecurityLevel {
        Dilithium2 = 1,
        Dilithium3 = 2,
        Dilithium5 = 3
    };

    SigningKeyPair generate_keypair(SecurityLevel level = SecurityLevel::Dilithium3);
    bytes sign(const SigningPrivateKey& private_key, const bytes& message);
    bool verify(const SigningPublicKey& public_key, const bytes& message, const bytes& signature);
}

namespace sphincsplus {
    class SPHINCSKeyPair;
    class SPHINCSPublicKey;
    class SPHINCSPrivateKey;

    enum class SecurityLevel {
        SPHINCS128 = 1,
        SPHINCS192 = 2,
        SPHINCS256 = 3
    };

    SPHINCSKeyPair generate_keypair(SecurityLevel level = SecurityLevel::SPHINCS192);
    bytes sign(const SPHINCSPrivateKey& private_key, const bytes& message);
    bool verify(const SPHINCSPublicKey& public_key, const bytes& message, const bytes& signature);
}

namespace hybrid {
    // Hybrid encryption combining classical and PQC
    class HybridKeyPair;
    class HybridPublicKey;
    class HybridPrivateKey;

    HybridKeyPair generate_hybrid_keypair();
    bytes hybrid_encrypt(const HybridPublicKey& public_key, const bytes& plaintext);
    bytes hybrid_decrypt(const HybridPrivateKey& private_key, const bytes& ciphertext);
}

} // namespace qybersafe

#endif // QYBERSAFE_QYBERSAFE_H