#ifndef QYBERSAFE_QYBERSAFE_H
#define QYBERSAFE_QYBERSAFE_H

#include <memory>
#include <vector>
#include <string>

/**
 * @file qybersafe.h
 * @brief Main header file for the QyberSafe post-quantum cryptography library
 *
 * This header provides the primary public API for QyberSafe, including
 * interfaces for Kyber (KEM), Dilithium (signatures), SPHINCS+ (hash-based signatures),
 * and hybrid encryption schemes.
 *
 * @author QyberSafe Team
 * @version 0.1.0
 * @since 0.1.0
 */

/**
 * @namespace qybersafe
 * @brief Main namespace for the QyberSafe post-quantum cryptography library
 *
 * QyberSafe provides implementations of NIST-standardized post-quantum cryptographic
 * algorithms with a focus on security, performance, and ease of use.
 */
namespace qybersafe {

/**
 * @brief Type alias for byte sequences
 *
 * Represents binary data as a vector of 8-bit unsigned integers.
 * This is the standard type used throughout the library for
 * keys, ciphertexts, signatures, and other binary data.
 */
using bytes = std::vector<uint8_t>;

/**
 * @namespace qybersafe::core
 * @brief Core utilities and fundamental cryptographic types
 *
 * Provides secure memory management, random number generation,
 * and other foundational cryptographic utilities.
 */
namespace core {
    class SecureRandom;  ///< Secure random number generator
    class SecureMemory;  ///< Secure memory management with automatic zeroing
}

/**
 * @namespace qybersafe::kyber
 * @brief Kyber Key Encapsulation Mechanism (KEM) implementation
 *
 * Kyber is a lattice-based key encapsulation mechanism selected for standardization
 * by NIST in the PQC competition. It provides IND-CCA2 secure key encapsulation
 * and is suitable for establishing shared secrets in a post-quantum world.
 */
namespace kyber {
    class KeyPair;        ///< Kyber key pair containing public and private keys
    class PublicKey;      ///< Kyber public key for encapsulation
    class PrivateKey;     ///< Kyber private key for decapsulation

    /**
     * @enum SecurityLevel
     * @brief Security levels for Kyber KEM
     *
     * Different security levels provide varying levels of quantum resistance:
     * - Kyber512: ~128-bit quantum security (comparable to AES-128)
     * - Kyber768: ~192-bit quantum security (comparable to AES-192)
     * - Kyber1024: ~256-bit quantum security (comparable to AES-256)
     */
    enum class SecurityLevel {
        Kyber512 = 1,   ///< 128-bit quantum security level
        Kyber768 = 2,   ///< 192-bit quantum security level (recommended)
        Kyber1024 = 3   ///< 256-bit quantum security level
    };

    /**
     * @brief Generate a Kyber key pair
     * @param level Security level (default: Kyber768)
     * @return KeyPair containing public and private keys
     */
    KeyPair generate_keypair(SecurityLevel level = SecurityLevel::Kyber768);

    /**
     * @brief Encrypt plaintext using Kyber public key
     * @param public_key The Kyber public key
     * @param plaintext The message to encrypt
     * @return Ciphertext containing the encrypted message
     */
    bytes encrypt(const PublicKey& public_key, const bytes& plaintext);

    /**
     * @brief Decrypt ciphertext using Kyber private key
     * @param private_key The Kyber private key
     * @param ciphertext The encrypted message
     * @return Decrypted plaintext
     */
    bytes decrypt(const PrivateKey& private_key, const bytes& ciphertext);

    /**
     * @brief Encapsulate a shared secret using Kyber public key
     * @param public_key The Kyber public key
     * @param shared_secret Output parameter for the generated shared secret
     * @return Ciphertext containing the encapsulated shared secret
     */
    bytes encapsulate(const PublicKey& public_key, bytes& shared_secret);

    /**
     * @brief Decapsulate shared secret using Kyber private key
     * @param private_key The Kyber private key
     * @param ciphertext The encapsulated shared secret
     * @return Decapsulated shared secret
     */
    bytes decapsulate(const PrivateKey& private_key, const bytes& ciphertext);
}

/**
 * @namespace qybersafe::dilithium
 * @brief Dilithium digital signature implementation
 *
 * Dilithium is a lattice-based digital signature algorithm selected for standardization
 * by NIST in the PQC competition. It provides high-performance, secure digital signatures
 * with quantum resistance.
 */
namespace dilithium {
    class SigningKeyPair;    ///< Dilithium signing key pair
    class SigningPublicKey;  ///< Dilithium public verification key
    class SigningPrivateKey; ///< Dilithium private signing key

    /**
     * @enum SecurityLevel
     * @brief Security levels for Dilithium signatures
     *
     * Different security levels provide varying levels of quantum resistance:
     * - Dilithium2: ~128-bit quantum security (comparable to ECDSA-P256)
     * - Dilithium3: ~192-bit quantum security (recommended for most applications)
     * - Dilithium5: ~256-bit quantum security (high-security applications)
     */
    enum class SecurityLevel {
        Dilithium2 = 1,  ///< 128-bit quantum security level
        Dilithium3 = 2,  ///< 192-bit quantum security level (recommended)
        Dilithium5 = 3   ///< 256-bit quantum security level
    };

    /**
     * @brief Generate a Dilithium signing key pair
     * @param level Security level (default: Dilithium3)
     * @return SigningKeyPair containing public and private keys
     */
    SigningKeyPair generate_keypair(SecurityLevel level = SecurityLevel::Dilithium3);

    /**
     * @brief Sign a message using Dilithium private key
     * @param private_key The Dilithium private signing key
     * @param message The message to sign
     * @return Digital signature
     */
    bytes sign(const SigningPrivateKey& private_key, const bytes& message);

    /**
     * @brief Verify a signature using Dilithium public key
     * @param public_key The Dilithium public verification key
     * @param message The original message
     * @param signature The signature to verify
     * @return true if signature is valid, false otherwise
     */
    bool verify(const SigningPublicKey& public_key, const bytes& message, const bytes& signature);
}

/**
 * @namespace qybersafe::sphincsplus
 * @brief SPHINCS+ hash-based signature implementation
 *
 * SPHINCS+ is a stateless hash-based signature scheme that provides security based
 * on the security of cryptographic hash functions. It offers conservative security
 * guarantees and is suitable for long-term security applications.
 */
namespace sphincsplus {
    class SPHINCSKeyPair;    ///< SPHINCS+ signing key pair
    class SPHINCSPublicKey;  ///< SPHINCS+ public verification key
    class SPHINCSPrivateKey; ///< SPHINCS+ private signing key

    /**
     * @enum SecurityLevel
     * @brief Security levels for SPHINCS+ signatures
     *
     * Different security levels provide varying levels of quantum resistance:
     * - SPHINCS128: ~128-bit quantum security
     * - SPHINCS192: ~192-bit quantum security
     * - SPHINCS256: ~256-bit quantum security
     */
    enum class SecurityLevel {
        SPHINCS128 = 1,  ///< 128-bit quantum security level
        SPHINCS192 = 2,  ///< 192-bit quantum security level (recommended)
        SPHINCS256 = 3   ///< 256-bit quantum security level
    };

    /**
     * @brief Generate a SPHINCS+ signing key pair
     * @param level Security level (default: SPHINCS192)
     * @return SPHINCSKeyPair containing public and private keys
     */
    SPHINCSKeyPair generate_keypair(SecurityLevel level = SecurityLevel::SPHINCS192);

    /**
     * @brief Sign a message using SPHINCS+ private key
     * @param private_key The SPHINCS+ private signing key
     * @param message The message to sign
     * @return Digital signature
     */
    bytes sign(const SPHINCSPrivateKey& private_key, const bytes& message);

    /**
     * @brief Verify a signature using SPHINCS+ public key
     * @param public_key The SPHINCS+ public verification key
     * @param message The original message
     * @param signature The signature to verify
     * @return true if signature is valid, false otherwise
     */
    bool verify(const SPHINCSPublicKey& public_key, const bytes& message, const bytes& signature);
}

/**
 * @namespace qybersafe::hybrid
 * @brief Hybrid encryption combining classical and post-quantum cryptography
 *
 * Hybrid encryption combines traditional algorithms (like AES-256-GCM) with
 * post-quantum algorithms to provide defense in depth. This ensures security
 * even if one of the algorithms is compromised in the future.
 */
namespace hybrid {
    class HybridKeyPair;    ///< Hybrid key pair combining classical and PQC keys
    class HybridPublicKey;  ///< Hybrid public key for encryption
    class HybridPrivateKey; ///< Hybrid private key for decryption

    /**
     * @brief Generate a hybrid key pair
     *
     * Creates a key pair that combines classical cryptography (AES-256-GCM)
     * with post-quantum cryptography (Kyber) for enhanced security.
     *
     * @return HybridKeyPair containing public and private keys
     */
    HybridKeyPair generate_hybrid_keypair();

    /**
     * @brief Encrypt plaintext using hybrid public key
     *
     * Encrypts the plaintext using both classical and post-quantum algorithms.
     * The symmetric key is encrypted with both algorithms and the data is
     * encrypted with AES-256-GCM.
     *
     * @param public_key The hybrid public key
     * @param plaintext The message to encrypt
     * @return Hybrid ciphertext containing all necessary components
     */
    bytes hybrid_encrypt(const HybridPublicKey& public_key, const bytes& plaintext);

    /**
     * @brief Decrypt hybrid ciphertext using hybrid private key
     *
     * Decrypts the hybrid ciphertext by attempting both classical and
     * post-quantum decryption. At least one method must succeed for
     * the overall decryption to succeed.
     *
     * @param private_key The hybrid private key
     * @param ciphertext The hybrid ciphertext to decrypt
     * @return Decrypted plaintext
     */
    bytes hybrid_decrypt(const HybridPrivateKey& private_key, const bytes& ciphertext);
}

} // namespace qybersafe

#endif // QYBERSAFE_QYBERSAFE_H