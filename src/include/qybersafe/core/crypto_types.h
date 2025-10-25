#ifndef QYBERSAFE_CORE_CRYPTO_TYPES_H
#define QYBERSAFE_CORE_CRYPTO_TYPES_H

/**
 * @file crypto_types.h
 * @brief Core cryptographic types and utilities for QyberSafe
 *
 * This header defines fundamental types, constants, and utilities used throughout
 * the QyberSafe library, including secure memory management, unified security levels,
 * and algorithm family definitions.
 *
 * @author QyberSafe Team
 * @version 0.1.0
 * @since 0.1.0
 */

#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <stdexcept>
#include <type_traits>
#include <openssl/evp.h>
#include "qybersafe/core/exceptions.h"

namespace qybersafe::core {

/**
 * @brief Secure memory allocation function
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or nullptr on failure
 * @warning Memory must be freed using secure_deallocate()
 */
void* secure_allocate(size_t size);

/**
 * @brief Secure memory deallocation function
 * @param ptr Pointer to memory allocated with secure_allocate()
 * @param size Original size of the allocation
 * @note This function securely zeros the memory before freeing
 */
void secure_deallocate(void* ptr, size_t size);

/**
 * @brief Securely zero memory
 * @param ptr Pointer to memory to zero
 * @param size Number of bytes to zero
 * @note This function is designed to prevent compiler optimizations from removing the zeroing
 */
void secure_zero_memory(void* ptr, size_t size);

/**
 * @brief Type alias for a single byte
 */
using byte = uint8_t;

/**
 * @brief Type alias for a sequence of bytes
 *
 * This is the primary type used throughout the library for representing
 * binary data such as keys, ciphertexts, signatures, and messages.
 */
using bytes = std::vector<byte>;

// Kyber key and ciphertext sizes (in bytes)
constexpr size_t KYBER_PUBLIC_KEY_512 = 800;    ///< Kyber-512 public key size
constexpr size_t KYBER_PRIVATE_KEY_512 = 1632;  ///< Kyber-512 private key size
constexpr size_t KYBER_CIPHERTEXT_512 = 768;    ///< Kyber-512 ciphertext size

constexpr size_t KYBER_PUBLIC_KEY_768 = 1184;   ///< Kyber-768 public key size
constexpr size_t KYBER_PRIVATE_KEY_768 = 2400;  ///< Kyber-768 private key size
constexpr size_t KYBER_CIPHERTEXT_768 = 1088;   ///< Kyber-768 ciphertext size

constexpr size_t KYBER_PUBLIC_KEY_1024 = 1568;  ///< Kyber-1024 public key size
constexpr size_t KYBER_PRIVATE_KEY_1024 = 3168; ///< Kyber-1024 private key size
constexpr size_t KYBER_CIPHERTEXT_1024 = 1568;  ///< Kyber-1024 ciphertext size

// Dilithium key and signature sizes (in bytes)
constexpr size_t DILITHIUM_PUBLIC_KEY_2 = 1312;  ///< Dilithium2 public key size
constexpr size_t DILITHIUM_PRIVATE_KEY_2 = 2528; ///< Dilithium2 private key size
constexpr size_t DILITHIUM_SIGNATURE_2 = 2420;   ///< Dilithium2 signature size

constexpr size_t DILITHIUM_PUBLIC_KEY_3 = 1952;  ///< Dilithium3 public key size
constexpr size_t DILITHIUM_PRIVATE_KEY_3 = 4000; ///< Dilithium3 private key size
constexpr size_t DILITHIUM_SIGNATURE_3 = 3293;   ///< Dilithium3 signature size

constexpr size_t DILITHIUM_PUBLIC_KEY_5 = 2592;  ///< Dilithium5 public key size
constexpr size_t DILITHIUM_PRIVATE_KEY_5 = 4864; ///< Dilithium5 private key size
constexpr size_t DILITHIUM_SIGNATURE_5 = 4595;   ///< Dilithium5 signature size

/**
 * @enum SecurityLevel
 * @brief Unified security level enumeration for all post-quantum algorithms
 *
 * This enumeration provides a consistent interface for specifying security levels
 * across all supported algorithms. Each algorithm family uses a different
 * numeric range to prevent accidental mixing of incompatible security levels.
 *
 * Security levels correspond to approximate quantum security bits:
 * - 128-bit quantum security: Suitable for most applications
 * - 192-bit quantum security: Recommended for high-value assets
 * - 256-bit quantum security: Maximum security for long-term protection
 */
enum class SecurityLevel {
    // Kyber security levels (100-199 range)
    KYBER_512 = 101,     ///< Kyber-512: ~128-bit quantum security
    KYBER_768 = 102,     ///< Kyber-768: ~192-bit quantum security (recommended)
    KYBER_1024 = 103,    ///< Kyber-1024: ~256-bit quantum security

    // Dilithium security levels (200-299 range)
    DILITHIUM_2 = 201,   ///< Dilithium2: ~128-bit quantum security
    DILITHIUM_3 = 202,   ///< Dilithium3: ~192-bit quantum security (recommended)
    DILITHIUM_5 = 203,   ///< Dilithium5: ~256-bit quantum security

    // SPHINCS+ security levels (300-399 range)
    SPHINCS_128 = 301,   ///< SPHINCS-128: ~128-bit quantum security
    SPHINCS_192 = 302,   ///< SPHINCS-192: ~192-bit quantum security
    SPHINCS_256 = 303,   ///< SPHINCS-256: ~256-bit quantum security

    // Legacy compatibility (deprecated) - use specific algorithm levels instead
    LOW = 1,      ///< Legacy: ~128-bit security (deprecated)
    MEDIUM = 2,   ///< Legacy: ~192-bit security (deprecated)
    HIGH = 3      ///< Legacy: ~256-bit security (deprecated)
};

/**
 * @enum AlgorithmFamily
 * @brief Enumeration of supported cryptographic algorithm families
 */
enum class AlgorithmFamily {
    KYBER,        ///< Kyber Key Encapsulation Mechanism family
    DILITHIUM,    ///< Dilithium Digital Signature family
    SPHINCS_PLUS, ///< SPHINCS+ Hash-based Signature family
    HYBRID        ///< Hybrid algorithms combining classical and PQC
};

/**
 * @enum Algorithm
 * @brief Complete algorithm identifiers for specific algorithm variants
 *
 * These identifiers specify both the algorithm family and security level
 * for precise algorithm selection.
 */
enum class Algorithm {
    // Kyber algorithms
    KYBER_512,    ///< Kyber-512 KEM
    KYBER_768,    ///< Kyber-768 KEM (recommended)
    KYBER_1024,   ///< Kyber-1024 KEM

    // Dilithium algorithms
    DILITHIUM_2,  ///< Dilithium2 signatures
    DILITHIUM_3,  ///< Dilithium3 signatures (recommended)
    DILITHIUM_5,  ///< Dilithium5 signatures

    // SPHINCS+ algorithms
    SPHINCS128,   ///< SPHINCS-128 signatures
    SPHINCS192,   ///< SPHINCS-192 signatures (recommended)
    SPHINCS256,   ///< SPHINCS-256 signatures

    // Hybrid algorithms
    HYBRID_KYBER_RSA,  ///< Hybrid Kyber + RSA encryption
    HYBRID_KYBER_ECDH  ///< Hybrid Kyber + ECDH encryption
};

/**
 * @namespace security_level_utils
 * @brief Utility functions for security level management and validation
 *
 * This namespace provides compile-time utilities for working with SecurityLevel
 * enumerations, including family detection and validation functions.
 */
namespace security_level_utils {
    /**
     * @brief Get the algorithm family for a security level
     * @param level Security level to check
     * @return AlgorithmFamily corresponding to the security level
     * @note Returns HYBRID as default for unknown levels
     */
    constexpr AlgorithmFamily get_family(SecurityLevel level) noexcept {
        if (level >= SecurityLevel::KYBER_512 && level <= SecurityLevel::KYBER_1024) {
            return AlgorithmFamily::KYBER;
        } else if (level >= SecurityLevel::DILITHIUM_2 && level <= SecurityLevel::DILITHIUM_5) {
            return AlgorithmFamily::DILITHIUM;
        } else if (level >= SecurityLevel::SPHINCS_128 && level <= SecurityLevel::SPHINCS_256) {
            return AlgorithmFamily::SPHINCS_PLUS;
        }
        return AlgorithmFamily::HYBRID; // Default fallback
    }

    /**
     * @brief Check if a security level belongs to the Kyber family
     * @param level Security level to check
     * @return true if level is a valid Kyber security level
     */
    constexpr bool is_kyber_level(SecurityLevel level) noexcept {
        return level == SecurityLevel::KYBER_512 ||
               level == SecurityLevel::KYBER_768 ||
               level == SecurityLevel::KYBER_1024;
    }

    /**
     * @brief Check if a security level belongs to the Dilithium family
     * @param level Security level to check
     * @return true if level is a valid Dilithium security level
     */
    constexpr bool is_dilithium_level(SecurityLevel level) noexcept {
        return level == SecurityLevel::DILITHIUM_2 ||
               level == SecurityLevel::DILITHIUM_3 ||
               level == SecurityLevel::DILITHIUM_5;
    }

    /**
     * @brief Check if a security level belongs to the SPHINCS+ family
     * @param level Security level to check
     * @return true if level is a valid SPHINCS+ security level
     */
    constexpr bool is_sphincs_level(SecurityLevel level) noexcept {
        return level == SecurityLevel::SPHINCS_128 ||
               level == SecurityLevel::SPHINCS_192 ||
               level == SecurityLevel::SPHINCS_256;
    }

    /**
     * @brief Convert legacy numeric security levels to modern SecurityLevel enum
     * @param level Legacy security level (1=LOW, 2=MEDIUM, 3=HIGH)
     * @return Corresponding SecurityLevel enum value
     * @deprecated Use specific algorithm security levels instead
     */
    constexpr SecurityLevel from_legacy(int level) noexcept {
        switch (level) {
            case 1: return SecurityLevel::LOW;
            case 2: return SecurityLevel::MEDIUM;
            case 3: return SecurityLevel::HIGH;
            default: return SecurityLevel::MEDIUM;
        }
    }
}

/**
 * @template Result
 * @brief Result type for error handling with modern C++ enhancements
 *
 * This template class provides a type-safe way to handle operations that can fail,
 * similar to Rust's Result or C++23's std::expected. It encapsulates either a
 * successful value or an error message, preventing undefined behavior from
 * unchecked error conditions.
 *
 * @tparam T Type of the success value
 */
template<typename T>
class Result {
public:
    /**
     * @brief Create a successful result with a value
     * @param value The success value to store
     * @return Result containing the value
     */
    [[nodiscard]] static Result success(T value) noexcept {
        return Result(std::move(value), true);
    }

    /**
     * @brief Create an error result with a string message
     * @param error_msg The error message
     * @return Result containing the error
     */
    [[nodiscard]] static Result error(const std::string& error_msg) noexcept {
        return Result(T{}, false, error_msg);
    }

    /**
     * @brief Create an error result from an ErrorCode
     * @param ec The error code
     * @return Result containing the error message from the error code
     */
    [[nodiscard]] static Result error(ErrorCode ec) noexcept {
        return Result(T{}, false, make_error_code(ec).message());
    }

    /**
     * @brief Create an error result with context and message
     * @param context The context where the error occurred
     * @param error_msg The specific error message
     * @return Result containing the formatted error message
     */
    [[nodiscard]] static Result error(const std::string& context, const std::string& error_msg) noexcept {
        return Result(T{}, false, context + ": " + error_msg);
    }

    /**
     * @brief Check if the result contains a success value
     * @return true if successful, false if error
     */
    [[nodiscard]] constexpr bool is_success() const noexcept { return success_; }

    /**
     * @brief Check if the result contains an error
     * @return true if error, false if successful
     */
    [[nodiscard]] constexpr bool is_error() const noexcept { return !success_; }

    /**
     * @brief Get the success value
     * @return Reference to the stored value
     * @throws QyberSafeException if the result contains an error
     */
    [[nodiscard]] const T& value() const {
        if (!success_) {
            throw QyberSafeException("Result error", error_msg_);
        }
        return value_;
    }

    /**
     * @brief Get the success value or a default value
     * @param default_value Default value to return if result is error
     * @return Reference to the success value or default_value
     */
    [[nodiscard]] const T& value_or(const T& default_value) const noexcept {
        return success_ ? value_ : default_value;
    }

    /**
     * @brief Get the error message
     * @return Reference to the error message (empty if successful)
     */
    [[nodiscard]] const std::string& error() const noexcept { return error_msg_; }

    /**
     * @brief Boolean conversion operator for checking success
     * @return true if successful, false if error
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return success_; }

    /**
     * @brief Apply a function to the success value (functional programming style)
     * @tparam F Function type to apply
     * @param func Function to apply to the success value
     * @return Result with function result or error if this result is error
     */
    template<typename F>
    [[nodiscard]] auto map(F&& func) -> Result<decltype(func(std::declval<T>()))> {
        using ReturnType = decltype(func(std::declval<T>()));
        if (!success_) {
            return Result<ReturnType>::error(error_msg_);
        }
        try {
            return Result<ReturnType>::success(func(value_));
        } catch (const std::exception& e) {
            return Result<ReturnType>::error("map", e.what());
        }
    }

    /**
     * @brief Apply a function that returns a Result (monadic binding)
     * @tparam F Function type to apply
     * @param func Function that takes the success value and returns a Result
     * @return Result from the function or error if this result is error
     */
    template<typename F>
    [[nodiscard]] auto flat_map(F&& func) -> decltype(func(std::declval<T>())) {
        if (!success_) {
            using ReturnType = decltype(func(std::declval<T>()));
            return ReturnType::error(error_msg_);
        }
        try {
            return func(value_);
        } catch (const std::exception& e) {
            using ReturnType = decltype(func(std::declval<T>()));
            return ReturnType::error("flat_map", e.what());
        }
    }

private:
    /**
     * @brief Private constructor for Result
     * @param val The value to store
     * @param succ Whether the result is successful
     * @param err The error message (if any)
     */
    Result(T val, bool succ, const std::string& err = "")
        : value_(std::move(val)), success_(succ), error_msg_(err) {}

    T value_;              ///< Stored success value
    bool success_;         ///< Success flag
    std::string error_msg_; ///< Error message
};

// Specialization for void with modern C++ enhancements
template<>
class Result<void> {
public:
    [[nodiscard]] static constexpr Result success() noexcept {
        return Result(true);
    }

    [[nodiscard]] static constexpr Result error(const std::string& error_msg) noexcept {
        return Result(false, error_msg);
    }

    [[nodiscard]] static constexpr Result error(ErrorCode ec) noexcept {
        return Result(false, make_error_code(ec).message());
    }

    [[nodiscard]] static constexpr Result error(const std::string& context, const std::string& error_msg) noexcept {
        return Result(false, context + ": " + error_msg);
    }

    [[nodiscard]] constexpr bool is_success() const noexcept { return success_; }
    [[nodiscard]] constexpr bool is_error() const noexcept { return !success_; }
    [[nodiscard]] const std::string& error() const noexcept { return error_msg_; }

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return success_; }

    // For void, map and flat_map don't make sense, but we provide a way to chain operations
    template<typename F>
    [[nodiscard]] auto and_then(F&& func) -> decltype(func()) {
        using ReturnType = decltype(func());
        if (!success_) {
            if constexpr (std::is_same_v<ReturnType, void>) {
                return Result<void>::error(error_msg_);
            } else {
                return ReturnType::error(error_msg_);
            }
        }
        try {
            return func();
        } catch (const std::exception& e) {
            if constexpr (std::is_same_v<ReturnType, void>) {
                return Result<void>::error("and_then", e.what());
            } else {
                return ReturnType::error("and_then", e.what());
            }
        }
    }

private:
    Result(bool succ, const std::string& err = "")
        : success_(succ), error_msg_(err) {}

    bool success_;
    std::string error_msg_;
};

// constexpr key size utility functions
namespace key_sizes {
    constexpr size_t kyber_public_key_size(SecurityLevel level) noexcept {
        switch (level) {
            case SecurityLevel::KYBER_512: return KYBER_PUBLIC_KEY_512;
            case SecurityLevel::KYBER_768: return KYBER_PUBLIC_KEY_768;
            case SecurityLevel::KYBER_1024: return KYBER_PUBLIC_KEY_1024;
            default: return 0;
        }
    }

    constexpr size_t kyber_private_key_size(SecurityLevel level) noexcept {
        switch (level) {
            case SecurityLevel::KYBER_512: return KYBER_PRIVATE_KEY_512;
            case SecurityLevel::KYBER_768: return KYBER_PRIVATE_KEY_768;
            case SecurityLevel::KYBER_1024: return KYBER_PRIVATE_KEY_1024;
            default: return 0;
        }
    }

    constexpr size_t kyber_ciphertext_size(SecurityLevel level) noexcept {
        switch (level) {
            case SecurityLevel::KYBER_512: return KYBER_CIPHERTEXT_512;
            case SecurityLevel::KYBER_768: return KYBER_CIPHERTEXT_768;
            case SecurityLevel::KYBER_1024: return KYBER_CIPHERTEXT_1024;
            default: return 0;
        }
    }

    constexpr size_t dilithium_public_key_size(SecurityLevel level) noexcept {
        switch (level) {
            case SecurityLevel::DILITHIUM_2: return DILITHIUM_PUBLIC_KEY_2;
            case SecurityLevel::DILITHIUM_3: return DILITHIUM_PUBLIC_KEY_3;
            case SecurityLevel::DILITHIUM_5: return DILITHIUM_PUBLIC_KEY_5;
            default: return 0;
        }
    }

    constexpr size_t dilithium_private_key_size(SecurityLevel level) noexcept {
        switch (level) {
            case SecurityLevel::DILITHIUM_2: return DILITHIUM_PRIVATE_KEY_2;
            case SecurityLevel::DILITHIUM_3: return DILITHIUM_PRIVATE_KEY_3;
            case SecurityLevel::DILITHIUM_5: return DILITHIUM_PRIVATE_KEY_5;
            default: return 0;
        }
    }

    constexpr size_t dilithium_signature_size(SecurityLevel level) noexcept {
        switch (level) {
            case SecurityLevel::DILITHIUM_2: return DILITHIUM_SIGNATURE_2;
            case SecurityLevel::DILITHIUM_3: return DILITHIUM_SIGNATURE_3;
            case SecurityLevel::DILITHIUM_5: return DILITHIUM_SIGNATURE_5;
            default: return 0;
        }
    }
}

// Secure memory container for sensitive data
class SecureBytes {
public:
    SecureBytes();
    explicit SecureBytes(size_t size);
    explicit SecureBytes(const bytes& data);
    explicit SecureBytes(bytes&& data);
    ~SecureBytes();

    SecureBytes(const SecureBytes& other);
    SecureBytes(SecureBytes&& other) noexcept;

    SecureBytes& operator=(const SecureBytes& other);
    SecureBytes& operator=(SecureBytes&& other) noexcept;
    SecureBytes& operator=(const bytes& other);
    SecureBytes& operator=(bytes&& other);

    void resize(size_t new_size);
    void clear();
    void insecure_clear();
    void set_secure(bool secure) noexcept;
    [[nodiscard]] bool is_secure() const noexcept;

    [[nodiscard]] const bytes& data() const;
    [[nodiscard]] bytes& data();
    [[nodiscard]] size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

    [[nodiscard]] uint8_t& operator[](size_t index);
    [[nodiscard]] const uint8_t& operator[](size_t index) const;

    [[nodiscard]] bool operator==(const SecureBytes& other) const;
    [[nodiscard]] bool operator!=(const SecureBytes& other) const;

    [[nodiscard]] bytes release();

private:
    bytes data_;
    bool secure_;
};

// RAII utilities for secure memory management
namespace raii {
    // RAII wrapper for OpenSSL EVP_MD_CTX
    class EvpMdContext {
    public:
        EvpMdContext() noexcept : ctx_(nullptr) {}

        ~EvpMdContext() noexcept {
            if (ctx_) {
                EVP_MD_CTX_free(ctx_);
            }
        }

        // Non-copyable but movable
        EvpMdContext(const EvpMdContext&) = delete;
        EvpMdContext& operator=(const EvpMdContext&) = delete;

        EvpMdContext(EvpMdContext&& other) noexcept : ctx_(other.ctx_) {
            other.ctx_ = nullptr;
        }

        EvpMdContext& operator=(EvpMdContext&& other) noexcept {
            if (this != &other) {
                if (ctx_) EVP_MD_CTX_free(ctx_);
                ctx_ = other.ctx_;
                other.ctx_ = nullptr;
            }
            return *this;
        }

        [[nodiscard]] EVP_MD_CTX* get() const noexcept { return ctx_; }
        [[nodiscard]] EVP_MD_CTX* release() noexcept {
            EVP_MD_CTX* temp = ctx_;
            ctx_ = nullptr;
            return temp;
        }

        void reset(EVP_MD_CTX* new_ctx = nullptr) noexcept {
            if (ctx_) EVP_MD_CTX_free(ctx_);
            ctx_ = new_ctx;
        }

    private:
        EVP_MD_CTX* ctx_;
    };

    // RAII wrapper for OpenSSL EVP_CIPHER_CTX
    class EvpCipherContext {
    public:
        EvpCipherContext() noexcept : ctx_(nullptr) {}

        ~EvpCipherContext() noexcept {
            if (ctx_) {
                EVP_CIPHER_CTX_free(ctx_);
            }
        }

        // Non-copyable but movable
        EvpCipherContext(const EvpCipherContext&) = delete;
        EvpCipherContext& operator=(const EvpCipherContext&) = delete;

        EvpCipherContext(EvpCipherContext&& other) noexcept : ctx_(other.ctx_) {
            other.ctx_ = nullptr;
        }

        EvpCipherContext& operator=(EvpCipherContext&& other) noexcept {
            if (this != &other) {
                if (ctx_) EVP_CIPHER_CTX_free(ctx_);
                ctx_ = other.ctx_;
                other.ctx_ = nullptr;
            }
            return *this;
        }

        [[nodiscard]] EVP_CIPHER_CTX* get() const noexcept { return ctx_; }
        [[nodiscard]] EVP_CIPHER_CTX* release() noexcept {
            EVP_CIPHER_CTX* temp = ctx_;
            ctx_ = nullptr;
            return temp;
        }

        void reset(EVP_CIPHER_CTX* new_ctx = nullptr) noexcept {
            if (ctx_) EVP_CIPHER_CTX_free(ctx_);
            ctx_ = new_ctx;
        }

    private:
        EVP_CIPHER_CTX* ctx_;
    };

    // RAII wrapper for secure buffer locking (platform-specific)
    class MemoryLock {
    public:
        explicit MemoryLock(void* ptr, size_t size) noexcept
            : ptr_(ptr), size_(size), locked_(false) {
            lock();
        }

        ~MemoryLock() noexcept {
            unlock();
        }

        // Non-copyable but movable
        MemoryLock(const MemoryLock&) = delete;
        MemoryLock& operator=(const MemoryLock&) = delete;

        MemoryLock(MemoryLock&& other) noexcept
            : ptr_(other.ptr_), size_(other.size_), locked_(other.locked_) {
            other.ptr_ = nullptr;
            other.size_ = 0;
            other.locked_ = false;
        }

        MemoryLock& operator=(MemoryLock&& other) noexcept {
            if (this != &other) {
                unlock();
                ptr_ = other.ptr_;
                size_ = other.size_;
                locked_ = other.locked_;
                other.ptr_ = nullptr;
                other.size_ = 0;
                other.locked_ = false;
            }
            return *this;
        }

        [[nodiscard]] bool is_locked() const noexcept { return locked_; }

    private:
        void lock() noexcept;
        void unlock() noexcept;

        void* ptr_;
        size_t size_;
        bool locked_;
    };
}

// RAII secure buffer with automatic locking and zeroing
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size) : size_(size) {
        data_ = static_cast<uint8_t*>(secure_allocate(size_));
        lock_ = std::make_unique<raii::MemoryLock>(data_, size_);
    }

    ~SecureBuffer() noexcept {
        if (data_) {
            secure_zero_memory(data_, size_);
            secure_deallocate(data_, size_);
        }
    }

    // Non-copyable but movable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept
        : data_(other.data_), size_(other.size_), lock_(std::move(other.lock_)) {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            if (data_) {
                secure_zero_memory(data_, size_);
                secure_deallocate(data_, size_);
            }
            data_ = other.data_;
            size_ = other.size_;
            lock_ = std::move(other.lock_);
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    [[nodiscard]] uint8_t* data() noexcept { return data_; }
    [[nodiscard]] const uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] constexpr size_t size() const noexcept { return size_; }
    [[nodiscard]] bool is_locked() const noexcept { return lock_ && lock_->is_locked(); }

    [[nodiscard]] uint8_t& operator[](size_t index) {
        if (index >= size_) {
            throw std::out_of_range("SecureBuffer index out of range");
        }
        return data_[index];
    }

    [[nodiscard]] const uint8_t& operator[](size_t index) const {
        if (index >= size_) {
            throw std::out_of_range("SecureBuffer index out of range");
        }
        return data_[index];
    }

    // Convert to bytes vector (copy)
    [[nodiscard]] bytes to_bytes() const {
        return bytes(data_, data_ + size_);
    }

private:
    uint8_t* data_;
    size_t size_;
    std::unique_ptr<raii::MemoryLock> lock_;
};

} // namespace qybersafe::core

#endif // QYBERSAFE_CORE_CRYPTO_TYPES_H