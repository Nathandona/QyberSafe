#ifndef QYBERSAFE_CORE_CRYPTO_TYPES_H
#define QYBERSAFE_CORE_CRYPTO_TYPES_H

#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <stdexcept>
#include <type_traits>
#include <openssl/evp.h>
#include "qybersafe/core/exceptions.h"

namespace qybersafe::core {

// Forward declarations for secure memory utilities
void* secure_allocate(size_t size);
void secure_deallocate(void* ptr, size_t size);
void secure_zero_memory(void* ptr, size_t size);

// Type definitions
using byte = uint8_t;
using bytes = std::vector<byte>;

// Constants
constexpr size_t KYBER_PUBLIC_KEY_512 = 800;
constexpr size_t KYBER_PRIVATE_KEY_512 = 1632;
constexpr size_t KYBER_CIPHERTEXT_512 = 768;

constexpr size_t KYBER_PUBLIC_KEY_768 = 1184;
constexpr size_t KYBER_PRIVATE_KEY_768 = 2400;
constexpr size_t KYBER_CIPHERTEXT_768 = 1088;

constexpr size_t KYBER_PUBLIC_KEY_1024 = 1568;
constexpr size_t KYBER_PRIVATE_KEY_1024 = 3168;
constexpr size_t KYBER_CIPHERTEXT_1024 = 1568;

constexpr size_t DILITHIUM_PUBLIC_KEY_2 = 1312;
constexpr size_t DILITHIUM_PRIVATE_KEY_2 = 2528;
constexpr size_t DILITHIUM_SIGNATURE_2 = 2420;

constexpr size_t DILITHIUM_PUBLIC_KEY_3 = 1952;
constexpr size_t DILITHIUM_PRIVATE_KEY_3 = 4000;
constexpr size_t DILITHIUM_SIGNATURE_3 = 3293;

constexpr size_t DILITHIUM_PUBLIC_KEY_5 = 2592;
constexpr size_t DILITHIUM_PRIVATE_KEY_5 = 4864;
constexpr size_t DILITHIUM_SIGNATURE_5 = 4595;

// Unified security level enumeration for all algorithms
enum class SecurityLevel {
    // Kyber security levels
    KYBER_512 = 101,     // ~128-bit quantum security
    KYBER_768 = 102,     // ~192-bit quantum security (recommended)
    KYBER_1024 = 103,    // ~256-bit quantum security

    // Dilithium security levels
    DILITHIUM_2 = 201,   // ~128-bit quantum security
    DILITHIUM_3 = 202,   // ~192-bit quantum security (recommended)
    DILITHIUM_5 = 203,   // ~256-bit quantum security

    // SPHINCS+ security levels
    SPHINCS_128 = 301,   // ~128-bit quantum security
    SPHINCS_192 = 302,   // ~192-bit quantum security
    SPHINCS_256 = 303,   // ~256-bit quantum security

    // Legacy compatibility (deprecated)
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3
};

// Algorithm family enumeration
enum class AlgorithmFamily {
    KYBER,
    DILITHIUM,
    SPHINCS_PLUS,
    HYBRID
};

// Complete algorithm identifier
enum class Algorithm {
    KYBER_512,
    KYBER_768,
    KYBER_1024,
    DILITHIUM_2,
    DILITHIUM_3,
    DILITHIUM_5,
    SPHINCS128,
    SPHINCS192,
    SPHINCS256,
    HYBRID_KYBER_RSA,
    HYBRID_KYBER_ECDH
};

// Helper functions for security level management
namespace security_level_utils {
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

    constexpr bool is_kyber_level(SecurityLevel level) noexcept {
        return level == SecurityLevel::KYBER_512 ||
               level == SecurityLevel::KYBER_768 ||
               level == SecurityLevel::KYBER_1024;
    }

    constexpr bool is_dilithium_level(SecurityLevel level) noexcept {
        return level == SecurityLevel::DILITHIUM_2 ||
               level == SecurityLevel::DILITHIUM_3 ||
               level == SecurityLevel::DILITHIUM_5;
    }

    constexpr bool is_sphincs_level(SecurityLevel level) noexcept {
        return level == SecurityLevel::SPHINCS_128 ||
               level == SecurityLevel::SPHINCS_192 ||
               level == SecurityLevel::SPHINCS_256;
    }

    // Legacy compatibility helpers
    constexpr SecurityLevel from_legacy(int level) noexcept {
        switch (level) {
            case 1: return SecurityLevel::LOW;
            case 2: return SecurityLevel::MEDIUM;
            case 3: return SecurityLevel::HIGH;
            default: return SecurityLevel::MEDIUM;
        }
    }
}

// Result type for operations with modern C++ enhancements
template<typename T>
class Result {
public:
    [[nodiscard]] static Result success(T value) noexcept {
        return Result(std::move(value), true);
    }

    [[nodiscard]] static Result error(const std::string& error_msg) noexcept {
        return Result(T{}, false, error_msg);
    }

    [[nodiscard]] static Result error(ErrorCode ec) noexcept {
        return Result(T{}, false, make_error_code(ec).message());
    }

    [[nodiscard]] static Result error(const std::string& context, const std::string& error_msg) noexcept {
        return Result(T{}, false, context + ": " + error_msg);
    }

    [[nodiscard]] constexpr bool is_success() const noexcept { return success_; }
    [[nodiscard]] constexpr bool is_error() const noexcept { return !success_; }

    [[nodiscard]] const T& value() const {
        if (!success_) {
            throw QyberSafeException("Result error", error_msg_);
        }
        return value_;
    }

    [[nodiscard]] const T& value_or(const T& default_value) const noexcept {
        return success_ ? value_ : default_value;
    }

    [[nodiscard]] const std::string& error() const noexcept { return error_msg_; }

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return success_; }

    // Chain operations for functional style error handling
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
    Result(T val, bool succ, const std::string& err = "")
        : value_(std::move(val)), success_(succ), error_msg_(err) {}

    T value_;
    bool success_;
    std::string error_msg_;
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