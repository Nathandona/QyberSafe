#ifndef QYBERSAFE_CORE_CRYPTO_TYPES_H
#define QYBERSAFE_CORE_CRYPTO_TYPES_H

#include <cstdint>
#include <vector>
#include <memory>

namespace qybersafe::core {

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

// Security level enumeration
enum class SecurityLevel {
    LOW = 1,    // ~128-bit quantum security
    MEDIUM = 2, // ~192-bit quantum security
    HIGH = 3    // ~256-bit quantum security
};

// Algorithm identifier
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

// Result type for operations
template<typename T>
class Result {
public:
    static Result success(T value) {
        return Result(std::move(value), true);
    }

    static Result error(const std::string& error_msg) {
        return Result(T{}, false, error_msg);
    }

    bool is_success() const { return success_; }
    const T& value() const { return value_; }
    const std::string& error() const { return error_msg_; }

    explicit operator bool() const { return success_; }

private:
    Result(T val, bool succ, const std::string& err = "")
        : value_(std::move(val)), success_(succ), error_msg_(err) {}

    T value_;
    bool success_;
    std::string error_msg_;
};

// Specialization for void
template<>
class Result<void> {
public:
    static Result success() {
        return Result(true);
    }

    static Result error(const std::string& error_msg) {
        return Result(false, error_msg);
    }

    bool is_success() const { return success_; }
    const std::string& error() const { return error_msg_; }

    explicit operator bool() const { return success_; }

private:
    Result(bool succ, const std::string& err = "")
        : success_(succ), error_msg_(err) {}

    bool success_;
    std::string error_msg_;
};

} // namespace qybersafe::core

#endif // QYBERSAFE_CORE_CRYPTO_TYPES_H