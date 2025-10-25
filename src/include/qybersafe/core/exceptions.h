#ifndef QYBERSAFE_CORE_EXCEPTIONS_H
#define QYBERSAFE_CORE_EXCEPTIONS_H

#include <stdexcept>
#include <string>
#include <system_error>

namespace qybersafe::core {

// Base exception class for all QyberSafe errors
class QyberSafeException : public std::runtime_error {
public:
    explicit QyberSafeException(const std::string& message)
        : std::runtime_error("QyberSafe: " + message) {}

    explicit QyberSafeException(const std::string& context, const std::string& message)
        : std::runtime_error("QyberSafe[" + context + "]: " + message) {}
};

// Cryptographic operation errors
class CryptographicException : public QyberSafeException {
public:
    explicit CryptographicException(const std::string& operation, const std::string& message)
        : QyberSafeException(operation, message) {}
};

// Key management errors
class KeyException : public QyberSafeException {
public:
    explicit KeyException(const std::string& message)
        : QyberSafeException("Key", message) {}
};

class InvalidKeyException : public KeyException {
public:
    explicit InvalidKeyException(const std::string& message)
        : KeyException("Invalid key: " + message) {}
};

class KeySizeException : public KeyException {
public:
    explicit KeySizeException(const std::string& message)
        : KeyException("Invalid key size: " + message) {}
};

// Algorithm-specific errors
class AlgorithmException : public QyberSafeException {
public:
    explicit AlgorithmException(const std::string& algorithm, const std::string& message)
        : QyberSafeException(algorithm, message) {}
};

class SecurityLevelException : public AlgorithmException {
public:
    explicit SecurityLevelException(const std::string& message)
        : AlgorithmException("Security Level", message) {}
};

// Input validation errors
class ValidationException : public QyberSafeException {
public:
    explicit ValidationException(const std::string& field, const std::string& message)
        : QyberSafeException("Validation", field + ": " + message) {}
};

class ParameterException : public ValidationException {
public:
    explicit ParameterException(const std::string& parameter, const std::string& message)
        : ValidationException(parameter, message) {}
};

// Memory and resource errors
class MemoryException : public QyberSafeException {
public:
    explicit MemoryException(const std::string& message)
        : QyberSafeException("Memory", message) {}
};

class ResourceException : public QyberSafeException {
public:
    explicit ResourceException(const std::string& resource, const std::string& message)
        : QyberSafeException("Resource", resource + ": " + message) {}
};

// System and I/O errors
class SystemException : public QyberSafeException {
public:
    explicit SystemException(const std::string& operation, const std::string& system_error)
        : QyberSafeException("System", operation + " failed: " + system_error) {}
};

// Random number generation errors
class RandomNumberException : public CryptographicException {
public:
    explicit RandomNumberException(const std::string& message)
        : CryptographicException("Random Number Generation", message) {}
};

// Hash function errors
class HashException : public CryptographicException {
public:
    explicit HashException(const std::string& hash_function, const std::string& message)
        : CryptographicException(hash_function, message) {}
};

// Error codes for system-independent error handling
enum class ErrorCode {
    SUCCESS = 0,

    // Key errors (1000-1099)
    INVALID_KEY_FORMAT = 1001,
    INVALID_KEY_SIZE = 1002,
    KEY_GENERATION_FAILED = 1003,
    KEY_DERIVATION_FAILED = 1004,

    // Algorithm errors (1100-1199)
    UNSUPPORTED_SECURITY_LEVEL = 1101,
    ALGORITHM_NOT_SUPPORTED = 1102,
    INVALID_PARAMETERS = 1103,

    // Cryptographic errors (1200-1299)
    ENCRYPTION_FAILED = 1201,
    DECRYPTION_FAILED = 1202,
    SIGNATURE_FAILED = 1203,
    VERIFICATION_FAILED = 1204,
    HASH_FAILED = 1205,

    // Random number errors (1300-1399)
    RANDOM_NUMBER_GENERATION_FAILED = 1301,
    ENTROPY_INSUFFICIENT = 1302,

    // Memory errors (1400-1499)
    MEMORY_ALLOCATION_FAILED = 1401,
    SECURE_MEMORY_ERROR = 1402,

    // System errors (1500-1599)
    SYSTEM_ERROR = 1501,
    IO_ERROR = 1502,
    RESOURCE_EXHAUSTED = 1503,

    // Validation errors (1600-1699)
    INVALID_INPUT = 1601,
    BUFFER_TOO_SMALL = 1602,
    BUFFER_TOO_LARGE = 1603,
};

// Error category for std::error_code support
class QyberSafeErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override {
        return "QyberSafe";
    }

    std::string message(int ev) const override {
        switch (static_cast<ErrorCode>(ev)) {
            case ErrorCode::SUCCESS:
                return "Success";
            case ErrorCode::INVALID_KEY_FORMAT:
                return "Invalid key format";
            case ErrorCode::INVALID_KEY_SIZE:
                return "Invalid key size";
            case ErrorCode::KEY_GENERATION_FAILED:
                return "Key generation failed";
            case ErrorCode::KEY_DERIVATION_FAILED:
                return "Key derivation failed";
            case ErrorCode::UNSUPPORTED_SECURITY_LEVEL:
                return "Unsupported security level";
            case ErrorCode::ALGORITHM_NOT_SUPPORTED:
                return "Algorithm not supported";
            case ErrorCode::INVALID_PARAMETERS:
                return "Invalid parameters";
            case ErrorCode::ENCRYPTION_FAILED:
                return "Encryption failed";
            case ErrorCode::DECRYPTION_FAILED:
                return "Decryption failed";
            case ErrorCode::SIGNATURE_FAILED:
                return "Signature generation failed";
            case ErrorCode::VERIFICATION_FAILED:
                return "Signature verification failed";
            case ErrorCode::HASH_FAILED:
                return "Hash operation failed";
            case ErrorCode::RANDOM_NUMBER_GENERATION_FAILED:
                return "Random number generation failed";
            case ErrorCode::ENTROPY_INSUFFICIENT:
                return "Insufficient entropy";
            case ErrorCode::MEMORY_ALLOCATION_FAILED:
                return "Memory allocation failed";
            case ErrorCode::SECURE_MEMORY_ERROR:
                return "Secure memory operation failed";
            case ErrorCode::SYSTEM_ERROR:
                return "System error";
            case ErrorCode::IO_ERROR:
                return "I/O error";
            case ErrorCode::RESOURCE_EXHAUSTED:
                return "Resource exhausted";
            case ErrorCode::INVALID_INPUT:
                return "Invalid input";
            case ErrorCode::BUFFER_TOO_SMALL:
                return "Buffer too small";
            case ErrorCode::BUFFER_TOO_LARGE:
                return "Buffer too large";
            default:
                return "Unknown error";
        }
    }

    static const QyberSafeErrorCategory& instance() {
        static QyberSafeErrorCategory category;
        return category;
    }
};

// Helper functions for creating std::error_code
inline std::error_code make_error_code(ErrorCode ec) {
    return std::error_code(static_cast<int>(ec), QyberSafeErrorCategory::instance());
}

} // namespace qybersafe::core

// Enable std::error_code support for ErrorCode
namespace std {
    template<>
    struct is_error_code_enum<qybersafe::core::ErrorCode> : true_type {};
}

#endif // QYBERSAFE_CORE_EXCEPTIONS_H