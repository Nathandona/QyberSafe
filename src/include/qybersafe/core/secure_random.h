#ifndef QYBERSAFE_CORE_SECURE_RANDOM_H
#define QYBERSAFE_CORE_SECURE_RANDOM_H

#include <vector>
#include <memory>
#include <cstdint>
#include "crypto_types.h"

namespace qybersafe::core {

class SecureRandom {
public:
    // Singleton access
    static SecureRandom& instance();
    static void set_instance(SecureRandom* instance);

    // Generate random bytes
    Result<bytes> generate_bytes(size_t count);

    // Generate random values of specific types
    Result<uint8_t> generate_uint8();
    Result<uint16_t> generate_uint16();
    Result<uint32_t> generate_uint32();
    Result<uint64_t> generate_uint64();

    // Generate random values in range [min, max]
    Result<uint32_t> generate_range(uint32_t min, uint32_t max);

    // Generate random boolean
    Result<bool> generate_bool();

    // Fill existing buffer with random bytes
    Result<void> fill_bytes(void* buffer, size_t size);

  // Reinitialize with system entropy
    Result<void> reinitialize();

    // Check if the generator is properly initialized
    bool is_initialized() const { return initialized_; }

    // Delete copy constructor and assignment operator
    SecureRandom(const SecureRandom&) = delete;
    SecureRandom& operator=(const SecureRandom&) = delete;

private:
    SecureRandom();
    ~SecureRandom();

    // Friend declarations for singleton management
    friend struct SecureRandomDeleter;

    bool initialized_;
    std::unique_ptr<uint8_t[]> state_;

    // Initialize the random number generator
    Result<void> initialize();

    // Platform-specific initialization
    Result<void> initialize_platform();

    // Generate entropy from system sources
    Result<bytes> get_system_entropy(size_t count);
};

// Global convenience functions
Result<bytes> random_bytes(size_t count);
Result<uint32_t> random_uint32();
Result<uint64_t> random_uint64();
Result<uint32_t> random_range(uint32_t min, uint32_t max);
Result<bool> random_bool();
Result<void> fill_random(void* buffer, size_t size);

} // namespace qybersafe::core

#endif // QYBERSAFE_CORE_SECURE_RANDOM_H