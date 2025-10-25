#include "qybersafe/core/secure_random.h"
#include <random>
#include <limits>
#include <stdexcept>
#include <thread>
#include <cstring>
#include <climits>
#include <mutex>
#include <memory>

namespace qybersafe::core {

// Custom deleter for SecureRandom singleton
struct SecureRandomDeleter {
    void operator()(SecureRandom* ptr) const {
        delete ptr;
    }
};

// Static instance for singleton pattern using smart pointer
static std::unique_ptr<SecureRandom, SecureRandomDeleter> instance_;

SecureRandom& SecureRandom::instance() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        instance_.reset(new SecureRandom());
    });
    return *instance_;
}

void SecureRandom::set_instance(SecureRandom* instance) {
    // For now, we'll just ignore this function since we use a singleton pattern
    (void)instance;
}

SecureRandom::SecureRandom() : initialized_(false) {
    auto result = initialize();
    if (!result.is_success()) {
        throw std::runtime_error("Failed to initialize SecureRandom: " + result.error());
    }
}

SecureRandom::~SecureRandom() {
    if (state_) {
        std::memset(state_.get(), 0, 256);
    }
}

Result<void> SecureRandom::initialize() {
    auto init_result = initialize_platform();
    if (!init_result.is_success()) {
        return init_result;
    }

    state_ = std::make_unique<uint8_t[]>(256);

    // Get initial entropy
    auto entropy = get_system_entropy(256);
    if (!entropy.is_success()) {
        return Result<void>::error(entropy.error());
    }

    // Validate entropy size before copying to prevent buffer overflow
    if (entropy.value().size() < 256) {
        return Result<void>::error("Insufficient entropy: expected 256 bytes, got " +
                                 std::to_string(entropy.value().size()));
    }

    std::memcpy(state_.get(), entropy.value().data(), 256);
    initialized_ = true;

    return Result<void>::success();
}

Result<void> SecureRandom::initialize_platform() {
    // Platform-specific initialization
    std::random_device rd;
    if (rd.entropy() == 0) {
        return Result<void>::error("Random device has no entropy");
    }

    // Additional platform checks could go here
    return Result<void>::success();
}

Result<bytes> SecureRandom::get_system_entropy(size_t count) {
    try {
        bytes result(count);
        std::random_device rd;

        std::uniform_int_distribution<uint8_t> dist(
            std::numeric_limits<uint8_t>::min(),
            std::numeric_limits<uint8_t>::max()
        );

        for (size_t i = 0; i < count; ++i) {
            result[i] = dist(rd);
        }

        return Result<bytes>::success(std::move(result));
    } catch (const std::exception& e) {
        return Result<bytes>::error("Failed to get system entropy: " + std::string(e.what()));
    }
}

Result<bytes> SecureRandom::generate_bytes(size_t count) {
    if (!initialized_) {
        return Result<bytes>::error("SecureRandom not initialized");
    }

    if (count == 0) {
        return Result<bytes>::success(bytes{});
    }

    try {
        bytes result(count);

        // Simple XOR-based PRNG for demonstration
        // In production, this should use cryptographically secure PRNG
        for (size_t i = 0; i < count; ++i) {
            state_[i % 256] ^= state_[(i + 1) % 256] + state_[(i + 7) % 256];
            result[i] = state_[i % 256];
        }

        // Reseed periodically - handle errors properly
        if (count % 256 == 0) {
            auto entropy = get_system_entropy(32);
            if (entropy.is_success()) {
                // Validate entropy size before using
                const auto& entropy_data = entropy.value();
                size_t copy_size = std::min(entropy_data.size(), static_cast<size_t>(32));
                for (size_t i = 0; i < copy_size; ++i) {
                    state_[i] ^= entropy_data[i];
                }
            }
            // Note: If entropy generation fails, we continue with existing state
            // but should log this in a production system
        }

        return Result<bytes>::success(std::move(result));
    } catch (const std::exception& e) {
        return Result<bytes>::error("Failed to generate random bytes: " + std::string(e.what()));
    }
}

Result<uint8_t> SecureRandom::generate_uint8() {
    auto bytes_result = generate_bytes(1);
    if (!bytes_result.is_success()) {
        return Result<uint8_t>::error(bytes_result.error());
    }
    return Result<uint8_t>::success(bytes_result.value()[0]);
}

Result<uint16_t> SecureRandom::generate_uint16() {
    auto bytes_result = generate_bytes(2);
    if (!bytes_result.is_success()) {
        return Result<uint16_t>::error(bytes_result.error());
    }

    uint16_t result = static_cast<uint16_t>(bytes_result.value()[0]) |
                     (static_cast<uint16_t>(bytes_result.value()[1]) << 8);
    return Result<uint16_t>::success(result);
}

Result<uint32_t> SecureRandom::generate_uint32() {
    auto bytes_result = generate_bytes(4);
    if (!bytes_result.is_success()) {
        return Result<uint32_t>::error(bytes_result.error());
    }

    uint32_t result = static_cast<uint32_t>(bytes_result.value()[0]) |
                     (static_cast<uint32_t>(bytes_result.value()[1]) << 8) |
                     (static_cast<uint32_t>(bytes_result.value()[2]) << 16) |
                     (static_cast<uint32_t>(bytes_result.value()[3]) << 24);
    return Result<uint32_t>::success(result);
}

Result<uint64_t> SecureRandom::generate_uint64() {
    auto bytes_result = generate_bytes(8);
    if (!bytes_result.is_success()) {
        return Result<uint64_t>::error(bytes_result.error());
    }

    uint64_t result = 0;
    for (size_t i = 0; i < 8; ++i) {
        result |= (static_cast<uint64_t>(bytes_result.value()[i]) << (i * 8));
    }
    return Result<uint64_t>::success(result);
}

Result<uint32_t> SecureRandom::generate_range(uint32_t min, uint32_t max) {
    if (min >= max) {
        return Result<uint32_t>::error("Invalid range: min must be less than max");
    }

    // Check for potential overflow in range calculation
    if (max - min > UINT32_MAX - 1) {
        return Result<uint32_t>::error("Range too large, may cause overflow");
    }

    uint32_t range = max - min;
    uint32_t result;

    // Rejection sampling to avoid modulo bias
    // Use proper calculation to prevent integer overflow
    const uint32_t threshold = (UINT32_MAX - (UINT32_MAX % range) + 1) % range;

    do {
        auto rand_result = generate_uint32();
        if (!rand_result.is_success()) {
            return rand_result;
        }

        result = rand_result.value();
    } while (result < threshold);

    return Result<uint32_t>::success(min + (result % range));
}

Result<bool> SecureRandom::generate_bool() {
    auto rand_result = generate_uint8();
    if (!rand_result.is_success()) {
        return Result<bool>::error(rand_result.error());
    }
    return Result<bool>::success(rand_result.value() % 2 == 1);
}

Result<void> SecureRandom::fill_bytes(void* buffer, size_t size) {
    if (!buffer) {
        return Result<void>::error("Buffer is null");
    }

    auto bytes_result = generate_bytes(size);
    if (!bytes_result.is_success()) {
        return Result<void>::error(bytes_result.error());
    }

    // Validate size before copying to prevent buffer overflow
    if (bytes_result.value().size() < size) {
        return Result<void>::error("Insufficient random bytes generated");
    }

    std::memcpy(buffer, bytes_result.value().data(), size);
    return Result<void>::success();
}


Result<void> SecureRandom::reinitialize() {
    initialized_ = false;
    return initialize();
}

// Global convenience functions
Result<bytes> random_bytes(size_t count) {
    return SecureRandom::instance().generate_bytes(count);
}

Result<uint32_t> random_uint32() {
    return SecureRandom::instance().generate_uint32();
}

Result<uint64_t> random_uint64() {
    return SecureRandom::instance().generate_uint64();
}

Result<uint32_t> random_range(uint32_t min, uint32_t max) {
    return SecureRandom::instance().generate_range(min, max);
}

Result<bool> random_bool() {
    return SecureRandom::instance().generate_bool();
}

Result<void> fill_random(void* buffer, size_t size) {
    return SecureRandom::instance().fill_bytes(buffer, size);
}

} // namespace qybersafe::core