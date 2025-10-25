#include "qybersafe/core/crypto_types.h"
#include "qybersafe/core/secure_random.h"
#include <cstring>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstddef>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace qybersafe::core {

// Secure memory class implementation
class SecureMemory {
public:
    static void* allocate(size_t size) {
        void* ptr = std::aligned_alloc(64, size);  // Align for cache line
        if (!ptr) {
            throw std::bad_alloc();
        }
        return ptr;
    }

    static void deallocate(void* ptr, size_t size) {
        if (ptr) {
            secure_zero_memory(ptr, size);
            std::free(ptr);
        }
    }

    static void secure_zero_memory(void* ptr, size_t size) {
        if (!ptr || size == 0) {
            return;
        }

        // Use volatile pointer to prevent compiler optimization
        volatile uint8_t* volatile_ptr = static_cast<volatile uint8_t*>(ptr);

        // Multiple passes with different patterns to ensure memory is cleared
        for (int pass = 0; pass < 3; ++pass) {
            uint8_t pattern = static_cast<uint8_t>(0xFF << pass);
            for (size_t i = 0; i < size; ++i) {
                volatile_ptr[i] = pattern;
            }
        }

        // Final zero pass
        for (size_t i = 0; i < size; ++i) {
            volatile_ptr[i] = 0;
        }

        // Memory barrier to prevent reordering
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }

    static bool compare_memory(const void* a, const void* b, size_t size) {
        if (!a || !b) {
            return a == b;
        }

        const volatile uint8_t* ptr_a = static_cast<const volatile uint8_t*>(a);
        const volatile uint8_t* ptr_b = static_cast<const volatile uint8_t*>(b);

        uint8_t result = 0;
        for (size_t i = 0; i < size; ++i) {
            result |= ptr_a[i] ^ ptr_b[i];
        }

        return result == 0;
    }
};

// Secure bytes implementation
SecureBytes::SecureBytes() : data_(), secure_(true) {}

SecureBytes::SecureBytes(size_t size) : data_(size), secure_(true) {
    if (size > 0) {
        auto result = fill_random(data_.data(), data_.size());
        if (!result.is_success()) {
            // If random generation fails, zero the memory for security
            SecureMemory::secure_zero_memory(data_.data(), data_.size());
            secure_ = false;
        }
    }
}

SecureBytes::SecureBytes(const bytes& data) : data_(data), secure_(true) {}

SecureBytes::SecureBytes(bytes&& data) : data_(std::move(data)), secure_(true) {}

SecureBytes::~SecureBytes() {
    if (secure_ && !data_.empty()) {
        SecureMemory::secure_zero_memory(data_.data(), data_.size());
    }
}

SecureBytes::SecureBytes(const SecureBytes& other) : data_(other.data_), secure_(true) {}

SecureBytes::SecureBytes(SecureBytes&& other) noexcept
    : data_(std::move(other.data_)), secure_(other.secure_) {
    other.secure_ = false;
}

SecureBytes& SecureBytes::operator=(const SecureBytes& other) {
    if (this != &other) {
        clear();
        data_ = other.data_;
        secure_ = true;
    }
    return *this;
}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
    if (this != &other) {
        clear();
        data_ = std::move(other.data_);
        secure_ = other.secure_;
        other.secure_ = false;
    }
    return *this;
}

SecureBytes& SecureBytes::operator=(const bytes& other) {
    clear();
    data_ = other;
    secure_ = true;
    return *this;
}

SecureBytes& SecureBytes::operator=(bytes&& other) {
    clear();
    data_ = std::move(other);
    secure_ = true;
    return *this;
}

void SecureBytes::resize(size_t new_size) {
    if (new_size != data_.size()) {
        clear();
        data_.resize(new_size);
        if (new_size > 0) {
            auto result = fill_random(data_.data(), data_.size());
            if (!result.is_success()) {
                // If random generation fails, zero the memory for security
                SecureMemory::secure_zero_memory(data_.data(), data_.size());
                secure_ = false;
            }
        }
    }
}

void SecureBytes::clear() {
    if (secure_ && !data_.empty()) {
        SecureMemory::secure_zero_memory(data_.data(), data_.size());
    }
    data_.clear();
}

void SecureBytes::insecure_clear() {
    data_.clear();
}

void SecureBytes::set_secure(bool secure) noexcept {
    secure_ = secure;
}

bool SecureBytes::is_secure() const noexcept {
    return secure_;
}

const bytes& SecureBytes::data() const {
    return data_;
}

bytes& SecureBytes::data() {
    return data_;
}

size_t SecureBytes::size() const noexcept {
    return data_.size();
}

bool SecureBytes::empty() const noexcept {
    return data_.empty();
}

uint8_t& SecureBytes::operator[](size_t index) {
    if (index >= data_.size()) {
        throw std::out_of_range("SecureBytes index out of range");
    }
    return data_[index];
}

const uint8_t& SecureBytes::operator[](size_t index) const {
    if (index >= data_.size()) {
        throw std::out_of_range("SecureBytes index out of range");
    }
    return data_[index];
}

bool SecureBytes::operator==(const SecureBytes& other) const {
    return SecureMemory::compare_memory(data_.data(), other.data_.data(),
                                       std::min(data_.size(), other.data_.size())) &&
           data_.size() == other.data_.size();
}

bool SecureBytes::operator!=(const SecureBytes& other) const {
    return !(*this == other);
}

core::bytes SecureBytes::release() {
    this->secure_ = false;
    return std::move(this->data_);
}

// Global utility functions
void secure_zero_memory(void* ptr, size_t size) {
    SecureMemory::secure_zero_memory(ptr, size);
}

bool constant_time_compare(const void* a, const void* b, size_t size) {
    return SecureMemory::compare_memory(a, b, size);
}

// Global secure memory utility functions (wrappers for SecureMemory)
void* secure_allocate(size_t size) {
    return SecureMemory::allocate(size);
}

void secure_deallocate(void* ptr, size_t size) {
    SecureMemory::deallocate(ptr, size);
}

// MemoryLock implementation
namespace raii {

void MemoryLock::lock() noexcept {
    if (!ptr_ || size_ == 0) {
        locked_ = false;
        return;
    }

#if defined(__unix__) || defined(__APPLE__)
    // Try to lock memory using mlock()
    if (mlock(ptr_, size_) == 0) {
        locked_ = true;
    } else {
        locked_ = false;
    }
#elif defined(_WIN32)
    // Try to lock memory using VirtualLock()
    if (VirtualLock(ptr_, size_) != 0) {
        locked_ = true;
    } else {
        locked_ = false;
    }
#else
    // Platform not supported
    locked_ = false;
#endif
}

void MemoryLock::unlock() noexcept {
    if (locked_ && ptr_ && size_ > 0) {
#if defined(__unix__) || defined(__APPLE__)
        munlock(ptr_, size_);
#elif defined(_WIN32)
        VirtualUnlock(ptr_, size_);
#endif
        locked_ = false;
    }
}

} // namespace raii

} // namespace qybersafe::core