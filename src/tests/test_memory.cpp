#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <string>
#include <chrono>
#include "qybersafe/core/crypto_types.h"

class MemoryTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up before each test
    }

    void TearDown() override {
        // Clean up after each test
    }
};

// Test SecureBytes default constructor
TEST_F(MemoryTest, SecureBytesDefaultConstructor) {
    qybersafe::core::SecureBytes bytes;

    EXPECT_EQ(bytes.size(), 0);
    EXPECT_TRUE(bytes.empty());
    EXPECT_TRUE(bytes.is_secure());
}

// Test SecureBytes sized constructor
TEST_F(MemoryTest, SecureBytesSizedConstructor) {
    const size_t test_size = 32;
    qybersafe::core::SecureBytes bytes(test_size);

    EXPECT_EQ(bytes.size(), test_size);
    EXPECT_FALSE(bytes.empty());
    EXPECT_TRUE(bytes.is_secure());

    // Should be initialized with random data (not all zeros)
    bool has_non_zero = false;
    for (size_t i = 0; i < test_size; ++i) {
        if (bytes[i] != 0) {
            has_non_zero = true;
            break;
        }
    }
    EXPECT_TRUE(has_non_zero) << "SecureBytes should be initialized with random data";
}

// Test SecureBytes copy constructor from bytes
TEST_F(MemoryTest, SecureBytesCopyFromBytes) {
    qybersafe::core::bytes source = {0x01, 0x02, 0x03, 0x04};
    qybersafe::core::SecureBytes secure_bytes(source);

    EXPECT_EQ(secure_bytes.size(), source.size());
    EXPECT_FALSE(secure_bytes.empty());
    EXPECT_TRUE(secure_bytes.is_secure());

    for (size_t i = 0; i < source.size(); ++i) {
        EXPECT_EQ(secure_bytes[i], source[i]);
    }
}

// Test SecureBytes move constructor from bytes
TEST_F(MemoryTest, SecureBytesMoveFromBytes) {
    qybersafe::core::bytes source = {0x01, 0x02, 0x03, 0x04};
    qybersafe::core::bytes source_copy = source;  // Keep a copy for verification
    qybersafe::core::SecureBytes secure_bytes(std::move(source));

    EXPECT_EQ(secure_bytes.size(), source_copy.size());
    EXPECT_FALSE(secure_bytes.empty());
    EXPECT_TRUE(secure_bytes.is_secure());

    for (size_t i = 0; i < source_copy.size(); ++i) {
        EXPECT_EQ(secure_bytes[i], source_copy[i]);
    }
}

// Test SecureBytes copy constructor
TEST_F(MemoryTest, SecureBytesCopyConstructor) {
    qybersafe::core::SecureBytes original(16);
    qybersafe::core::SecureBytes copy(original);

    EXPECT_EQ(copy.size(), original.size());
    EXPECT_EQ(copy.is_secure(), original.is_secure());

    // Should have same content
    for (size_t i = 0; i < original.size(); ++i) {
        EXPECT_EQ(copy[i], original[i]);
    }
}

// Test SecureBytes move constructor
TEST_F(MemoryTest, SecureBytesMoveConstructor) {
    qybersafe::core::SecureBytes original(16);
    std::vector<uint8_t> original_content;
    for (size_t i = 0; i < original.size(); ++i) {
        original_content.push_back(original[i]);
    }

    qybersafe::core::SecureBytes moved(std::move(original));

    EXPECT_EQ(moved.size(), original_content.size());
    EXPECT_TRUE(moved.is_secure());
    EXPECT_EQ(original.size(), 0);  // Original should be empty after move

    // Should have same content
    for (size_t i = 0; i < moved.size(); ++i) {
        EXPECT_EQ(moved[i], original_content[i]);
    }
}

// Test SecureBytes copy assignment
TEST_F(MemoryTest, SecureBytesCopyAssignment) {
    qybersafe::core::SecureBytes original(16);
    qybersafe::core::SecureBytes copy;

    copy = original;

    EXPECT_EQ(copy.size(), original.size());
    EXPECT_EQ(copy.is_secure(), original.is_secure());

    // Should have same content
    for (size_t i = 0; i < original.size(); ++i) {
        EXPECT_EQ(copy[i], original[i]);
    }
}

// Test SecureBytes move assignment
TEST_F(MemoryTest, SecureBytesMoveAssignment) {
    qybersafe::core::SecureBytes original(16);
    std::vector<uint8_t> original_content;
    for (size_t i = 0; i < original.size(); ++i) {
        original_content.push_back(original[i]);
    }

    qybersafe::core::SecureBytes moved;
    moved = std::move(original);

    EXPECT_EQ(moved.size(), original_content.size());
    EXPECT_TRUE(moved.is_secure());
    EXPECT_EQ(original.size(), 0);  // Original should be empty after move

    // Should have same content
    for (size_t i = 0; i < moved.size(); ++i) {
        EXPECT_EQ(moved[i], original_content[i]);
    }
}

// Test SecureBytes resize
TEST_F(MemoryTest, SecureBytesResize) {
    qybersafe::core::SecureBytes bytes(8);

    // Record original content
    std::vector<uint8_t> original_content;
    for (size_t i = 0; i < bytes.size(); ++i) {
        original_content.push_back(bytes[i]);
    }

    // Resize to larger
    size_t new_size = 16;
    bytes.resize(new_size);

    EXPECT_EQ(bytes.size(), new_size);
    EXPECT_FALSE(bytes.empty());
    EXPECT_TRUE(bytes.is_secure());

    // Original content should be gone (cleared and reinitialized)
    bool content_changed = false;
    for (size_t i = 0; i < std::min(original_content.size(), new_size); ++i) {
        if (bytes[i] != original_content[i]) {
            content_changed = true;
            break;
        }
    }
    EXPECT_TRUE(content_changed) << "Content should change after resize";

    // Resize to smaller
    size_t smaller_size = 8;
    bytes.resize(smaller_size);

    EXPECT_EQ(bytes.size(), smaller_size);
    EXPECT_FALSE(bytes.empty());
    EXPECT_TRUE(bytes.is_secure());
}

// Test SecureBytes clear
TEST_F(MemoryTest, SecureBytesClear) {
    qybersafe::core::SecureBytes bytes(16);
    EXPECT_FALSE(bytes.empty());

    bytes.clear();

    EXPECT_EQ(bytes.size(), 0);
    EXPECT_TRUE(bytes.empty());
    EXPECT_TRUE(bytes.is_secure());
}

// Test SecureBytes comparison operators
TEST_F(MemoryTest, SecureBytesComparison) {
    qybersafe::core::SecureBytes bytes1(16);
    qybersafe::core::SecureBytes bytes2(16);

    // Two different random instances should not be equal (very high probability)
    EXPECT_NE(bytes1, bytes2);

    // Copy should be equal
    qybersafe::core::SecureBytes bytes1_copy(bytes1);
    EXPECT_EQ(bytes1, bytes1_copy);

    // Test with different sizes
    qybersafe::core::SecureBytes bytes3(32);
    EXPECT_NE(bytes1, bytes3);
}

// Test SecureBytes data access
TEST_F(MemoryTest, SecureBytesDataAccess) {
    const size_t test_size = 16;
    qybersafe::core::SecureBytes bytes(test_size);

    // Test data() method
    const uint8_t* const_data = bytes.data();
    EXPECT_NE(const_data, nullptr);

    uint8_t* mutable_data = bytes.data();
    EXPECT_NE(mutable_data, nullptr);
    EXPECT_EQ(const_data, mutable_data);  // Should be same pointer

    // Test that we can modify data through data()
    uint8_t original_value = mutable_data[0];
    mutable_data[0] = static_cast<uint8_t>(original_value + 1);
    EXPECT_EQ(bytes[0], mutable_data[0]);
}

// Test SecureBytes operator[] bounds checking
TEST_F(MemoryTest, SecureBytesOperatorBounds) {
    qybersafe::core::SecureBytes bytes(4);

    // Valid access
    EXPECT_NO_THROW(bytes[0]);
    EXPECT_NO_THROW(bytes[1]);
    EXPECT_NO_THROW(bytes[2]);
    EXPECT_NO_THROW(bytes[3]);

    // Invalid access should throw
    EXPECT_THROW(bytes[4], std::out_of_range);
    EXPECT_THROW(bytes[100], std::out_of_range);
}

// Test SecureBytes const operator[]
TEST_F(MemoryTest, SecureBytesConstOperator) {
    qybersafe::core::SecureBytes bytes(4);
    const qybersafe::core::SecureBytes& const_bytes = bytes;

    // Should be able to access through const reference
    EXPECT_NO_THROW(const_bytes[0]);
    EXPECT_NO_THROW(const_bytes[1]);
    EXPECT_NO_THROW(const_bytes[2]);
    EXPECT_NO_THROW(const_bytes[3]);

    // Invalid access should throw
    EXPECT_THROW(const_bytes[4], std::out_of_range);
}

// Test SecureMemory secure zero
TEST_F(MemoryTest, SecureMemoryZero) {
    std::vector<uint8_t> buffer = {0x01, 0x02, 0x03, 0x04, 0x05};

    qybersafe::core::SecureMemory::secure_zero_memory(buffer.data(), buffer.size());

    // All bytes should be zero
    for (uint8_t byte : buffer) {
        EXPECT_EQ(byte, 0);
    }
}

// Test SecureMemory secure zero with null pointer
TEST_F(MemoryTest, SecureMemoryZeroNull) {
    // Should not crash with null pointer and zero size
    EXPECT_NO_THROW(qybersafe::core::SecureMemory::secure_zero_memory(nullptr, 0));
}

// Test SecureMemory compare
TEST_F(MemoryTest, SecureMemoryCompare) {
    std::vector<uint8_t> buffer1 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> buffer2 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> buffer3 = {0x01, 0x02, 0x03, 0x05};

    // Equal buffers should return true
    EXPECT_TRUE(qybersafe::core::SecureMemory::compare_memory(
        buffer1.data(), buffer2.data(), buffer1.size()));

    // Different buffers should return false
    EXPECT_FALSE(qybersafe::core::SecureMemory::compare_memory(
        buffer1.data(), buffer3.data(), buffer1.size()));
}

// Test SecureMemory compare with different sizes
TEST_F(MemoryTest, SecureMemoryCompareDifferentSizes) {
    std::vector<uint8_t> buffer1 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> buffer2 = {0x01, 0x02, 0x03};  // Smaller

    // Should compare up to the smaller buffer size
    EXPECT_FALSE(qybersafe::core::SecureMemory::compare_memory(
        buffer1.data(), buffer2.data(), buffer1.size()));
}

// Test SecureMemory allocate_aligned
TEST_F(MemoryTest, SecureMemoryAllocateAligned) {
    const size_t alignment = 16;
    const size_t size = 64;

    auto ptr = qybersafe::core::SecureMemory::allocate_aligned(size, alignment);
    ASSERT_NE(ptr, nullptr);

    // Check alignment
    EXPECT_EQ(reinterpret_cast<uintptr_t>(ptr) % alignment, 0);

    // Should be able to write and read
    for (size_t i = 0; i < size; ++i) {
        ptr[i] = static_cast<uint8_t>(i % 256);
    }

    for (size_t i = 0; i < size; ++i) {
        EXPECT_EQ(ptr[i], static_cast<uint8_t>(i % 256));
    }

    qybersafe::core::SecureMemory::free_aligned(ptr);
}

// Test SecureMemory allocate_aligned with zero size
TEST_F(MemoryTest, SecureMemoryAllocateAlignedZero) {
    auto ptr = qybersafe::core::SecureMemory::allocate_aligned(0, 16);
    EXPECT_EQ(ptr, nullptr);
}

// Test bytes alias functionality
TEST_F(MemoryTest, BytesAlias) {
    static_assert(std::is_same_v<qybersafe::core::bytes, std::vector<uint8_t>>,
                  "bytes should be an alias for std::vector<uint8_t>");

    qybersafe::core::bytes test_bytes = {0x01, 0x02, 0x03};
    EXPECT_EQ(test_bytes.size(), 3);
    EXPECT_EQ(test_bytes[0], 0x01);
    EXPECT_EQ(test_bytes[1], 0x02);
    EXPECT_EQ(test_bytes[2], 0x03);
}

// Test Result type with bytes
TEST_F(MemoryTest, ResultWithBytes) {
    qybersafe::core::bytes test_data = {0x01, 0x02, 0x03};

    // Success case
    auto success_result = qybersafe::core::Result<qybersafe::core::bytes>::success(test_data);
    EXPECT_TRUE(success_result.is_success());
    EXPECT_EQ(success_result.value(), test_data);

    // Error case
    auto error_result = qybersafe::core::Result<qybersafe::core::bytes>::error("Test error");
    EXPECT_FALSE(error_result.is_success());
    EXPECT_EQ(error_result.error(), "Test error");
}

// Performance test for SecureBytes operations
TEST_F(MemoryTest, SecureBytesPerformance) {
    const size_t test_size = 1024 * 1024;  // 1MB
    const int iterations = 10;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        qybersafe::core::SecureBytes bytes(test_size);

        // Do some operations
        for (size_t j = 0; j < 100; ++j) {
            size_t index = j % test_size;
            uint8_t value = bytes[index];
            bytes[index] = static_cast<uint8_t>(value + 1);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete within reasonable time (5 seconds for 10MB of operations)
    EXPECT_LT(duration.count(), 5000) << "SecureBytes operations too slow: " << duration.count() << "ms";
}