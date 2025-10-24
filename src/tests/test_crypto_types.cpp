#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <vector>
#include <string>
#include "qybersafe/core/crypto_types.h"

using namespace qybersafe::core;
using namespace testing;

class CryptoTypesTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common setup for each test
    }

    void TearDown() override {
        // Common cleanup for each test
    }
};

// Test Result type with success
TEST_F(CryptoTypesTest, ResultSuccess) {
    std::string test_value = "test data";
    auto result = Result<std::string>::success(test_value);

    EXPECT_TRUE(result.is_success());
    EXPECT_TRUE(result);
    EXPECT_EQ(result.value(), test_value);
}

// Test Result type with error
TEST_F(CryptoTypesTest, ResultError) {
    std::string error_msg = "test error";
    auto result = Result<std::string>::error(error_msg);

    EXPECT_FALSE(result.is_success());
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error(), error_msg);
}

// Test void Result type with success
TEST_F(CryptoTypesTest, VoidResultSuccess) {
    auto result = Result<void>::success();

    EXPECT_TRUE(result.is_success());
    EXPECT_TRUE(result);
}

// Test void Result type with error
TEST_F(CryptoTypesTest, VoidResultError) {
    std::string error_msg = "test error";
    auto result = Result<void>::error(error_msg);

    EXPECT_FALSE(result.is_success());
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error(), error_msg);
}

// Test byte type alias
TEST_F(CryptoTypesTest, ByteTypeAlias) {
    bytes data = {0x01, 0x02, 0x03, 0x04};

    EXPECT_EQ(data.size(), 4);
    EXPECT_EQ(data[0], 0x01);
    EXPECT_EQ(data[1], 0x02);
    EXPECT_EQ(data[2], 0x03);
    EXPECT_EQ(data[3], 0x04);
}

// Test SecurityLevel values
TEST_F(CryptoTypesTest, SecurityLevelValues) {
    EXPECT_EQ(static_cast<int>(SecurityLevel::LOW), 1);
    EXPECT_EQ(static_cast<int>(SecurityLevel::MEDIUM), 2);
    EXPECT_EQ(static_cast<int>(SecurityLevel::HIGH), 3);
}

// Test Algorithm enum values
TEST_F(CryptoTypesTest, AlgorithmValues) {
    // Kyber algorithms
    EXPECT_LT(static_cast<int>(Algorithm::KYBER_512), static_cast<int>(Algorithm::KYBER_768));
    EXPECT_LT(static_cast<int>(Algorithm::KYBER_768), static_cast<int>(Algorithm::KYBER_1024));

    // Dilithium algorithms
    EXPECT_LT(static_cast<int>(Algorithm::DILITHIUM_2), static_cast<int>(Algorithm::DILITHIUM_3));
    EXPECT_LT(static_cast<int>(Algorithm::DILITHIUM_3), static_cast<int>(Algorithm::DILITHIUM_5));

    // SPHINCS+ algorithms
    EXPECT_LT(static_cast<int>(Algorithm::SPHINCS128), static_cast<int>(Algorithm::SPHINCS192));
    EXPECT_LT(static_cast<int>(Algorithm::SPHINCS192), static_cast<int>(Algorithm::SPHINCS256));
}

// Test constants
TEST_F(CryptoTypesTest, KyberConstants) {
    EXPECT_GT(KYBER_PUBLIC_KEY_512, 0);
    EXPECT_GT(KYBER_PRIVATE_KEY_512, 0);
    EXPECT_GT(KYBER_CIPHERTEXT_512, 0);

    EXPECT_GT(KYBER_PUBLIC_KEY_768, KYBER_PUBLIC_KEY_512);
    EXPECT_GT(KYBER_PRIVATE_KEY_768, KYBER_PRIVATE_KEY_512);
    EXPECT_GT(KYBER_CIPHERTEXT_768, KYBER_CIPHERTEXT_512);

    EXPECT_GT(KYBER_PUBLIC_KEY_1024, KYBER_PUBLIC_KEY_768);
    EXPECT_GT(KYBER_PRIVATE_KEY_1024, KYBER_PRIVATE_KEY_768);
    EXPECT_GT(KYBER_CIPHERTEXT_1024, KYBER_CIPHERTEXT_768);
}

TEST_F(CryptoTypesTest, DilithiumConstants) {
    EXPECT_GT(DILITHIUM_PUBLIC_KEY_2, 0);
    EXPECT_GT(DILITHIUM_PRIVATE_KEY_2, 0);
    EXPECT_GT(DILITHIUM_SIGNATURE_2, 0);

    EXPECT_GT(DILITHIUM_PUBLIC_KEY_3, DILITHIUM_PUBLIC_KEY_2);
    EXPECT_GT(DILITHIUM_PRIVATE_KEY_3, DILITHIUM_PRIVATE_KEY_2);
    EXPECT_GT(DILITHIUM_SIGNATURE_3, DILITHIUM_SIGNATURE_2);

    EXPECT_GT(DILITHIUM_PUBLIC_KEY_5, DILITHIUM_PUBLIC_KEY_3);
    EXPECT_GT(DILITHIUM_PRIVATE_KEY_5, DILITHIUM_PRIVATE_KEY_3);
    EXPECT_GT(DILITHIUM_SIGNATURE_5, DILITHIUM_SIGNATURE_3);
}

// Test type safety
TEST_F(CryptoTypesTest, TypeSafety) {
    // Result should not be copyable from failed to success
    auto failed_result = Result<int>::error("failed");
    EXPECT_THROW(Result<int>::success(failed_result.value()), std::exception);

    // bytes should work with standard algorithms
    bytes data1 = {1, 2, 3};
    bytes data2 = {4, 5, 6};

    data1.insert(data1.end(), data2.begin(), data2.end());
    EXPECT_EQ(data1, bytes({1, 2, 3, 4, 5, 6}));
}

// Test edge cases
TEST_F(CryptoTypesTest, EdgeCases) {
    // Empty bytes
    bytes empty;
    EXPECT_TRUE(empty.empty());
    EXPECT_EQ(empty.size(), 0);

    // Single byte
    bytes single = {0x42};
    EXPECT_EQ(single.size(), 1);
    EXPECT_EQ(single[0], 0x42);

    // Result with empty error message
    auto empty_error = Result<int>::error("");
    EXPECT_FALSE(empty_error);
    EXPECT_TRUE(empty_error.error().empty());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}