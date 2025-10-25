#include <gtest/gtest.h>
#include "qybersafe/dilithium/dilithium_sig.h"
#include "qybersafe/core/secure_random.h"
#include <vector>

using namespace qybersafe::dilithium;
using namespace qybersafe::core;

class DilithiumTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate test key pairs for each security level
        keypair_2 = generate_keypair(SecurityLevel::Dilithium2);
        keypair_3 = generate_keypair(SecurityLevel::Dilithium3);
        keypair_5 = generate_keypair(SecurityLevel::Dilithium5);

        test_message = bytes{'H', 'e', 'l', 'l', 'o', ' ', 'D', 'i', 'l', 'i', 't', 'h', 'i', 'u', 'm'};
    }

    SigningKeyPair keypair_2, keypair_3, keypair_5;
    bytes test_message;
};

TEST_F(DilithiumTest, KeyGeneration) {
    // Test Dilithium2
    EXPECT_TRUE(keypair_2.verifying_key().is_valid());
    EXPECT_TRUE(keypair_2.signing_key().is_valid());
    EXPECT_EQ(keypair_2.verifying_key().size(), DILITHIUM_PUBLIC_KEY_2);
    EXPECT_EQ(keypair_2.signing_key().size(), DILITHIUM_PRIVATE_KEY_2);

    // Test Dilithium3
    EXPECT_TRUE(keypair_3.verifying_key().is_valid());
    EXPECT_TRUE(keypair_3.signing_key().is_valid());
    EXPECT_EQ(keypair_3.verifying_key().size(), DILITHIUM_PUBLIC_KEY_3);
    EXPECT_EQ(keypair_3.signing_key().size(), DILITHIUM_PRIVATE_KEY_3);

    // Test Dilithium5
    EXPECT_TRUE(keypair_5.verifying_key().is_valid());
    EXPECT_TRUE(keypair_5.signing_key().is_valid());
    EXPECT_EQ(keypair_5.verifying_key().size(), DILITHIUM_PUBLIC_KEY_5);
    EXPECT_EQ(keypair_5.signing_key().size(), DILITHIUM_PRIVATE_KEY_5);
}

TEST_F(DilithiumTest, PublicKeyExtraction) {
    VerifyingKey extracted_vk_2 = keypair_2.signing_key().get_verifying_key();
    VerifyingKey extracted_vk_3 = keypair_3.signing_key().get_verifying_key();
    VerifyingKey extracted_vk_5 = keypair_5.signing_key().get_verifying_key();

    // Compare with original verifying keys
    EXPECT_EQ(extracted_vk_2.data(), keypair_2.verifying_key().data());
    EXPECT_EQ(extracted_vk_3.data(), keypair_3.verifying_key().data());
    EXPECT_EQ(extracted_vk_5.data(), keypair_5.verifying_key().data());
}

TEST_F(DilithiumTest, SignAndVerify) {
    // Test Dilithium2
    auto signature_result_2 = sign(keypair_2.signing_key(), test_message);
    ASSERT_TRUE(signature_result_2.is_success());
    bytes signature_2 = signature_result_2.value();
    EXPECT_EQ(signature_2.size(), DILITHIUM_SIGNATURE_2);
    EXPECT_TRUE(verify(keypair_2.verifying_key(), test_message, signature_2));

    // Test Dilithium3
    auto signature_result_3 = sign(keypair_3.signing_key(), test_message);
    ASSERT_TRUE(signature_result_3.is_success());
    bytes signature_3 = signature_result_3.value();
    EXPECT_EQ(signature_3.size(), DILITHIUM_SIGNATURE_3);
    EXPECT_TRUE(verify(keypair_3.verifying_key(), test_message, signature_3));

    // Test Dilithium5
    auto signature_result_5 = sign(keypair_5.signing_key(), test_message);
    ASSERT_TRUE(signature_result_5.is_success());
    bytes signature_5 = signature_result_5.value();
    EXPECT_EQ(signature_5.size(), DILITHIUM_SIGNATURE_5);
    EXPECT_TRUE(verify(keypair_5.verifying_key(), test_message, signature_5));
}

TEST_F(DilithiumTest, VerifyInvalidSignature) {
    // Generate a valid signature
    auto signature_result = sign(keypair_3.signing_key(), test_message);
    ASSERT_TRUE(signature_result.is_success());
    bytes signature = signature_result.value();

    // Modify the signature to make it invalid
    signature[0] ^= 0xFF;

    // Verification should fail
    EXPECT_FALSE(verify(keypair_3.verifying_key(), test_message, signature));
}

TEST_F(DilithiumTest, VerifyWrongMessage) {
    // Generate a valid signature
    auto signature_result = sign(keypair_3.signing_key(), test_message);
    ASSERT_TRUE(signature_result.is_success());
    bytes signature = signature_result.value();

    // Modify the message
    bytes wrong_message = {'W', 'r', 'o', 'n', 'g', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};

    // Verification should fail
    EXPECT_FALSE(verify(keypair_3.verifying_key(), wrong_message, signature));
}

TEST_F(DilithiumTest, VerifyWrongKey) {
    // Generate a signature with one key pair
    auto signature_result = sign(keypair_3.signing_key(), test_message);
    ASSERT_TRUE(signature_result.is_success());
    bytes signature = signature_result.value();

    // Try to verify with a different key pair
    EXPECT_FALSE(verify(keypair_2.verifying_key(), test_message, signature));
}

TEST_F(DilithiumTest, EmptyMessage) {
    bytes empty_message;

    auto signature_result = sign(keypair_3.signing_key(), empty_message);
    ASSERT_TRUE(signature_result.is_success());
    bytes signature = signature_result.value();

    EXPECT_TRUE(verify(keypair_3.verifying_key(), empty_message, signature));
}

TEST_F(DilithiumTest, LargeMessage) {
    // Create a 1KB message
    bytes large_message(1024, 0x42);

    auto signature_result = sign(keypair_3.signing_key(), large_message);
    ASSERT_TRUE(signature_result.is_success());
    bytes signature = signature_result.value();

    EXPECT_TRUE(verify(keypair_3.verifying_key(), large_message, signature));
}

TEST_F(DilithiumTest, MultipleSignatures) {
    // Sign the same message multiple times
    auto sig1_result = sign(keypair_3.signing_key(), test_message);
    auto sig2_result = sign(keypair_3.signing_key(), test_message);

    ASSERT_TRUE(sig1_result.is_success());
    ASSERT_TRUE(sig2_result.is_success());

    bytes sig1 = sig1_result.value();
    bytes sig2 = sig2_result.value();

    // Both signatures should verify
    EXPECT_TRUE(verify(keypair_3.verifying_key(), test_message, sig1));
    EXPECT_TRUE(verify(keypair_3.verifying_key(), test_message, sig2));

    // Signatures should be different (due to randomness)
    EXPECT_NE(sig1, sig2);
}

TEST_F(DilithiumTest, UtilityFunctions) {
    // Test size utility functions
    EXPECT_EQ(get_verifying_key_size(SecurityLevel::Dilithium2), DILITHIUM_PUBLIC_KEY_2);
    EXPECT_EQ(get_verifying_key_size(SecurityLevel::Dilithium3), DILITHIUM_PUBLIC_KEY_3);
    EXPECT_EQ(get_verifying_key_size(SecurityLevel::Dilithium5), DILITHIUM_PUBLIC_KEY_5);

    EXPECT_EQ(get_signing_key_size(SecurityLevel::Dilithium2), DILITHIUM_PRIVATE_KEY_2);
    EXPECT_EQ(get_signing_key_size(SecurityLevel::Dilithium3), DILITHIUM_PRIVATE_KEY_3);
    EXPECT_EQ(get_signing_key_size(SecurityLevel::Dilithium5), DILITHIUM_PRIVATE_KEY_5);

    EXPECT_EQ(get_signature_size(SecurityLevel::Dilithium2), DILITHIUM_SIGNATURE_2);
    EXPECT_EQ(get_signature_size(SecurityLevel::Dilithium3), DILITHIUM_SIGNATURE_3);
    EXPECT_EQ(get_signature_size(SecurityLevel::Dilithium5), DILITHIUM_SIGNATURE_5);

    // Test message hashing
    bytes hash = hash_message(test_message);
    EXPECT_EQ(hash.size(), 32); // SHA3-256 output size
}

TEST_F(DilithiumTest, ErrorHandling) {
    // Test with invalid signing key
    SigningKey invalid_key(bytes{0x00, 0x01, 0x02});
    EXPECT_FALSE(invalid_key.is_valid());

    auto signature_result = sign(invalid_key, test_message);
    EXPECT_FALSE(signature_result.is_success());

    // Test with invalid verifying key
    VerifyingKey invalid_vk(bytes{0x00, 0x01, 0x02});
    EXPECT_FALSE(invalid_vk.is_valid());

    // This should return false rather than throw
    EXPECT_FALSE(verify(invalid_vk, test_message, bytes{0x00, 0x01}));
}

TEST_F(DilithiumTest, KeySerialization) {
    // Test that we can reconstruct keys from their data
    bytes vk_data = keypair_3.verifying_key().data();
    bytes sk_data = keypair_3.signing_key().data();

    VerifyingKey reconstructed_vk(vk_data);
    SigningKey reconstructed_sk(sk_data);

    EXPECT_TRUE(reconstructed_vk.is_valid());
    EXPECT_TRUE(reconstructed_sk.is_valid());
    EXPECT_EQ(reconstructed_vk.data(), keypair_3.verifying_key().data());
    EXPECT_EQ(reconstructed_sk.data(), keypair_3.signing_key().data());

    // Test that reconstructed keys work for signing and verification
    auto signature_result = sign(reconstructed_sk, test_message);
    ASSERT_TRUE(signature_result.is_success());
    bytes signature = signature_result.value();

    EXPECT_TRUE(verify(reconstructed_vk, test_message, signature));
}