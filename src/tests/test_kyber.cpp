#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <vector>
#include <memory>
#include "qybersafe/kyber/kyber_kem.h"
#include "qybersafe/core/crypto_types.h"

using namespace qybersafe::kyber;
using namespace qybersafe::core;
using namespace testing;

class KyberTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate test keypairs for each security level
        auto keypair_512_result = generate_keypair(SecurityLevel::LOW);
        if (keypair_512_result.is_success()) {
            keypair_512 = std::make_unique<KeyPair>(keypair_512_result.value());
        }

        auto keypair_768_result = generate_keypair(SecurityLevel::MEDIUM);
        if (keypair_768_result.is_success()) {
            keypair_768 = std::make_unique<KeyPair>(keypair_768_result.value());
        }

        auto keypair_1024_result = generate_keypair(SecurityLevel::HIGH);
        if (keypair_1024_result.is_success()) {
            keypair_1024 = std::make_unique<KeyPair>(keypair_1024_result.value());
        }
    }

    std::unique_ptr<KeyPair> keypair_512;
    std::unique_ptr<KeyPair> keypair_768;
    std::unique_ptr<KeyPair> keypair_1024;

    static constexpr bytes test_message = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x51, 0x79, 0x62, 0x65, 0x72, 0x53, 0x61, 0x66, 0x65};
};

// Test keypair generation
TEST_F(KyberTest, KeypairGeneration) {
    // Test basic keypair generation
    auto keypair_result = generate_keypair(SecurityLevel::MEDIUM);
    ASSERT_TRUE(keypair_result.is_success());

    auto keypair = keypair_result.value();

    // Verify key sizes
    EXPECT_EQ(keypair.public_key().size(), KYBER_PUBLIC_KEY_768);
    EXPECT_EQ(keypair.private_key().size(), KYBER_PRIVATE_KEY_768);

    // Verify keys are valid
    EXPECT_TRUE(keypair.public_key().is_valid());
    EXPECT_TRUE(keypair.private_key().is_valid());

    // Test different security levels
    auto keypair_512_result = generate_keypair(SecurityLevel::LOW);
    ASSERT_TRUE(keypair_512_result.is_success());
    EXPECT_EQ(keypair_512_result.value().public_key().size(), KYBER_PUBLIC_KEY_512);
    EXPECT_EQ(keypair_512_result.value().private_key().size(), KYBER_PRIVATE_KEY_512);

    auto keypair_1024_result = generate_keypair(SecurityLevel::HIGH);
    ASSERT_TRUE(keypair_1024_result.is_success());
    EXPECT_EQ(keypair_1024_result.value().public_key().size(), KYBER_PUBLIC_KEY_1024);
    EXPECT_EQ(keypair_1024_result.value().private_key().size(), KYBER_PRIVATE_KEY_1024);
}

// Test encryption and decryption
TEST_F(KyberTest, EncryptDecrypt) {
    ASSERT_TRUE(keypair_768 != nullptr);

    // Test encryption
    auto ciphertext_result = encrypt(keypair_768->public_key(), test_message);
    ASSERT_TRUE(ciphertext_result.is_success());

    auto ciphertext = ciphertext_result.value();
    EXPECT_EQ(ciphertext.size(), KYBER_CIPHERTEXT_768);

    // Test decryption
    auto plaintext_result = decrypt(keypair_768->private_key(), ciphertext);
    ASSERT_TRUE(plaintext_result.is_success());

    EXPECT_EQ(plaintext_result.value(), test_message);
}

// Test KEM operations
TEST_F(KyberTest, KEMOperations) {
    ASSERT_TRUE(keypair_768 != nullptr);

    // Test encapsulation
    auto encap_result = encapsulate(keypair_768->public_key());
    ASSERT_TRUE(encap_result.is_success());

    auto [ciphertext, shared_secret1] = encap_result.value();
    EXPECT_EQ(ciphertext.size(), KYBER_CIPHERTEXT_768);
    EXPECT_EQ(shared_secret1.size(), 32); // Standard shared secret size

    // Test decapsulation
    auto shared_secret2_result = decapsulate(keypair_768->private_key(), ciphertext);
    ASSERT_TRUE(shared_secret2_result.is_success());

    EXPECT_EQ(shared_secret1, shared_secret2_result.value());
}

// Test invalid keys
TEST_F(KyberTest, InvalidKeys) {
    // Test with invalid public key
    bytes invalid_pub_key(100, 0x00);
    PublicKey invalid_public(invalid_pub_key);
    EXPECT_FALSE(invalid_public.is_valid());

    // Test with invalid private key
    bytes invalid_priv_key(100, 0x00);
    PrivateKey invalid_private(invalid_priv_key);
    EXPECT_FALSE(invalid_private.is_valid());

    // Test decryption with invalid key
    auto decrypt_result = decrypt(invalid_private, test_message);
    EXPECT_FALSE(decrypt_result.is_success());
}

// Test different message sizes
TEST_F(KyberTest, DifferentMessageSizes) {
    ASSERT_TRUE(keypair_768 != nullptr);

    // Test empty message
    bytes empty_message;
    auto empty_result = encrypt(keypair_768->public_key(), empty_message);
    ASSERT_TRUE(empty_result.is_success());

    auto empty_dec_result = decrypt(keypair_768->private_key(), empty_result.value());
    ASSERT_TRUE(empty_dec_result.is_success());
    EXPECT_EQ(empty_dec_result.value(), empty_message);

    // Test larger message
    bytes large_message(1000, 0x42);
    auto large_result = encrypt(keypair_768->public_key(), large_message);
    ASSER
auto keypair = qybersafe::kyber::generate_keypair();
auto ciphertext = qybersafe::kyber::enT_TRUE(large_result.is_success());

      auto large_dec_result = decrypt(keypair_768->private_key(), large_result.value());
    ASSERT_TRUE(large_dec_result.is_success());
    EXPECT_EQ(large_dec_result.value(), large_message);
}

// Test multiple encryptions with same key
TEST_F(KyberTest, MultipleEncryptions) {
    ASSERT_TRUE(keypair_768 != nullptr);

    bytes message1 = {0x01, 0x02, 0x03};
    bytes message2 = {0x04, 0x05, 0x06};

    auto ciphertext1_result = encrypt(keypair_768->public_key(), message1);
    auto ciphertext2_result = encrypt(keypair_768->public_key(), message2);

    ASSERT_TRUE(ciphertext1_result.is_success());
    ASSERT_TRUE(ciphertext2_result.is_success());

    // Ciphertexts should be different (due to randomness)
    EXPECT_NE(ciphertext1_result.value(), ciphertext2_result.value());

    // But both should decrypt correctly
    auto plaintext1_result = decrypt(keypair_768->private_key(), ciphertext1_result.value());
    auto plaintext2_result = decrypt(keypair_768->private_key(), ciphertext2_result.value());

    ASSERT_TRUE(plaintext1_result.is_success());
    ASSERT_TRUE(plaintext2_result.is_success());

    EXPECT_EQ(plaintext1_result.value(), message1);
    EXPECT_EQ(plaintext2_result.value(), message2);
}

// Test public key derivation from private key
TEST_F(KyberTest, PublicKeyDerivation) {
    ASSERT_TRUE(keypair_768 != nullptr);

    auto derived_public = keypair_768->private_key().get_public_key();
    EXPECT_EQ(derived_public.data(), keypair_768->public_key().data());
    EXPECT_TRUE(derived_public.is_valid());
}

// Test utility functions
TEST_F(KyberTest, UtilityFunctions) {
    EXPECT_GT(get_public_key_size(SecurityLevel::LOW), 0);
    EXPECT_GT(get_public_key_size(SecurityLevel::MEDIUM), 0);
    EXPECT_GT(get_public_key_size(SecurityLevel::HIGH), 0);

    EXPECT_GT(get_private_key_size(SecurityLevel::LOW), 0);
    EXPECT_GT(get_private_key_size(SecurityLevel::MEDIUM), 0);
    EXPECT_GT(get_private_key_size(SecurityLevel::HIGH), 0);

    EXPECT_GT(get_ciphertext_size(SecurityLevel::LOW), 0);
    EXPECT_GT(get_ciphertext_size(SecurityLevel::MEDIUM), 0);
    EXPECT_GT(get_ciphertext_size(SecurityLevel::HIGH), 0);

    EXPECT_GT(get_shared_secret_size(), 0);
}

// Test key consistency
TEST_F(KyberTest, KeyConsistency) {
    // Generate two keypairs and ensure they are different
    auto keypair1_result = generate_keypair(SecurityLevel::MEDIUM);
    auto keypair2_result = generate_keypair(SecurityLevel::MEDIUM);

    ASSERT_TRUE(keypair1_result.is_success());
    ASSERT_TRUE(keypair2_result.is_success());

    auto keypair1 = keypair1_result.value();
    auto keypair2 = keypair2_result.value();

    // Keys should be different
    EXPECT_NE(keypair1.public_key().data(), keypair2.public_key().data());
    EXPECT_NE(keypair1.private_key().data(), keypair2.private_key().data());

    // But all should be valid
    EXPECT_TRUE(keypair1.public_key().is_valid());
    EXPECT_TRUE(keypair1.private_key().is_valid());
    EXPECT_TRUE(keypair2.public_key().is_valid());
    EXPECT_TRUE(keypair2.private_key().is_valid());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}