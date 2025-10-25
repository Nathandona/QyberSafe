#include <gtest/gtest.h>
#include "qybersafe/sphincsplus/sphincsplus_sig.h"
#include "qybersafe/core/secure_random.h"
#include <vector>

using namespace qybersafe::sphincsplus;
using namespace qybersafe::core;

class SphincsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate test key pairs for each security level
        keypair_128 = generate_keypair(SecurityLevel::SPHINCS128);
        keypair_192 = generate_keypair(SecurityLevel::SPHINCS192);
        keypair_256 = generate_keypair(SecurityLevel::SPHINCS256);

        test_message = bytes{'H', 'e', 'l', 'l', 'o', ' ', 'S', 'P', 'H', 'I', 'N', 'C', 'S', '+'};
    }

    SPHINCSKeyPair keypair_128, keypair_192, keypair_256;
    bytes test_message;
};

TEST_F(SphincsTest, KeyGeneration) {
    // Test SPHINCS128
    EXPECT_TRUE(keypair_128.public_key().is_valid());
    EXPECT_TRUE(keypair_128.private_key().is_valid());
    EXPECT_EQ(keypair_128.public_key().size(), 32);
    EXPECT_EQ(keypair_128.private_key().size(), 64);

    // Test SPHINCS192
    EXPECT_TRUE(keypair_192.public_key().is_valid());
    EXPECT_TRUE(keypair_192.private_key().is_valid());
    EXPECT_EQ(keypair_192.public_key().size(), 48);
    EXPECT_EQ(keypair_192.private_key().size(), 96);

    // Test SPHINCS256
    EXPECT_TRUE(keypair_256.public_key().is_valid());
    EXPECT_TRUE(keypair_256.private_key().is_valid());
    EXPECT_EQ(keypair_256.public_key().size(), 64);
    EXPECT_EQ(keypair_256.private_key().size(), 128);
}

TEST_F(SphincsTest, PublicKeyExtraction) {
    SPHINCSPublicKey extracted_pk_128 = keypair_128.private_key().get_public_key();
    SPHINCSPublicKey extracted_pk_192 = keypair_192.private_key().get_public_key();
    SPHINCSPublicKey extracted_pk_256 = keypair_256.private_key().get_public_key();

    // Compare with original public keys
    EXPECT_EQ(extracted_pk_128.data(), keypair_128.public_key().data());
    EXPECT_EQ(extracted_pk_192.data(), keypair_192.public_key().data());
    EXPECT_EQ(extracted_pk_256.data(), keypair_256.public_key().data());
}

TEST_F(SphincsTest, SignAndVerify) {
    // Test SPHINCS128
    bytes signature_128 = sign(keypair_128.private_key(), test_message);
    EXPECT_FALSE(signature_128.empty());
    EXPECT_TRUE(verify(keypair_128.public_key(), test_message, signature_128));

    // Test SPHINCS192
    bytes signature_192 = sign(keypair_192.private_key(), test_message);
    EXPECT_FALSE(signature_192.empty());
    EXPECT_TRUE(verify(keypair_192.public_key(), test_message, signature_192));

    // Test SPHINCS256
    bytes signature_256 = sign(keypair_256.private_key(), test_message);
    EXPECT_FALSE(signature_256.empty());
    EXPECT_TRUE(verify(keypair_256.public_key(), test_message, signature_256));
}

TEST_F(SphincsTest, VerifyInvalidSignature) {
    // Generate a valid signature
    bytes signature = sign(keypair_192.private_key(), test_message);
    EXPECT_FALSE(signature.empty());

    // Modify the signature to make it invalid
    if (!signature.empty()) {
        signature[0] ^= 0xFF;
    }

    // Verification should fail
    EXPECT_FALSE(verify(keypair_192.public_key(), test_message, signature));
}

TEST_F(SphincsTest, VerifyWrongMessage) {
    // Generate a valid signature
    bytes signature = sign(keypair_192.private_key(), test_message);
    EXPECT_FALSE(signature.empty());

    // Modify the message
    bytes wrong_message = {'W', 'r', 'o', 'n', 'g', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};

    // Verification should fail
    EXPECT_FALSE(verify(keypair_192.public_key(), wrong_message, signature));
}

TEST_F(SphincsTest, VerifyWrongKey) {
    // Generate a signature with one key pair
    bytes signature = sign(keypair_192.private_key(), test_message);
    EXPECT_FALSE(signature.empty());

    // Try to verify with a different key pair
    EXPECT_FALSE(verify(keypair_128.public_key(), test_message, signature));
}

TEST_F(SphincsTest, EmptyMessage) {
    bytes empty_message;

    bytes signature = sign(keypair_192.private_key(), empty_message);
    EXPECT_FALSE(signature.empty());

    EXPECT_TRUE(verify(keypair_192.public_key(), empty_message, signature));
}

TEST_F(SphincsTest, LargeMessage) {
    // Create a 1KB message
    bytes large_message(1024, 0x42);

    bytes signature = sign(keypair_192.private_key(), large_message);
    EXPECT_FALSE(signature.empty());

    EXPECT_TRUE(verify(keypair_192.public_key(), large_message, signature));
}

TEST_F(SphincsTest, MultipleSignatures) {
    // Sign the same message multiple times
    bytes sig1 = sign(keypair_192.private_key(), test_message);
    bytes sig2 = sign(keypair_192.private_key(), test_message);

    EXPECT_FALSE(sig1.empty());
    EXPECT_FALSE(sig2.empty());

    // Both signatures should verify
    EXPECT_TRUE(verify(keypair_192.public_key(), test_message, sig1));
    EXPECT_TRUE(verify(keypair_192.public_key(), test_message, sig2));

    // Signatures should be different (due to randomness in SPHINCS+)
    EXPECT_NE(sig1, sig2);
}

TEST_F(SphincsTest, KeySerialization) {
    // Test that we can reconstruct keys from their data
    bytes pk_data = keypair_192.public_key().data();
    bytes sk_data = keypair_192.private_key().data();

    SPHINCSPublicKey reconstructed_pk(pk_data);
    SPHINCSPrivateKey reconstructed_sk(sk_data);

    EXPECT_TRUE(reconstructed_pk.is_valid());
    EXPECT_TRUE(reconstructed_sk.is_valid());
    EXPECT_EQ(reconstructed_pk.data(), keypair_192.public_key().data());
    EXPECT_EQ(reconstructed_sk.data(), keypair_192.private_key().data());

    // Test that reconstructed keys work for signing and verification
    bytes signature = sign(reconstructed_sk, test_message);
    EXPECT_FALSE(signature.empty());

    EXPECT_TRUE(verify(reconstructed_pk, test_message, signature));
}

TEST_F(SphincsTest, ErrorHandling) {
    // Test with invalid private key
    SPHINCSPrivateKey invalid_key(bytes{0x00, 0x01, 0x02});
    EXPECT_FALSE(invalid_key.is_valid());

    EXPECT_THROW(sign(invalid_key, test_message), std::invalid_argument);

    // Test with invalid public key
    SPHINCSPublicKey invalid_pk(bytes{0x00, 0x01, 0x02});
    EXPECT_FALSE(invalid_pk.is_valid());

    // This should return false rather than throw
    EXPECT_FALSE(verify(invalid_pk, test_message, bytes{0x00, 0x01}));
}

TEST_F(SphincsTest, SignatureSizeVariations) {
    // Test that signatures have reasonable sizes
    bytes sig_128 = sign(keypair_128.private_key(), test_message);
    bytes sig_192 = sign(keypair_192.private_key(), test_message);
    bytes sig_256 = sign(keypair_256.private_key(), test_message);

    // Higher security levels should have larger signatures
    EXPECT_TRUE(sig_128.size() <= sig_256.size());
    EXPECT_TRUE(sig_192.size() <= sig_256.size());

    // All should be non-empty
    EXPECT_FALSE(sig_128.empty());
    EXPECT_FALSE(sig_192.empty());
    EXPECT_FALSE(sig_256.empty());
}

TEST_F(SphincsTest, OneTimeKeyBehavior) {
    // SPHINCS+ is stateful, but our implementation should handle multiple signatures
    // This is more of a conceptual test to ensure the implementation doesn't break

    for (int i = 0; i < 5; ++i) {
        bytes message = {'T', 'e', 's', 't', ' ', static_cast<uint8_t>(i)};
        bytes signature = sign(keypair_128.private_key(), message);
        EXPECT_FALSE(signature.empty());
        EXPECT_TRUE(verify(keypair_128.public_key(), message, signature));
    }
}