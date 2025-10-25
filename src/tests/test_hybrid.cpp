#include <gtest/gtest.h>
#include "qybersafe/hybrid/hybrid_encryption.h"
#include "qybersafe/core/secure_random.h"
#include <vector>

using namespace qybersafe::hybrid;
using namespace qybersafe::core;

class HybridTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate test key pair
        keypair = generate_hybrid_keypair();

        test_message = bytes{'H', 'e', 'l', 'l', 'o', ' ', 'H', 'y', 'b', 'r', 'i', 'd', ' ', 'E', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n'};
    }

    HybridKeyPair keypair;
    bytes test_message;
};

TEST_F(HybridTest, KeyGeneration) {
    // Test that both public and private keys are valid
    EXPECT_TRUE(keypair.public_key().is_valid());
    EXPECT_TRUE(keypair.private_key().is_valid());

    // Test that both PQC and classical components are present
    EXPECT_TRUE(keypair.public_key().pq_key().is_valid());
    EXPECT_FALSE(keypair.public_key().classical_key().empty());

    EXPECT_TRUE(keypair.private_key().pq_key().is_valid());
    EXPECT_FALSE(keypair.private_key().classical_key().empty());
}

TEST_F(HybridTest, PublicKeyExtraction) {
    HybridPublicKey extracted_pk = keypair.private_key().get_public_key();

    // Compare with original public key
    EXPECT_EQ(extracted_pk.data(), keypair.public_key().data());
    EXPECT_EQ(extracted_pk.pq_key().data(), keypair.public_key().pq_key().data());
    EXPECT_EQ(extracted_pk.classical_key(), keypair.public_key().classical_key());
}

TEST_F(HybridTest, EncryptAndDecrypt) {
    // Encrypt the message
    bytes ciphertext = hybrid_encrypt(keypair.public_key(), test_message);
    EXPECT_FALSE(ciphertext.empty());

    // Decrypt the message
    bytes decrypted_message = hybrid_decrypt(keypair.private_key(), ciphertext);

    // Verify that the decrypted message matches the original
    EXPECT_EQ(decrypted_message, test_message);
}

TEST_F(HybridTest, EncryptWithWrongKey) {
    // Generate another key pair
    HybridKeyPair wrong_keypair = generate_hybrid_keypair();

    // Encrypt with one key, try to decrypt with another
    bytes ciphertext = hybrid_encrypt(keypair.public_key(), test_message);

    // This should throw an exception due to authentication failure
    EXPECT_THROW(hybrid_decrypt(wrong_keypair.private_key(), ciphertext), std::runtime_error);
}

TEST_F(HybridTest, EmptyMessage) {
    bytes empty_message;

    // Encrypt empty message
    bytes ciphertext = hybrid_encrypt(keypair.public_key(), empty_message);
    EXPECT_FALSE(ciphertext.empty());

    // Decrypt empty message
    bytes decrypted_message = hybrid_decrypt(keypair.private_key(), ciphertext);

    // Verify that the decrypted message matches the original
    EXPECT_EQ(decrypted_message, empty_message);
}

TEST_F(HybridTest, LargeMessage) {
    // Create a 10KB message
    bytes large_message(10240, 0x42);

    // Encrypt large message
    bytes ciphertext = hybrid_encrypt(keypair.public_key(), large_message);
    EXPECT_FALSE(ciphertext.empty());

    // Decrypt large message
    bytes decrypted_message = hybrid_decrypt(keypair.private_key(), ciphertext);

    // Verify that the decrypted message matches the original
    EXPECT_EQ(decrypted_message, large_message);
}

TEST_F(HybridTest, MultipleEncryptions) {
    // Encrypt the same message multiple times
    bytes ciphertext1 = hybrid_encrypt(keypair.public_key(), test_message);
    bytes ciphertext2 = hybrid_encrypt(keypair.public_key(), test_message);

    // Both ciphertexts should be different (due to random IVs)
    EXPECT_NE(ciphertext1, ciphertext2);

    // Both should decrypt correctly
    bytes decrypted1 = hybrid_decrypt(keypair.private_key(), ciphertext1);
    bytes decrypted2 = hybrid_decrypt(keypair.private_key(), ciphertext2);

    EXPECT_EQ(decrypted1, test_message);
    EXPECT_EQ(decrypted2, test_message);
}

TEST_F(HybridTest, KeySerialization) {
    // Test that we can reconstruct keys from their data
    bytes pk_data = keypair.public_key().data();
    bytes sk_data = keypair.private_key().data();

    HybridPublicKey reconstructed_pk(pk_data);
    HybridPrivateKey reconstructed_sk(sk_data);

    EXPECT_TRUE(reconstructed_pk.is_valid());
    EXPECT_TRUE(reconstructed_sk.is_valid());
    EXPECT_EQ(reconstructed_pk.data(), keypair.public_key().data());
    EXPECT_EQ(reconstructed_sk.data(), keypair.private_key().data());

    // Test that reconstructed keys work for encryption and decryption
    bytes ciphertext = hybrid_encrypt(reconstructed_pk, test_message);
    EXPECT_FALSE(ciphertext.empty());

    bytes decrypted_message = hybrid_decrypt(reconstructed_sk, ciphertext);
    EXPECT_EQ(decrypted_message, test_message);
}

TEST_F(HybridTest, ErrorHandling) {
    // Test with invalid public key
    HybridPublicKey invalid_pk(kyber::PublicKey(bytes{0x00, 0x01}), bytes{0x02});
    EXPECT_FALSE(invalid_pk.is_valid());

    EXPECT_THROW(hybrid_encrypt(invalid_pk, test_message), std::invalid_argument);

    // Test with invalid private key
    HybridPrivateKey invalid_sk(kyber::PrivateKey(bytes{0x00, 0x01}), bytes{0x02});
    EXPECT_FALSE(invalid_sk.is_valid());

    EXPECT_THROW(hybrid_decrypt(invalid_sk, bytes{0x00, 0x01}), std::invalid_argument);

    // Test with invalid ciphertext
    bytes invalid_ciphertext = {0x00, 0x01, 0x02};

    EXPECT_THROW(hybrid_decrypt(keypair.private_key(), invalid_ciphertext), std::invalid_argument);
}

TEST_F(HybridTest, CiphertextStructure) {
    bytes ciphertext = hybrid_encrypt(keypair.public_key(), test_message);

    // Ciphertext should have a minimum structure:
    // 4 bytes for PQ encrypted key length
    // PQ encrypted key data
    // 12 bytes for IV
    // 16 bytes for authentication tag
    // Classical ciphertext data
    EXPECT_GT(ciphertext.size(), 4 + 12 + 16);

    // Verify structure by parsing length field
    size_t pq_size = (static_cast<size_t>(ciphertext[0]) << 24) |
                    (static_cast<size_t>(ciphertext[1]) << 16) |
                    (static_cast<size_t>(ciphertext[2]) << 8) |
                    static_cast<size_t>(ciphertext[3]);

    EXPECT_GT(pq_size, 0);
    EXPECT_EQ(ciphertext.size(), 4 + pq_size + 12 + 16 + (ciphertext.size() - (4 + pq_size + 12 + 16)));
}

TEST_F(HybridTest, TamperResistance) {
    bytes ciphertext = hybrid_encrypt(keypair.public_key(), test_message);

    // Tamper with ciphertext
    bytes tampered_ciphertext = ciphertext;
    tampered_ciphertext[4] ^= 0xFF; // Modify first byte of PQ encrypted key

    // Decryption should fail
    EXPECT_THROW(hybrid_decrypt(keypair.private_key(), tampered_ciphertext), std::runtime_error);

    // Tamper with IV
    tampered_ciphertext = ciphertext;
    size_t pq_size = (static_cast<size_t>(ciphertext[0]) << 24) |
                    (static_cast<size_t>(ciphertext[1]) << 16) |
                    (static_cast<size_t>(ciphertext[2]) << 8) |
                    static_cast<size_t>(ciphertext[3]);
    size_t iv_offset = 4 + pq_size;
    if (iv_offset < ciphertext.size()) {
        tampered_ciphertext[iv_offset] ^= 0xFF;
        EXPECT_THROW(hybrid_decrypt(keypair.private_key(), tampered_ciphertext), std::runtime_error);
    }

    // Tamper with authentication tag
    tampered_ciphertext = ciphertext;
    size_t tag_offset = 4 + pq_size + 12;
    if (tag_offset < ciphertext.size()) {
        tampered_ciphertext[tag_offset] ^= 0xFF;
        EXPECT_THROW(hybrid_decrypt(keypair.private_key(), tampered_ciphertext), std::runtime_error);
    }

    // Tamper with ciphertext data
    tampered_ciphertext = ciphertext;
    size_t data_offset = 4 + pq_size + 12 + 16;
    if (data_offset < ciphertext.size()) {
        tampered_ciphertext[data_offset] ^= 0xFF;
        EXPECT_THROW(hybrid_decrypt(keypair.private_key(), tampered_ciphertext), std::runtime_error);
    }
}

TEST_F(HybridTest, KeyPairConsistency) {
    // Generate multiple key pairs and ensure they're different
    HybridKeyPair keypair1 = generate_hybrid_keypair();
    HybridKeyPair keypair2 = generate_hybrid_keypair();

    EXPECT_NE(keypair1.public_key().data(), keypair2.public_key().data());
    EXPECT_NE(keypair1.private_key().data(), keypair2.private_key().data());

    // Keys should only work with their corresponding pairs
    bytes ciphertext1 = hybrid_encrypt(keypair1.public_key(), test_message);
    bytes ciphertext2 = hybrid_encrypt(keypair2.public_key(), test_message);

    EXPECT_EQ(hybrid_decrypt(keypair1.private_key(), ciphertext1), test_message);
    EXPECT_EQ(hybrid_decrypt(keypair2.private_key(), ciphertext2), test_message);

    // Cross decryption should fail
    EXPECT_THROW(hybrid_decrypt(keypair1.private_key(), ciphertext2), std::runtime_error);
    EXPECT_THROW(hybrid_decrypt(keypair2.private_key(), ciphertext1), std::runtime_error);
}