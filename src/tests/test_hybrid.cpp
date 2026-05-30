#include <gtest/gtest.h>

#include <vector>

#include "qybersafe/core/crypto_types.h"
#include "qybersafe/hybrid/hybrid_encryption.h"

using namespace qybersafe::hybrid;
using namespace qybersafe::core;

namespace {
bytes sample_message() {
    return {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x79,
            0x62, 0x72, 0x69, 0x64};  // "hello hybrid"
}
}  // namespace

TEST(HybridTest, KeypairValidity) {
    const HybridKeyPair kp = generate_hybrid_keypair();
    EXPECT_TRUE(kp.public_key().is_valid());
    EXPECT_TRUE(kp.private_key().is_valid());
    EXPECT_EQ(kp.public_key().classical_key().size(), 32u);  // X25519
    EXPECT_TRUE(kp.public_key().pq_key().is_valid());        // ML-KEM-768
}

TEST(HybridTest, EncryptDecryptRoundtrip) {
    const HybridKeyPair kp = generate_hybrid_keypair();
    const bytes message = sample_message();
    const bytes envelope = hybrid_encrypt(kp.public_key(), message);
    const bytes recovered = hybrid_decrypt(kp.private_key(), envelope);
    EXPECT_EQ(recovered, message);
}

TEST(HybridTest, EdgeCaseMessageSizes) {
    const HybridKeyPair kp = generate_hybrid_keypair();

    const bytes empty;
    EXPECT_EQ(hybrid_decrypt(kp.private_key(),
                             hybrid_encrypt(kp.public_key(), empty)),
              empty);

    const bytes large(8192, 0x5a);
    EXPECT_EQ(hybrid_decrypt(kp.private_key(),
                             hybrid_encrypt(kp.public_key(), large)),
              large);
}

TEST(HybridTest, EncryptionIsProbabilistic) {
    const HybridKeyPair kp = generate_hybrid_keypair();
    const bytes message = sample_message();
    EXPECT_NE(hybrid_encrypt(kp.public_key(), message),
              hybrid_encrypt(kp.public_key(), message));
}

TEST(HybridTest, WrongKeyFails) {
    const HybridKeyPair kp = generate_hybrid_keypair();
    const HybridKeyPair other = generate_hybrid_keypair();
    const bytes envelope = hybrid_encrypt(kp.public_key(), sample_message());
    EXPECT_THROW(hybrid_decrypt(other.private_key(), envelope), std::exception);
}

TEST(HybridTest, CorruptionIsDetected) {
    const HybridKeyPair kp = generate_hybrid_keypair();
    bytes envelope = hybrid_encrypt(kp.public_key(), sample_message());
    envelope.back() ^= 0xFF;  // flip a ciphertext byte
    EXPECT_THROW(hybrid_decrypt(kp.private_key(), envelope), std::exception);
}

TEST(HybridTest, KeySerializationRoundtrip) {
    const HybridKeyPair kp = generate_hybrid_keypair();

    const HybridPublicKey pub(kp.public_key().data());
    const HybridPrivateKey priv(kp.private_key().data());

    EXPECT_EQ(pub.classical_key(), kp.public_key().classical_key());
    EXPECT_EQ(pub.pq_key().data(), kp.public_key().pq_key().data());

    // Keys reconstructed from their serialized form still interoperate.
    const bytes envelope = hybrid_encrypt(pub, sample_message());
    EXPECT_EQ(hybrid_decrypt(priv, envelope), sample_message());
}

TEST(HybridTest, DerivedPublicKeyMatches) {
    const HybridKeyPair kp = generate_hybrid_keypair();
    const HybridPublicKey derived = kp.private_key().get_public_key();
    EXPECT_EQ(derived.data(), kp.public_key().data());
}

TEST(HybridTest, RejectsMalformedEnvelope) {
    const HybridKeyPair kp = generate_hybrid_keypair();
    EXPECT_THROW(hybrid_decrypt(kp.private_key(), bytes{0x00, 0x01, 0x02}),
                 std::exception);
}
