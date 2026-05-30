#include <gtest/gtest.h>

#include <vector>

#include "qybersafe/core/crypto_types.h"
#include "qybersafe/kyber/kyber_kem.h"

using namespace qybersafe::kyber;
using namespace qybersafe::core;

namespace {
bytes sample_message() {
    // "Hello QyberSafe"
    return {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x51, 0x79,
            0x62, 0x65, 0x72, 0x53, 0x61, 0x66, 0x65};
}
}  // namespace

// Key generation produces keys of the exact ML-KEM sizes for each level.
TEST(KyberTest, KeypairSizes) {
    const KeyPair kp512 = generate_keypair(SecurityLevel::KYBER_512);
    EXPECT_EQ(kp512.public_key().size(), KYBER_PUBLIC_KEY_512);
    EXPECT_EQ(kp512.private_key().size(), KYBER_PRIVATE_KEY_512);

    const KeyPair kp768 = generate_keypair(SecurityLevel::KYBER_768);
    EXPECT_EQ(kp768.public_key().size(), KYBER_PUBLIC_KEY_768);
    EXPECT_EQ(kp768.private_key().size(), KYBER_PRIVATE_KEY_768);

    const KeyPair kp1024 = generate_keypair(SecurityLevel::KYBER_1024);
    EXPECT_EQ(kp1024.public_key().size(), KYBER_PUBLIC_KEY_1024);
    EXPECT_EQ(kp1024.private_key().size(), KYBER_PRIVATE_KEY_1024);

    EXPECT_TRUE(kp768.public_key().is_valid());
    EXPECT_TRUE(kp768.private_key().is_valid());
}

// Legacy LOW/MEDIUM/HIGH aliases map to 512/768/1024.
TEST(KyberTest, LegacyLevelAliases) {
    EXPECT_EQ(generate_keypair(SecurityLevel::LOW).public_key().size(),
              KYBER_PUBLIC_KEY_512);
    EXPECT_EQ(generate_keypair(SecurityLevel::MEDIUM).public_key().size(),
              KYBER_PUBLIC_KEY_768);
    EXPECT_EQ(generate_keypair(SecurityLevel::HIGH).public_key().size(),
              KYBER_PUBLIC_KEY_1024);
}

// Two key generations yield distinct keys.
TEST(KyberTest, KeysAreDistinct) {
    const KeyPair a = generate_keypair(SecurityLevel::KYBER_768);
    const KeyPair b = generate_keypair(SecurityLevel::KYBER_768);
    EXPECT_NE(a.public_key().data(), b.public_key().data());
    EXPECT_NE(a.private_key().data(), b.private_key().data());
}

// Raw KEM: encapsulate then decapsulate recovers the same shared secret.
TEST(KyberTest, EncapsulateDecapsulateRoundtrip) {
    const KeyPair kp = generate_keypair(SecurityLevel::KYBER_768);

    auto encaps = encapsulate(kp.public_key());
    ASSERT_TRUE(encaps.is_success());
    const auto& [ct, ss_sender] = encaps.value();
    EXPECT_EQ(ct.size(), KYBER_CIPHERTEXT_768);
    EXPECT_EQ(ss_sender.size(), get_shared_secret_size());

    auto decaps = decapsulate(kp.private_key(), ct);
    ASSERT_TRUE(decaps.is_success());
    EXPECT_EQ(decaps.value(), ss_sender);
}

// KEM-DEM convenience encryption round-trips arbitrary plaintext.
TEST(KyberTest, EncryptDecryptRoundtrip) {
    const KeyPair kp = generate_keypair(SecurityLevel::KYBER_768);
    const bytes message = sample_message();

    const bytes envelope = encrypt(kp.public_key(), message);
    // kem_ct + nonce(12) + tag(16) + aes_ct(len(message))
    EXPECT_EQ(envelope.size(), KYBER_CIPHERTEXT_768 + 12 + 16 + message.size());

    auto decrypted = decrypt(kp.private_key(), envelope);
    ASSERT_TRUE(decrypted.is_success());
    EXPECT_EQ(decrypted.value(), message);
}

// Encryption is probabilistic: same input, different envelopes.
TEST(KyberTest, EncryptionIsProbabilistic) {
    const KeyPair kp = generate_keypair(SecurityLevel::KYBER_768);
    const bytes message = sample_message();
    EXPECT_NE(encrypt(kp.public_key(), message),
              encrypt(kp.public_key(), message));
}

// Decryption with the wrong private key fails (ML-KEM implicit rejection plus
// the GCM tag check).
TEST(KyberTest, WrongKeyFails) {
    const KeyPair kp = generate_keypair(SecurityLevel::KYBER_768);
    const KeyPair other = generate_keypair(SecurityLevel::KYBER_768);
    const bytes envelope = encrypt(kp.public_key(), sample_message());

    EXPECT_FALSE(decrypt(other.private_key(), envelope).is_success());
}

// A single flipped byte is detected by the AEAD tag.
TEST(KyberTest, CorruptionIsDetected) {
    const KeyPair kp = generate_keypair(SecurityLevel::KYBER_768);
    bytes envelope = encrypt(kp.public_key(), sample_message());
    envelope[0] ^= 0xFF;
    EXPECT_FALSE(decrypt(kp.private_key(), envelope).is_success());
}

// Empty and large plaintexts both round-trip.
TEST(KyberTest, EdgeCaseMessageSizes) {
    const KeyPair kp = generate_keypair(SecurityLevel::KYBER_768);

    const bytes empty;
    auto e = decrypt(kp.private_key(), encrypt(kp.public_key(), empty));
    ASSERT_TRUE(e.is_success());
    EXPECT_EQ(e.value(), empty);

    const bytes large(4096, 0x42);
    auto l = decrypt(kp.private_key(), encrypt(kp.public_key(), large));
    ASSERT_TRUE(l.is_success());
    EXPECT_EQ(l.value(), large);
}

// Invalid keys are rejected.
TEST(KyberTest, InvalidKeys) {
    PublicKey bad_pub(bytes(100, 0x00));
    PrivateKey bad_priv(bytes(100, 0x00));
    EXPECT_FALSE(bad_pub.is_valid());
    EXPECT_FALSE(bad_priv.is_valid());

    EXPECT_FALSE(encapsulate(bad_pub).is_success());
    EXPECT_FALSE(decrypt(bad_priv, sample_message()).is_success());
}

// The public key embedded in the ML-KEM private key matches the real one.
TEST(KyberTest, PublicKeyDerivation) {
    const KeyPair kp = generate_keypair(SecurityLevel::KYBER_768);
    const PublicKey derived = kp.private_key().get_public_key();
    EXPECT_EQ(derived.data(), kp.public_key().data());
    EXPECT_TRUE(derived.is_valid());
}

// Size helpers report the standardized ML-KEM sizes.
TEST(KyberTest, SizeHelpers) {
    EXPECT_EQ(get_public_key_size(SecurityLevel::KYBER_512), KYBER_PUBLIC_KEY_512);
    EXPECT_EQ(get_private_key_size(SecurityLevel::KYBER_768), KYBER_PRIVATE_KEY_768);
    EXPECT_EQ(get_ciphertext_size(SecurityLevel::KYBER_1024), KYBER_CIPHERTEXT_1024);
    EXPECT_EQ(get_shared_secret_size(), 32u);
}
