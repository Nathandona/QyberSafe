#include <gtest/gtest.h>

#include <vector>

#include "qybersafe/core/crypto_types.h"
#include "qybersafe/dilithium/dilithium_sig.h"

using namespace qybersafe::dilithium;
using namespace qybersafe::core;

namespace {
bytes sample_message() {
    return {0x51, 0x79, 0x62, 0x65, 0x72, 0x53, 0x61, 0x66, 0x65};  // "QyberSafe"
}
}  // namespace

// Key sizes match the liboqs-reported ML-DSA sizes and the helper functions.
TEST(DilithiumTest, KeypairSizes) {
    const SigningKeyPair kp = generate_keypair(SecurityLevel::DILITHIUM_3);
    EXPECT_EQ(kp.verifying_key().size(),
              get_verifying_key_size(SecurityLevel::DILITHIUM_3));
    EXPECT_EQ(kp.signing_key().size(),
              get_signing_key_size(SecurityLevel::DILITHIUM_3));
    // FIPS 204 anchor: ML-DSA-65 public key is 1952 bytes.
    EXPECT_EQ(kp.verifying_key().size(), 1952u);
    EXPECT_TRUE(kp.verifying_key().is_valid());
    EXPECT_TRUE(kp.signing_key().is_valid());
}

// Sign then verify succeeds across all parameter sets.
TEST(DilithiumTest, SignVerifyAllLevels) {
    for (const SecurityLevel level : {SecurityLevel::DILITHIUM_2,
                                      SecurityLevel::DILITHIUM_3,
                                      SecurityLevel::DILITHIUM_5}) {
        const SigningKeyPair kp = generate_keypair(level);
        auto sig = sign(kp.signing_key(), sample_message());
        ASSERT_TRUE(sig.is_success());
        EXPECT_LE(sig.value().size(), get_signature_size(level));
        EXPECT_TRUE(verify(kp.verifying_key(), sample_message(), sig.value()));
    }
}

// Verification fails for a different message.
TEST(DilithiumTest, WrongMessageFails) {
    const SigningKeyPair kp = generate_keypair(SecurityLevel::DILITHIUM_3);
    auto sig = sign(kp.signing_key(), sample_message());
    ASSERT_TRUE(sig.is_success());
    bytes other = sample_message();
    other[0] ^= 0x01;
    EXPECT_FALSE(verify(kp.verifying_key(), other, sig.value()));
}

// A tampered signature is rejected.
TEST(DilithiumTest, TamperedSignatureFails) {
    const SigningKeyPair kp = generate_keypair(SecurityLevel::DILITHIUM_3);
    auto sig = sign(kp.signing_key(), sample_message());
    ASSERT_TRUE(sig.is_success());
    bytes bad = sig.value();
    bad[0] ^= 0xFF;
    EXPECT_FALSE(verify(kp.verifying_key(), sample_message(), bad));
}

// A signature does not verify under a different key.
TEST(DilithiumTest, WrongKeyFails) {
    const SigningKeyPair kp = generate_keypair(SecurityLevel::DILITHIUM_3);
    const SigningKeyPair other = generate_keypair(SecurityLevel::DILITHIUM_3);
    auto sig = sign(kp.signing_key(), sample_message());
    ASSERT_TRUE(sig.is_success());
    EXPECT_FALSE(verify(other.verifying_key(), sample_message(), sig.value()));
}

// Invalid keys are rejected.
TEST(DilithiumTest, InvalidKeys) {
    VerifyingKey bad_vk(bytes(100, 0x00));
    SigningKey bad_sk(bytes(100, 0x00));
    EXPECT_FALSE(bad_vk.is_valid());
    EXPECT_FALSE(bad_sk.is_valid());
    EXPECT_FALSE(sign(bad_sk, sample_message()).is_success());
    EXPECT_FALSE(verify(bad_vk, sample_message(), bytes(2420, 0x00)));
}

// ML-DSA signing keys do not embed the public key; derivation is unsupported.
TEST(DilithiumTest, VerifyingKeyDerivationUnsupported) {
    const SigningKeyPair kp = generate_keypair(SecurityLevel::DILITHIUM_3);
    EXPECT_THROW(kp.signing_key().get_verifying_key(), std::runtime_error);
}
