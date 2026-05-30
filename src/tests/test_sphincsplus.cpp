#include <gtest/gtest.h>

#include <vector>

#include "qybersafe/core/crypto_types.h"
#include "qybersafe/sphincsplus/sphincsplus_sig.h"

using namespace qybersafe::sphincsplus;
using namespace qybersafe::core;

namespace {
bytes sample_message() {
    return {0x51, 0x79, 0x62, 0x65, 0x72, 0x53, 0x61, 0x66, 0x65};  // "QyberSafe"
}
}  // namespace

// Key sizes match the liboqs-reported SLH-DSA sizes and the helper functions.
TEST(SphincsPlusTest, KeypairSizes) {
    const SPHINCSKeyPair kp = generate_keypair(SecurityLevel::SPHINCS_192);
    EXPECT_EQ(kp.public_key().size(),
              get_public_key_size(SecurityLevel::SPHINCS_192));
    EXPECT_EQ(kp.private_key().size(),
              get_private_key_size(SecurityLevel::SPHINCS_192));
    // FIPS 205 anchor: SLH-DSA-SHA2-192s public key is 2n = 48 bytes.
    EXPECT_EQ(kp.public_key().size(), 48u);
    EXPECT_TRUE(kp.public_key().is_valid());
    EXPECT_TRUE(kp.private_key().is_valid());
}

// Sign then verify succeeds (one round at the default level; SLH-DSA is slow).
TEST(SphincsPlusTest, SignVerifyRoundtrip) {
    const SPHINCSKeyPair kp = generate_keypair(SecurityLevel::SPHINCS_192);
    const bytes sig = sign(kp.private_key(), sample_message());
    EXPECT_EQ(sig.size(), get_signature_size(SecurityLevel::SPHINCS_192));
    EXPECT_TRUE(verify(kp.public_key(), sample_message(), sig));
}

// Verification fails for a different message.
TEST(SphincsPlusTest, WrongMessageFails) {
    const SPHINCSKeyPair kp = generate_keypair(SecurityLevel::SPHINCS_192);
    const bytes sig = sign(kp.private_key(), sample_message());
    bytes other = sample_message();
    other[0] ^= 0x01;
    EXPECT_FALSE(verify(kp.public_key(), other, sig));
}

// A tampered signature is rejected.
TEST(SphincsPlusTest, TamperedSignatureFails) {
    const SPHINCSKeyPair kp = generate_keypair(SecurityLevel::SPHINCS_192);
    bytes sig = sign(kp.private_key(), sample_message());
    sig[0] ^= 0xFF;
    EXPECT_FALSE(verify(kp.public_key(), sample_message(), sig));
}

// The public key embedded in the SLH-DSA private key matches the real one.
TEST(SphincsPlusTest, PublicKeyDerivation) {
    const SPHINCSKeyPair kp = generate_keypair(SecurityLevel::SPHINCS_192);
    const SPHINCSPublicKey derived = kp.private_key().get_public_key();
    EXPECT_EQ(derived.data(), kp.public_key().data());
    EXPECT_TRUE(derived.is_valid());
}

// Invalid keys are rejected.
TEST(SphincsPlusTest, InvalidKeys) {
    SPHINCSPublicKey bad_pub(bytes(10, 0x00));
    SPHINCSPrivateKey bad_priv(bytes(10, 0x00));
    EXPECT_FALSE(bad_pub.is_valid());
    EXPECT_FALSE(bad_priv.is_valid());
    EXPECT_THROW(sign(bad_priv, sample_message()), std::invalid_argument);
    EXPECT_FALSE(verify(bad_pub, sample_message(), bytes(16224, 0x00)));
}
