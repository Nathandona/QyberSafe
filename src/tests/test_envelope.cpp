#include <gtest/gtest.h>

#include <vector>

#include "qybersafe/qybersafe.h"

using namespace qybersafe;

namespace {
bytes msg() { return {0x65, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65}; }  // "envelope"
}  // namespace

// ---- Encryption -----------------------------------------------------------

TEST(EnvelopeEncryption, SealOpenRoundtrip) {
    const EncryptionKeyPair kp = generate_encryption_keypair();
    const bytes envelope = seal(kp.public_key, msg());
    EXPECT_EQ(open(kp.private_key, envelope), msg());
}

TEST(EnvelopeEncryption, AadMustMatch) {
    const EncryptionKeyPair kp = generate_encryption_keypair();
    const bytes aad = {0x63, 0x74, 0x78};  // "ctx"
    const bytes envelope = seal(kp.public_key, msg(), aad);

    EXPECT_EQ(open(kp.private_key, envelope, aad), msg());
    EXPECT_THROW(open(kp.private_key, envelope, bytes{0x00}), CryptoError);
    EXPECT_THROW(open(kp.private_key, envelope), CryptoError);  // missing aad
}

TEST(EnvelopeEncryption, WrongKeyThrows) {
    const EncryptionKeyPair kp = generate_encryption_keypair();
    const EncryptionKeyPair other = generate_encryption_keypair();
    const bytes envelope = seal(kp.public_key, msg());
    EXPECT_THROW(open(other.private_key, envelope), CryptoError);
}

TEST(EnvelopeEncryption, KeySerializationRoundtrip) {
    const EncryptionKeyPair kp = generate_encryption_keypair();
    const EncryptionPublicKey pub =
        encryption_public_key_from_bytes(to_bytes(kp.public_key));
    const EncryptionPrivateKey priv =
        encryption_private_key_from_bytes(to_bytes(kp.private_key));

    const bytes envelope = seal(pub, msg());
    EXPECT_EQ(open(priv, envelope), msg());
}

TEST(EnvelopeEncryption, DerivedPublicKeyInteroperates) {
    const EncryptionKeyPair kp = generate_encryption_keypair();
    const EncryptionPublicKey derived = kp.private_key.public_key();
    EXPECT_EQ(to_bytes(derived), to_bytes(kp.public_key));
}

TEST(EnvelopeEncryption, RejectsMalformedEnvelope) {
    const EncryptionKeyPair kp = generate_encryption_keypair();
    EXPECT_THROW(open(kp.private_key, bytes{0x01, 0x02}), CryptoError);
}

// ---- Signatures -----------------------------------------------------------

TEST(EnvelopeSignatures, SignVerifyAllAlgorithms) {
    for (const SignAlg alg : {SignAlg::ML_DSA_44, SignAlg::ML_DSA_65,
                              SignAlg::ML_DSA_87, SignAlg::SLH_DSA_128s,
                              SignAlg::SLH_DSA_192s, SignAlg::SLH_DSA_256s}) {
        const SigningKeyPair kp = generate_signing_keypair(alg);
        const bytes signature = sign(kp.private_key, msg());
        EXPECT_TRUE(verify(kp.public_key, msg(), signature));
    }
}

TEST(EnvelopeSignatures, DefaultIsMlDsa65) {
    const SigningKeyPair kp = generate_signing_keypair();
    EXPECT_EQ(kp.public_key.algorithm(), SignAlg::ML_DSA_65);
}

TEST(EnvelopeSignatures, WrongMessageFails) {
    const SigningKeyPair kp = generate_signing_keypair();
    const bytes signature = sign(kp.private_key, msg());
    bytes other = msg();
    other[0] ^= 0x01;
    EXPECT_FALSE(verify(kp.public_key, other, signature));
}

TEST(EnvelopeSignatures, KeySerializationRoundtrip) {
    const SigningKeyPair kp = generate_signing_keypair(SignAlg::ML_DSA_65);
    const SigningPublicKey pub =
        signing_public_key_from_bytes(to_bytes(kp.public_key));
    const SigningPrivateKey priv =
        signing_private_key_from_bytes(to_bytes(kp.private_key));

    EXPECT_EQ(pub.algorithm(), SignAlg::ML_DSA_65);
    EXPECT_EQ(priv.algorithm(), SignAlg::ML_DSA_65);

    const bytes signature = sign(priv, msg());
    EXPECT_TRUE(verify(pub, msg(), signature));
}

TEST(EnvelopeSignatures, SlhDsaSerializationRoundtrip) {
    const SigningKeyPair kp = generate_signing_keypair(SignAlg::SLH_DSA_192s);
    const SigningPublicKey pub =
        signing_public_key_from_bytes(to_bytes(kp.public_key));
    EXPECT_EQ(pub.algorithm(), SignAlg::SLH_DSA_192s);
    const bytes signature = sign(kp.private_key, msg());
    EXPECT_TRUE(verify(pub, msg(), signature));
}

TEST(EnvelopeSignatures, RejectsMalformedKey) {
    EXPECT_THROW(signing_public_key_from_bytes(bytes{0x01, 0x02}), CryptoError);
}
