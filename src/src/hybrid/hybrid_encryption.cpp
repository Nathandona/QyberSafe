#include "qybersafe/hybrid/hybrid_encryption.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>

#include "qybersafe/kyber/kyber_kem.h"

/**
 * @file hybrid_encryption.cpp
 * @brief Hybrid public-key encryption: X25519 + ML-KEM-768 (suite 0x0301).
 *
 * Construction (KEM-DEM, see SPEC.md section 6):
 *   1. X25519 ECDH against an ephemeral key  -> ss_x
 *   2. ML-KEM-768 encapsulation              -> ss_pq, ct_pq
 *   3. K = HKDF-SHA-256(ss_pq || ss_x, info = transcript)
 *   4. AES-256-GCM(K, random nonce, plaintext)
 * The post-quantum secret is placed first and the full transcript is bound into
 * the KDF so neither half can be stripped or substituted.
 *
 * Wire format (SPEC.md section 7): a 4-byte header (version, artifact type,
 * algorithm id) followed by uint32-length-prefixed fields.
 */

namespace qybersafe::hybrid {

using core::bytes;

namespace {

constexpr uint8_t kVersion = 0x01;
constexpr uint8_t kTypePublicKey = 1;
constexpr uint8_t kTypePrivateKey = 2;
constexpr uint8_t kTypeEnvelope = 5;
constexpr uint16_t kAlgHybrid = 0x0301;  // X25519 + ML-KEM-768 + AES-256-GCM

constexpr size_t kX25519Len = 32;
constexpr size_t kAesKeyLen = 32;
constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;

constexpr kyber::SecurityLevel kPqLevel = kyber::SecurityLevel::KYBER_768;

// --- wire format -----------------------------------------------------------

void put_u32(bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void put_header(bytes& out, uint8_t type) {
    out.push_back(kVersion);
    out.push_back(type);
    out.push_back(static_cast<uint8_t>(kAlgHybrid >> 8));
    out.push_back(static_cast<uint8_t>(kAlgHybrid & 0xFF));
}

void put_field(bytes& out, const bytes& field) {
    put_u32(out, static_cast<uint32_t>(field.size()));
    out.insert(out.end(), field.begin(), field.end());
}

class Reader {
public:
    explicit Reader(const bytes& data) : data_(data) {}

    void expect_header(uint8_t type) {
        if (data_.size() - pos_ < 4) throw std::runtime_error("truncated header");
        const uint8_t version = data_[pos_++];
        const uint8_t t = data_[pos_++];
        const uint16_t alg =
            static_cast<uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
        pos_ += 2;
        if (version != kVersion) throw std::runtime_error("unsupported version");
        if (t != type) throw std::runtime_error("unexpected artifact type");
        if (alg != kAlgHybrid) throw std::runtime_error("unexpected algorithm id");
    }

    bytes field() {
        if (data_.size() - pos_ < 4) throw std::runtime_error("truncated length");
        const uint32_t n = (static_cast<uint32_t>(data_[pos_]) << 24) |
                           (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                           (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                           static_cast<uint32_t>(data_[pos_ + 3]);
        pos_ += 4;
        if (data_.size() - pos_ < n) throw std::runtime_error("truncated field");
        bytes out(data_.begin() + pos_, data_.begin() + pos_ + n);
        pos_ += n;
        return out;
    }

    void expect_end() {
        if (pos_ != data_.size()) throw std::runtime_error("trailing bytes");
    }

private:
    const bytes& data_;
    size_t pos_ = 0;
};

// --- OpenSSL helpers -------------------------------------------------------

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

void x25519_generate(bytes& public_out, bytes& private_out) {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr),
                   EVP_PKEY_CTX_free);
    EVP_PKEY* raw = nullptr;
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
        EVP_PKEY_keygen(ctx.get(), &raw) <= 0) {
        throw std::runtime_error("X25519 key generation failed");
    }
    PkeyPtr key(raw, EVP_PKEY_free);

    public_out.resize(kX25519Len);
    private_out.resize(kX25519Len);
    size_t pub_len = kX25519Len;
    size_t priv_len = kX25519Len;
    if (EVP_PKEY_get_raw_public_key(key.get(), public_out.data(), &pub_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(key.get(), private_out.data(), &priv_len) <= 0 ||
        pub_len != kX25519Len || priv_len != kX25519Len) {
        throw std::runtime_error("X25519 raw key export failed");
    }
}

bytes x25519_public_from_private(const bytes& priv) {
    PkeyPtr key(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                             priv.data(), priv.size()),
                EVP_PKEY_free);
    if (!key) throw std::runtime_error("invalid X25519 private key");
    bytes pub(kX25519Len);
    size_t len = kX25519Len;
    if (EVP_PKEY_get_raw_public_key(key.get(), pub.data(), &len) <= 0 ||
        len != kX25519Len) {
        throw std::runtime_error("X25519 public key derivation failed");
    }
    return pub;
}

bytes x25519_ecdh(const bytes& priv, const bytes& peer_pub) {
    PkeyPtr self(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                              priv.data(), priv.size()),
                 EVP_PKEY_free);
    PkeyPtr peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                             peer_pub.data(), peer_pub.size()),
                 EVP_PKEY_free);
    if (!self || !peer) throw std::runtime_error("invalid X25519 key material");

    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(self.get(), nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) <= 0) {
        throw std::runtime_error("X25519 ECDH setup failed");
    }
    size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) <= 0) {
        throw std::runtime_error("X25519 ECDH failed");
    }
    bytes secret(len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) <= 0) {
        throw std::runtime_error("X25519 ECDH failed");
    }
    secret.resize(len);
    return secret;
}

bytes hkdf_sha256(const bytes& ikm, const bytes& info, size_t out_len) {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr),
                   EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(),
                                   static_cast<int>(ikm.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(),
                                    static_cast<int>(info.size())) <= 0) {
        throw std::runtime_error("HKDF setup failed");
    }
    bytes out(out_len);
    size_t len = out_len;
    if (EVP_PKEY_derive(ctx.get(), out.data(), &len) <= 0 || len != out_len) {
        throw std::runtime_error("HKDF derivation failed");
    }
    return out;
}

void aes_256_gcm_encrypt(const bytes& key, const bytes& nonce,
                         const bytes& plaintext, bytes& ciphertext,
                         bytes& tag) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx ||
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM encrypt init failed");
    }
    ciphertext.resize(plaintext.size());
    int out_len = 0;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("AES-GCM encrypt failed");
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len,
                            &final_len) != 1) {
        throw std::runtime_error("AES-GCM encrypt final failed");
    }
    ciphertext.resize(static_cast<size_t>(out_len + final_len));
    tag.resize(kTagLen);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(kTagLen), tag.data()) != 1) {
        throw std::runtime_error("AES-GCM tag extraction failed");
    }
}

bool aes_256_gcm_decrypt(const bytes& key, const bytes& nonce,
                         const bytes& ciphertext, const bytes& tag,
                         bytes& plaintext) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx ||
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM decrypt init failed");
    }
    plaintext.resize(ciphertext.size());
    int out_len = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("AES-GCM decrypt failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()),
                            const_cast<unsigned char*>(tag.data())) != 1) {
        throw std::runtime_error("AES-GCM set tag failed");
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len,
                            &final_len) != 1) {
        plaintext.clear();
        return false;
    }
    plaintext.resize(static_cast<size_t>(out_len + final_len));
    return true;
}

// Transcript bound into the KDF: suite id, ephemeral key, KEM ciphertext, and
// the recipient's public keys.
bytes transcript(const bytes& eph_x25519_pub, const bytes& kem_ct,
                 const bytes& recipient_x25519_pub,
                 const bytes& recipient_mlkem_pub) {
    bytes t;
    t.push_back(static_cast<uint8_t>(kAlgHybrid >> 8));
    t.push_back(static_cast<uint8_t>(kAlgHybrid & 0xFF));
    t.insert(t.end(), eph_x25519_pub.begin(), eph_x25519_pub.end());
    t.insert(t.end(), kem_ct.begin(), kem_ct.end());
    t.insert(t.end(), recipient_x25519_pub.begin(), recipient_x25519_pub.end());
    t.insert(t.end(), recipient_mlkem_pub.begin(), recipient_mlkem_pub.end());
    return t;
}

kyber::PublicKey parse_public_pq(const bytes& data) {
    Reader r(data);
    r.expect_header(kTypePublicKey);
    bytes pq = r.field();   // ml-kem public key
    (void)r.field();        // x25519 public key
    r.expect_end();
    return kyber::PublicKey(pq);
}

bytes parse_public_classical(const bytes& data) {
    Reader r(data);
    r.expect_header(kTypePublicKey);
    (void)r.field();              // ml-kem public key
    bytes classical = r.field();  // x25519 public key
    r.expect_end();
    return classical;
}

kyber::PrivateKey parse_private_pq(const bytes& data) {
    Reader r(data);
    r.expect_header(kTypePrivateKey);
    bytes pq = r.field();
    (void)r.field();
    r.expect_end();
    return kyber::PrivateKey(pq);
}

bytes parse_private_classical(const bytes& data) {
    Reader r(data);
    r.expect_header(kTypePrivateKey);
    (void)r.field();
    bytes classical = r.field();
    r.expect_end();
    return classical;
}

}  // namespace

// --- HybridPublicKey -------------------------------------------------------

HybridPublicKey::HybridPublicKey(const kyber::PublicKey& pq_key,
                                 const bytes& classical_key)
    : pq_key_(pq_key), classical_key_(classical_key) {}

HybridPublicKey::HybridPublicKey(const bytes& data)
    : HybridPublicKey(parse_public_pq(data), parse_public_classical(data)) {}

const kyber::PublicKey& HybridPublicKey::pq_key() const { return pq_key_; }

const bytes& HybridPublicKey::classical_key() const { return classical_key_; }

bytes HybridPublicKey::data() const {
    if (data_.empty()) {
        put_header(data_, kTypePublicKey);
        put_field(data_, pq_key_.data());
        put_field(data_, classical_key_);
    }
    return data_;
}

size_t HybridPublicKey::size() const { return data().size(); }

bool HybridPublicKey::is_valid() const {
    if (!validity_checked_) {
        is_valid_ = pq_key_.is_valid() && classical_key_.size() == kX25519Len;
        validity_checked_ = true;
    }
    return is_valid_;
}

// --- HybridPrivateKey ------------------------------------------------------

HybridPrivateKey::HybridPrivateKey(const kyber::PrivateKey& pq_key,
                                   const bytes& classical_key)
    : pq_key_(pq_key), classical_key_(classical_key) {}

HybridPrivateKey::HybridPrivateKey(const bytes& data)
    : HybridPrivateKey(parse_private_pq(data), parse_private_classical(data)) {}

const kyber::PrivateKey& HybridPrivateKey::pq_key() const { return pq_key_; }

const bytes& HybridPrivateKey::classical_key() const { return classical_key_; }

bytes HybridPrivateKey::data() const {
    if (data_.empty()) {
        put_header(data_, kTypePrivateKey);
        put_field(data_, pq_key_.data());
        put_field(data_, classical_key_);
    }
    return data_;
}

size_t HybridPrivateKey::size() const { return data().size(); }

bool HybridPrivateKey::is_valid() const {
    if (!validity_checked_) {
        is_valid_ = pq_key_.is_valid() && classical_key_.size() == kX25519Len;
        validity_checked_ = true;
    }
    return is_valid_;
}

HybridPublicKey HybridPrivateKey::get_public_key() const {
    return HybridPublicKey(pq_key_.get_public_key(),
                           x25519_public_from_private(classical_key_));
}

// --- HybridKeyPair ---------------------------------------------------------

HybridKeyPair::HybridKeyPair(const HybridPublicKey& public_key,
                             const HybridPrivateKey& private_key)
    : public_key_(public_key), private_key_(private_key) {}

const HybridPublicKey& HybridKeyPair::public_key() const {
    return *public_key_;
}

const HybridPrivateKey& HybridKeyPair::private_key() const {
    return *private_key_;
}

// --- API -------------------------------------------------------------------

HybridKeyPair generate_hybrid_keypair() {
    kyber::KeyPair pq = kyber::generate_keypair(kPqLevel);
    bytes x_pub;
    bytes x_priv;
    x25519_generate(x_pub, x_priv);

    HybridPublicKey public_key(pq.public_key(), x_pub);
    HybridPrivateKey private_key(pq.private_key(), x_priv);
    return HybridKeyPair(public_key, private_key);
}

core::bytes hybrid_encrypt(const HybridPublicKey& public_key,
                           const core::bytes& plaintext) {
    if (!public_key.is_valid()) {
        throw std::invalid_argument("Invalid hybrid public key");
    }

    // Classical half: ephemeral X25519 ECDH.
    bytes eph_pub;
    bytes eph_priv;
    x25519_generate(eph_pub, eph_priv);
    const bytes ss_x = x25519_ecdh(eph_priv, public_key.classical_key());

    // Post-quantum half: ML-KEM-768 encapsulation.
    auto encaps = kyber::encapsulate(public_key.pq_key());
    if (!encaps.is_success()) {
        throw std::runtime_error("hybrid_encrypt: " + encaps.error());
    }
    const bytes& kem_ct = encaps.value().first;
    const bytes& ss_pq = encaps.value().second;

    // Combine: HKDF over ss_pq || ss_x, bound to the transcript.
    bytes ikm;
    ikm.reserve(ss_pq.size() + ss_x.size());
    ikm.insert(ikm.end(), ss_pq.begin(), ss_pq.end());
    ikm.insert(ikm.end(), ss_x.begin(), ss_x.end());
    const bytes info = transcript(eph_pub, kem_ct, public_key.classical_key(),
                                  public_key.pq_key().data());
    bytes key = hkdf_sha256(ikm, info, kAesKeyLen);

    bytes nonce(kNonceLen);
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        core::secure_zero_memory(key.data(), key.size());
        throw std::runtime_error("hybrid_encrypt: CSPRNG failure");
    }

    bytes ciphertext;
    bytes tag;
    try {
        aes_256_gcm_encrypt(key, nonce, plaintext, ciphertext, tag);
    } catch (...) {
        core::secure_zero_memory(key.data(), key.size());
        throw;
    }
    core::secure_zero_memory(key.data(), key.size());

    bytes envelope;
    put_header(envelope, kTypeEnvelope);
    put_field(envelope, eph_pub);
    put_field(envelope, kem_ct);
    put_field(envelope, nonce);
    put_field(envelope, tag);
    put_field(envelope, ciphertext);
    return envelope;
}

core::bytes hybrid_decrypt(const HybridPrivateKey& private_key,
                           const core::bytes& ciphertext) {
    if (!private_key.is_valid()) {
        throw std::invalid_argument("Invalid hybrid private key");
    }

    Reader reader(ciphertext);
    reader.expect_header(kTypeEnvelope);
    const bytes eph_pub = reader.field();
    const bytes kem_ct = reader.field();
    const bytes nonce = reader.field();
    const bytes tag = reader.field();
    const bytes ct = reader.field();
    reader.expect_end();

    const bytes ss_x = x25519_ecdh(private_key.classical_key(), eph_pub);

    auto decaps = kyber::decapsulate(private_key.pq_key(), kem_ct);
    if (!decaps.is_success()) {
        throw std::runtime_error("hybrid_decrypt: " + decaps.error());
    }
    const bytes& ss_pq = decaps.value();

    bytes ikm;
    ikm.reserve(ss_pq.size() + ss_x.size());
    ikm.insert(ikm.end(), ss_pq.begin(), ss_pq.end());
    ikm.insert(ikm.end(), ss_x.begin(), ss_x.end());
    const bytes recipient_x25519_pub =
        x25519_public_from_private(private_key.classical_key());
    const bytes recipient_mlkem_pub = private_key.pq_key().get_public_key().data();
    const bytes info =
        transcript(eph_pub, kem_ct, recipient_x25519_pub, recipient_mlkem_pub);
    bytes key = hkdf_sha256(ikm, info, kAesKeyLen);

    bytes plaintext;
    const bool ok = aes_256_gcm_decrypt(key, nonce, ct, tag, plaintext);
    core::secure_zero_memory(key.data(), key.size());
    if (!ok) {
        throw std::runtime_error("hybrid_decrypt: authentication failed");
    }
    return plaintext;
}

}  // namespace qybersafe::hybrid
