#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>
#include "qybersafe/qybersafe.h"
#include "qybersafe/core/crypto_types.h"
#include "qybersafe/core/secure_random.h"
#include "qybersafe/kyber/kyber_kem.h"
#include "qybersafe/dilithium/dilithium_sig.h"
#include "qybersafe/sphincsplus/sphincsplus_sig.h"
#include "qybersafe/hybrid/hybrid_encryption.h"

namespace py = pybind11;

using namespace qybersafe;
using namespace qybersafe::core;
using namespace qybersafe::kyber;
using namespace qybersafe::dilithium;
using namespace qybersafe::sphincsplus;
using namespace qybersafe::hybrid;

// Helper function to convert Result types to Python
template<typename T>
py::object handle_result(const Result<T>& result) {
    if (result.is_success()) {
        if constexpr (std::is_void_v<T>) {
            return py::none();
        } else {
            return py::cast(result.value());
        }
    } else {
        throw std::runtime_error(result.error());
    }
}

// Module definition
PYBIND11_MODULE(qybersafe, m) {
    m.doc() = "QyberSafe - Post-Quantum Cryptography Library";

    // Core types
    py::class_<bytes>(m, "bytes", py::buffer_protocol())
        .def(py::init<>())
        .def(py::init<const std::vector<uint8_t>&>())
        .def_buffer([](bytes& b) -> py::buffer_info {
            return py::buffer_info(
                b.data(),
                sizeof(uint8_t),
                py::format_descriptor<uint8_t>::format(),
                1,
                {b.size()},
                {sizeof(uint8_t)}
            );
        })
        .def("__len__", [](const bytes& b) { return b.size(); })
        .def("__getitem__", [](const bytes& b, size_t i) {
            if (i >= b.size()) throw py::index_error();
            return b[i];
        })
        .def("__setitem__", [](bytes& b, size_t i, uint8_t v) {
            if (i >= b.size()) throw py::index_error();
            b[i] = v;
        })
        .def("append", [](bytes& b, uint8_t v) { b.push_back(v); })
        .def("extend", [](bytes& b, const bytes& other) {
            b.insert(b.end(), other.begin(), other.end());
        });

    // Security level enums
    py::enum_<kyber::SecurityLevel>(m, "KyberSecurityLevel")
        .value("Kyber512", kyber::SecurityLevel::Kyber512)
        .value("Kyber768", kyber::SecurityLevel::Kyber768)
        .value("Kyber1024", kyber::SecurityLevel::Kyber1024);

    py::enum_<dilithium::SecurityLevel>(m, "DilithiumSecurityLevel")
        .value("Dilithium2", dilithium::SecurityLevel::Dilithium2)
        .value("Dilithium3", dilithium::SecurityLevel::Dilithium3)
        .value("Dilithium5", dilithium::SecurityLevel::Dilithium5);

    py::enum_<sphincsplus::SecurityLevel>(m, "SphincsSecurityLevel")
        .value("SPHINCS128", sphincsplus::SecurityLevel::SPHINCS128)
        .value("SPHINCS192", sphincsplus::SecurityLevel::SPHINCS192)
        .value("SPHINCS256", sphincsplus::SecurityLevel::SPHINCS256);

    // Kyber classes
    py::class_<kyber::PublicKey>(m, "KyberPublicKey")
        .def(py::init<const bytes&>())
        .def("data", &kyber::PublicKey::data)
        .def("size", &kyber::PublicKey::size)
        .def("is_valid", &kyber::PublicKey::is_valid);

    py::class_<kyber::PrivateKey>(m, "KyberPrivateKey")
        .def(py::init<const bytes&>())
        .def("data", &kyber::PrivateKey::data)
        .def("size", &kyber::PrivateKey::size)
        .def("is_valid", &kyber::PrivateKey::is_valid)
        .def("get_public_key", &kyber::PrivateKey::get_public_key);

    py::class_<kyber::KeyPair>(m, "KyberKeyPair")
        .def(py::init<const kyber::PublicKey&, const kyber::PrivateKey&>())
        .def("public_key", &kyber::KeyPair::public_key, py::return_value_policy::reference)
        .def("private_key", &kyber::KeyPair::private_key, py::return_value_policy::reference);

    // Kyber functions
    m.def("kyber_generate_keypair", [](kyber::SecurityLevel level) {
        return kyber::generate_keypair(level);
    }, py::arg("level") = kyber::SecurityLevel::Kyber768);

    m.def("kyber_encrypt", [](const kyber::PublicKey& public_key, const bytes& plaintext) {
        return kyber::encrypt(public_key, plaintext);
    });

    m.def("kyber_decrypt", [](const kyber::PrivateKey& private_key, const bytes& ciphertext) {
        return handle_result(kyber::decrypt(private_key, ciphertext));
    });

    m.def("kyber_encapsulate", [](const kyber::PublicKey& public_key) {
        return handle_result(kyber::encapsulate(public_key));
    });

    m.def("kyber_decapsulate", [](const kyber::PrivateKey& private_key, const bytes& ciphertext) {
        return handle_result(kyber::decapsulate(private_key, ciphertext));
    });

    // Kyber utility functions
    m.def("kyber_get_public_key_size", &kyber::get_public_key_size);
    m.def("kyber_get_private_key_size", &kyber::get_private_key_size);
    m.def("kyber_get_ciphertext_size", &kyber::get_ciphertext_size);
    m.def("kyber_get_shared_secret_size", &kyber::get_shared_secret_size);

    // Dilithium classes
    py::class_<dilithium::VerifyingKey>(m, "DilithiumVerifyingKey")
        .def(py::init<const bytes&>())
        .def("data", &dilithium::VerifyingKey::data)
        .def("size", &dilithium::VerifyingKey::size)
        .def("is_valid", &dilithium::VerifyingKey::is_valid);

    py::class_<dilithium::SigningKey>(m, "DilithiumSigningKey")
        .def(py::init<const bytes&>())
        .def("data", &dilithium::SigningKey::data)
        .def("size", &dilithium::SigningKey::size)
        .def("is_valid", &dilithium::SigningKey::is_valid)
        .def("get_verifying_key", &dilithium::SigningKey::get_verifying_key);

    py::class_<dilithium::SigningKeyPair>(m, "DilithiumSigningKeyPair")
        .def(py::init<const dilithium::VerifyingKey&, const dilithium::SigningKey&>())
        .def("verifying_key", &dilithium::SigningKeyPair::verifying_key, py::return_value_policy::reference)
        .def("signing_key", &dilithium::SigningKeyPair::signing_key, py::return_value_policy::reference);

    // Dilithium functions
    m.def("dilithium_generate_keypair", [](dilithium::SecurityLevel level) {
        return dilithium::generate_keypair(level);
    }, py::arg("level") = dilithium::SecurityLevel::Dilithium3);

    m.def("dilithium_sign", [](const dilithium::SigningKey& signing_key, const bytes& message) {
        return handle_result(dilithium::sign(signing_key, message));
    });

    m.def("dilithium_verify", [](const dilithium::VerifyingKey& verifying_key, const bytes& message, const bytes& signature) {
        return dilithium::verify(verifying_key, message, signature);
    });

    // Dilithium utility functions
    m.def("dilithium_get_verifying_key_size", &dilithium::get_verifying_key_size);
    m.def("dilithium_get_signing_key_size", &dilithium::get_signing_key_size);
    m.def("dilithium_get_signature_size", &dilithium::get_signature_size);
    m.def("dilithium_hash_message", &dilithium::hash_message);

    // SPHINCS+ classes
    py::class_<sphincsplus::SPHINCSPublicKey>(m, "SphincsPublicKey")
        .def(py::init<const bytes&>())
        .def("data", &sphincsplus::SPHINCSPublicKey::data)
        .def("size", &sphincsplus::SPHINCSPublicKey::size)
        .def("is_valid", &sphincsplus::SPHINCSPublicKey::is_valid);

    py::class_<sphincsplus::SPHINCSPrivateKey>(m, "SphincsPrivateKey")
        .def(py::init<const bytes&>())
        .def("data", &sphincsplus::SPHINCSPrivateKey::data)
        .def("size", &sphincsplus::SPHINCSPrivateKey::size)
        .def("is_valid", &sphincsplus::SPHINCSPrivateKey::is_valid)
        .def("get_public_key", &sphincsplus::SPHINCSPrivateKey::get_public_key);

    py::class_<sphincsplus::SPHINCSKeyPair>(m, "SphincsKeyPair")
        .def(py::init<const sphincsplus::SPHINCSPublicKey&, const sphincsplus::SPHINCSPrivateKey&>())
        .def("public_key", &sphincsplus::SPHINCSKeyPair::public_key, py::return_value_policy::reference)
        .def("private_key", &sphincsplus::SPHINCSKeyPair::private_key, py::return_value_policy::reference);

    // SPHINCS+ functions
    m.def("sphincs_generate_keypair", [](sphincsplus::SecurityLevel level) {
        return sphincsplus::generate_keypair(level);
    }, py::arg("level") = sphincsplus::SecurityLevel::SPHINCS192);

    m.def("sphincs_sign", [](const sphincsplus::SPHINCSPrivateKey& private_key, const bytes& message) {
        return sphincsplus::sign(private_key, message);
    });

    m.def("sphincs_verify", [](const sphincsplus::SPHINCSPublicKey& public_key, const bytes& message, const bytes& signature) {
        return sphincsplus::verify(public_key, message, signature);
    });

    // Hybrid encryption classes
    py::class_<hybrid::HybridPublicKey>(m, "HybridPublicKey")
        .def(py::init<const kyber::PublicKey&, const bytes&>())
        .def(py::init<const bytes&>())
        .def("pq_key", &hybrid::HybridPublicKey::pq_key, py::return_value_policy::reference)
        .def("classical_key", &hybrid::HybridPublicKey::classical_key)
        .def("data", &hybrid::HybridPublicKey::data)
        .def("size", &hybrid::HybridPublicKey::size)
        .def("is_valid", &hybrid::HybridPublicKey::is_valid);

    py::class_<hybrid::HybridPrivateKey>(m, "HybridPrivateKey")
        .def(py::init<const kyber::PrivateKey&, const bytes&>())
        .def(py::init<const bytes&>())
        .def("pq_key", &hybrid::HybridPrivateKey::pq_key, py::return_value_policy::reference)
        .def("classical_key", &hybrid::HybridPrivateKey::classical_key)
        .def("data", &hybrid::HybridPrivateKey::data)
        .def("size", &hybrid::HybridPrivateKey::size)
        .def("is_valid", &hybrid::HybridPrivateKey::is_valid)
        .def("get_public_key", &hybrid::HybridPrivateKey::get_public_key);

    py::class_<hybrid::HybridKeyPair>(m, "HybridKeyPair")
        .def(py::init<const hybrid::HybridPublicKey&, const hybrid::HybridPrivateKey&>())
        .def("public_key", &hybrid::HybridKeyPair::public_key, py::return_value_policy::reference)
        .def("private_key", &hybrid::HybridKeyPair::private_key, py::return_value_policy::reference);

    // Hybrid encryption functions
    m.def("hybrid_generate_keypair", &hybrid::generate_hybrid_keypair);
    m.def("hybrid_encrypt", &hybrid::hybrid_encrypt);
    m.def("hybrid_decrypt", &hybrid::hybrid_decrypt);

    // Utility functions
    m.def("random_bytes", [](size_t count) {
        return handle_result(random_bytes(count));
    });

    // Hex encoding/decoding
    m.def("encode_hex", [](const bytes& data) {
        return qybersafe::utils::encode_hex(data);
    });

    m.def("decode_hex", [](const std::string& hex_str) {
        try {
            return qybersafe::utils::decode_hex(hex_str);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Hex decode error: ") + e.what());
        }
    });

    m.def("is_valid_hex", &qybersafe::utils::is_valid_hex);

    // Base64 encoding/decoding
    m.def("encode_base64", [](const bytes& data) {
        return qybersafe::utils::encode_base64(data);
    });

    m.def("decode_base64", [](const std::string& base64_str) {
        try {
            return qybersafe::utils::decode_base64(base64_str);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Base64 decode error: ") + e.what());
        }
    });

    m.def("is_valid_base64", &qybersafe::utils::is_valid_base64);

    // Constants
    m.attr("VERSION") = "0.1.0";
    m.attr("KYBER512_PUBLIC_KEY_SIZE") = KYBER_PUBLIC_KEY_512;
    m.attr("KYBER512_PRIVATE_KEY_SIZE") = KYBER_PRIVATE_KEY_512;
    m.attr("KYBER512_CIPHERTEXT_SIZE") = KYBER_CIPHERTEXT_512;
    m.attr("KYBER768_PUBLIC_KEY_SIZE") = KYBER_PUBLIC_KEY_768;
    m.attr("KYBER768_PRIVATE_KEY_SIZE") = KYBER_PRIVATE_KEY_768;
    m.attr("KYBER768_CIPHERTEXT_SIZE") = KYBER_CIPHERTEXT_768;
    m.attr("KYBER1024_PUBLIC_KEY_SIZE") = KYBER_PUBLIC_KEY_1024;
    m.attr("KYBER1024_PRIVATE_KEY_SIZE") = KYBER_PRIVATE_KEY_1024;
    m.attr("KYBER1024_CIPHERTEXT_SIZE") = KYBER_CIPHERTEXT_1024;
    m.attr("DILITHIUM2_PUBLIC_KEY_SIZE") = DILITHIUM_PUBLIC_KEY_2;
    m.attr("DILITHIUM2_PRIVATE_KEY_SIZE") = DILITHIUM_PRIVATE_KEY_2;
    m.attr("DILITHIUM2_SIGNATURE_SIZE") = DILITHIUM_SIGNATURE_2;
    m.attr("DILITHIUM3_PUBLIC_KEY_SIZE") = DILITHIUM_PUBLIC_KEY_3;
    m.attr("DILITHIUM3_PRIVATE_KEY_SIZE") = DILITHIUM_PRIVATE_KEY_3;
    m.attr("DILITHIUM3_SIGNATURE_SIZE") = DILITHIUM_SIGNATURE_3;
    m.attr("DILITHIUM5_PUBLIC_KEY_SIZE") = DILITHIUM_PUBLIC_KEY_5;
    m.attr("DILITHIUM5_PRIVATE_KEY_SIZE") = DILITHIUM_PRIVATE_KEY_5;
    m.attr("DILITHIUM5_SIGNATURE_SIZE") = DILITHIUM_SIGNATURE_5;
}