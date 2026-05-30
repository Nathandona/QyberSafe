#include <pybind11/pybind11.h>

#include <string>

#include "qybersafe/qybersafe.h"

/**
 * @file bindings.cpp
 * @brief pybind11 bindings for the QyberSafe envelope-first public API.
 *
 * Binary values cross the boundary as Python `bytes`. Inputs are taken as
 * std::string (pybind converts Python bytes to it) and outputs are returned as
 * py::bytes so binary data is never UTF-8 decoded.
 */

namespace py = pybind11;
using namespace qybersafe;

namespace {

bytes to_vec(const std::string& s) {
    return bytes(s.begin(), s.end());
}

py::bytes to_pybytes(const bytes& v) {
    return py::bytes(reinterpret_cast<const char*>(v.data()), v.size());
}

}  // namespace

PYBIND11_MODULE(_core, m) {
    m.doc() = "QyberSafe post-quantum cryptography (C++ core)";

    py::register_exception<CryptoError>(m, "CryptoError");

    // ---- Encryption -------------------------------------------------------

    py::class_<EncryptionPublicKey>(m, "EncryptionPublicKey")
        .def("to_bytes",
             [](const EncryptionPublicKey& k) { return to_pybytes(to_bytes(k)); })
        .def_static("from_bytes", [](const std::string& d) {
            return encryption_public_key_from_bytes(to_vec(d));
        });

    py::class_<EncryptionPrivateKey>(m, "EncryptionPrivateKey")
        .def("to_bytes",
             [](const EncryptionPrivateKey& k) { return to_pybytes(to_bytes(k)); })
        .def("public_key", &EncryptionPrivateKey::public_key)
        .def_static("from_bytes", [](const std::string& d) {
            return encryption_private_key_from_bytes(to_vec(d));
        });

    py::class_<EncryptionKeyPair>(m, "EncryptionKeyPair")
        .def_readonly("public_key", &EncryptionKeyPair::public_key)
        .def_readonly("private_key", &EncryptionKeyPair::private_key);

    m.def("generate_encryption_keypair", &generate_encryption_keypair);

    m.def(
        "seal",
        [](const EncryptionPublicKey& to, const std::string& plaintext,
           const std::string& aad) {
            return to_pybytes(seal(to, to_vec(plaintext), to_vec(aad)));
        },
        py::arg("to"), py::arg("plaintext"), py::arg("aad") = std::string());

    m.def(
        "open",
        [](const EncryptionPrivateKey& key, const std::string& envelope,
           const std::string& aad) {
            return to_pybytes(open(key, to_vec(envelope), to_vec(aad)));
        },
        py::arg("key"), py::arg("envelope"), py::arg("aad") = std::string());

    // ---- Signatures -------------------------------------------------------

    py::enum_<SignAlg>(m, "SignAlg")
        .value("ML_DSA_44", SignAlg::ML_DSA_44)
        .value("ML_DSA_65", SignAlg::ML_DSA_65)
        .value("ML_DSA_87", SignAlg::ML_DSA_87)
        .value("SLH_DSA_128s", SignAlg::SLH_DSA_128s)
        .value("SLH_DSA_192s", SignAlg::SLH_DSA_192s)
        .value("SLH_DSA_256s", SignAlg::SLH_DSA_256s);

    py::class_<SigningPublicKey>(m, "SigningPublicKey")
        .def_property_readonly("algorithm", &SigningPublicKey::algorithm)
        .def("to_bytes",
             [](const SigningPublicKey& k) { return to_pybytes(to_bytes(k)); })
        .def_static("from_bytes", [](const std::string& d) {
            return signing_public_key_from_bytes(to_vec(d));
        });

    py::class_<SigningPrivateKey>(m, "SigningPrivateKey")
        .def_property_readonly("algorithm", &SigningPrivateKey::algorithm)
        .def("to_bytes",
             [](const SigningPrivateKey& k) { return to_pybytes(to_bytes(k)); })
        .def_static("from_bytes", [](const std::string& d) {
            return signing_private_key_from_bytes(to_vec(d));
        });

    py::class_<SigningKeyPair>(m, "SigningKeyPair")
        .def_readonly("public_key", &SigningKeyPair::public_key)
        .def_readonly("private_key", &SigningKeyPair::private_key);

    m.def("generate_signing_keypair", &generate_signing_keypair,
          py::arg("algorithm") = SignAlg::ML_DSA_65);

    m.def(
        "sign",
        [](const SigningPrivateKey& key, const std::string& message) {
            return to_pybytes(sign(key, to_vec(message)));
        },
        py::arg("key"), py::arg("message"));

    m.def(
        "verify",
        [](const SigningPublicKey& key, const std::string& message,
           const std::string& signature) {
            return verify(key, to_vec(message), to_vec(signature));
        },
        py::arg("key"), py::arg("message"), py::arg("signature"));
}
