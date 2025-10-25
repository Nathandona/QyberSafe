#include "qybersafe/qybersafe.h"
#include <iostream>
#include <iomanip>
#include <string>

using namespace qybersafe;
using namespace qybersafe::kyber;
using namespace qybersafe::core;

void print_hex(const std::string& label, const bytes& data) {
    std::cout << label << ": " << std::hex << std::setfill('0');
    for (size_t i = 0; i < std::min(data.size(), size_t(32)); ++i) {
        std::cout << std::setw(2) << static_cast<int>(data[i]);
    }
    if (data.size() > 32) {
        std::cout << "... (" << data.size() << " bytes total)";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "=== QyberSafe Kyber KEM Example ===" << std::endl;
    std::cout << std::endl;

    try {
        // Generate a Kyber key pair
        std::cout << "Generating Kyber768 key pair..." << std::endl;
        KeyPair keypair = generate_keypair(SecurityLevel::Kyber768);

        print_hex("Public key", keypair.public_key().data());
        print_hex("Private key", keypair.private_key().data());
        std::cout << std::endl;

        // Test basic encryption/decryption
        std::cout << "Testing basic encryption/decryption..." << std::endl;
        std::string message_str = "Hello, Kyber!";
        bytes message(message_str.begin(), message_str.end());

        std::cout << "Original message: " << message_str << std::endl;

        // Encrypt the message
        bytes ciphertext = encrypt(keypair.public_key(), message);
        print_hex("Ciphertext", ciphertext);

        // Decrypt the message
        auto decrypted_result = decrypt(keypair.private_key(), ciphertext);
        if (decrypted_result.is_success()) {
            bytes decrypted = decrypted_result.value();
            std::string decrypted_str(decrypted.begin(), decrypted.end());
            std::cout << "Decrypted message: " << decrypted_str << std::endl;
            std::cout << "Encryption/Decryption: " << (message_str == decrypted_str ? "SUCCESS" : "FAILED") << std::endl;
        } else {
            std::cout << "Decryption failed: " << decrypted_result.error() << std::endl;
        }
        std::cout << std::endl;

        // Test KEM encapsulation/decapsulation
        std::cout << "Testing KEM encapsulation/decapsulation..." << std::endl;

        // Encapsulate (sender side)
        auto encaps_result = encapsulate(keypair.public_key());
        if (encaps_result.is_success()) {
            auto [ciphertext_kem, shared_secret_sender] = encaps_result.value();
            print_hex("KEM Ciphertext", ciphertext_kem);
            print_hex("Sender's shared secret", shared_secret_sender);

            // Decapsulate (receiver side)
            auto decaps_result = decapsulate(keypair.private_key(), ciphertext_kem);
            if (decaps_result.is_success()) {
                bytes shared_secret_receiver = decaps_result.value();
                print_hex("Receiver's shared secret", shared_secret_receiver);

                bool secrets_match = (shared_secret_sender == shared_secret_receiver);
                std::cout << "Shared secrets match: " << (secrets_match ? "YES" : "NO") << std::endl;
            } else {
                std::cout << "Decapsulation failed: " << decaps_result.error() << std::endl;
            }
        } else {
            std::cout << "Encapsulation failed: " << encaps_result.error() << std::endl;
        }
        std::cout << std::endl;

        // Test different security levels
        std::cout << "Testing different security levels..." << std::endl;

        // Kyber512
        std::cout << "\nKyber512:" << std::endl;
        KeyPair keypair_512 = generate_keypair(SecurityLevel::Kyber512);
        std::cout << "  Public key size: " << keypair_512.public_key().size() << " bytes" << std::endl;
        std::cout << "  Private key size: " << keypair_512.private_key().size() << " bytes" << std::endl;
        std::cout << "  Ciphertext size: " << get_ciphertext_size(SecurityLevel::Kyber512) << " bytes" << std::endl;

        // Kyber768
        std::cout << "\nKyber768:" << std::endl;
        std::cout << "  Public key size: " << keypair.public_key().size() << " bytes" << std::endl;
        std::cout << "  Private key size: " << keypair.private_key().size() << " bytes" << std::endl;
        std::cout << "  Ciphertext size: " << get_ciphertext_size(SecurityLevel::Kyber768) << " bytes" << std::endl;

        // Kyber1024
        std::cout << "\nKyber1024:" << std::endl;
        KeyPair keypair_1024 = generate_keypair(SecurityLevel::Kyber1024);
        std::cout << "  Public key size: " << keypair_1024.public_key().size() << " bytes" << std::endl;
        std::cout << "  Private key size: " << keypair_1024.private_key().size() << " bytes" << std::endl;
        std::cout << "  Ciphertext size: " << get_ciphertext_size(SecurityLevel::Kyber1024) << " bytes" << std::endl;

        std::cout << std::endl;

        // Test multiple encryptions with same message
        std::cout << "Testing probabilistic encryption..." << std::endl;
        bytes ciphertext1 = encrypt(keypair.public_key(), message);
        bytes ciphertext2 = encrypt(keypair.public_key(), message);

        bool ciphertexts_different = (ciphertext1 != ciphertext2);
        std::cout << "Multiple encryptions produce different ciphertexts: " << (ciphertexts_different ? "YES" : "NO") << std::endl;

        // But both should decrypt to the same message
        auto decrypted1_result = decrypt(keypair.private_key(), ciphertext1);
        auto decrypted2_result = decrypt(keypair.private_key(), ciphertext2);

        if (decrypted1_result.is_success() && decrypted2_result.is_success()) {
            bool messages_same = (decrypted1_result.value() == decrypted2_result.value() &&
                                decrypted1_result.value() == message);
            std::cout << "Both ciphertexts decrypt to same message: " << (messages_same ? "YES" : "NO") << std::endl;
        }

        std::cout << std::endl;

        // Test error handling
        std::cout << "Testing error handling..." << std::endl;

        // Wrong key
        KeyPair wrong_keypair = generate_keypair(SecurityLevel::Kyber768);
        auto wrong_decrypt_result = decrypt(wrong_keypair.private_key(), ciphertext);
        std::cout << "Decryption with wrong key: " << (wrong_decrypt_result.is_success() ? "UNEXPECTED SUCCESS" : "EXPECTED FAILURE") << std::endl;

        // Corrupted ciphertext
        if (!ciphertext.empty()) {
            bytes corrupted_ciphertext = ciphertext;
            corrupted_ciphertext[0] ^= 0xFF;
            auto corrupted_decrypt_result = decrypt(keypair.private_key(), corrupted_ciphertext);
            std::cout << "Decryption with corrupted ciphertext: " << (corrupted_decrypt_result.is_success() ? "UNEXPECTED SUCCESS" : "EXPECTED FAILURE") << std::endl;
        }

        std::cout << std::endl;

        std::cout << "=== Kyber KEM Example Complete ===" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}