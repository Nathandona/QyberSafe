#include "qybersafe/qybersafe.h"
#include <iostream>
#include <iomanip>
#include <string>

using namespace qybersafe;
using namespace qybersafe::hybrid;
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
    std::cout << "=== QyberSafe Hybrid Encryption Example ===" << std::endl;
    std::cout << std::endl;

    try {
        // Generate a hybrid key pair
        std::cout << "Generating hybrid key pair..." << std::endl;
        HybridKeyPair keypair = generate_hybrid_keypair();

        print_hex("Hybrid public key", keypair.public_key().data());
        print_hex("Hybrid private key", keypair.private_key().data());

        std::cout << "PQC public key size: " << keypair.public_key().pq_key().size() << " bytes" << std::endl;
        std::cout << "Classical key size: " << keypair.public_key().classical_key().size() << " bytes" << std::endl;
        std::cout << std::endl;

        // Test hybrid encryption/decryption
        std::cout << "Testing hybrid encryption/decryption..." << std::endl;
        std::string message_str = "Hello, Hybrid Encryption! This message is protected by both post-quantum and classical cryptography.";
        bytes message(message_str.begin(), message_str.end());

        std::cout << "Original message (" << message.size() << " bytes): " << message_str << std::endl;

        // Encrypt the message
        bytes ciphertext = hybrid_encrypt(keypair.public_key(), message);
        print_hex("Ciphertext", ciphertext);
        std::cout << "Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;
        std::cout << "Size overhead: " << (ciphertext.size() - message.size()) << " bytes ("
                  << ((float)(ciphertext.size() - message.size()) / message.size() * 100) << "%)" << std::endl;

        // Decrypt the message
        bytes decrypted_message = hybrid_decrypt(keypair.private_key(), ciphertext);
        std::string decrypted_str(decrypted_message.begin(), decrypted_message.end());
        std::cout << "Decrypted message: " << decrypted_str << std::endl;
        std::cout << "Encryption/Decryption: " << (message_str == decrypted_str ? "SUCCESS" : "FAILED") << std::endl;
        std::cout << std::endl;

        // Test multiple encryptions
        std::cout << "Testing probabilistic encryption..." << std::endl;
        bytes ciphertext1 = hybrid_encrypt(keypair.public_key(), message);
        bytes ciphertext2 = hybrid_encrypt(keypair.public_key(), message);

        bool ciphertexts_different = (ciphertext1 != ciphertext2);
        std::cout << "Multiple encryptions produce different ciphertexts: " << (ciphertexts_different ? "YES" : "NO") << std::endl;

        // Both should decrypt to the same message
        bytes decrypted1 = hybrid_decrypt(keypair.private_key(), ciphertext1);
        bytes decrypted2 = hybrid_decrypt(keypair.private_key(), ciphertext2);

        bool messages_same = (decrypted1 == decrypted2 && decrypted1 == message);
        std::cout << "Both ciphertexts decrypt to same message: " << (messages_same ? "YES" : "NO") << std::endl;
        std::cout << std::endl;

        // Test different message sizes
        std::cout << "Testing different message sizes..." << std::endl;

        // Empty message
        bytes empty_message;
        bytes empty_ciphertext = hybrid_encrypt(keypair.public_key(), empty_message);
        bytes empty_decrypted = hybrid_decrypt(keypair.private_key(), empty_ciphertext);
        std::cout << "Empty message: " << (empty_decrypted == empty_message ? "SUCCESS" : "FAILED") << std::endl;
        std::cout << "  Ciphertext size: " << empty_ciphertext.size() << " bytes" << std::endl;

        // Small message
        bytes small_message = {'H', 'i', '!'};
        bytes small_ciphertext = hybrid_encrypt(keypair.public_key(), small_message);
        bytes small_decrypted = hybrid_decrypt(keypair.private_key(), small_ciphertext);
        std::cout << "Small message: " << (small_decrypted == small_message ? "SUCCESS" : "FAILED") << std::endl;
        std::cout << "  Ciphertext size: " << small_ciphertext.size() << " bytes" << std::endl;

        // Large message (10KB)
        bytes large_message(10240, 0x42);
        bytes large_ciphertext = hybrid_encrypt(keypair.public_key(), large_message);
        bytes large_decrypted = hybrid_decrypt(keypair.private_key(), large_ciphertext);
        std::cout << "Large message (10KB): " << (large_decrypted == large_message ? "SUCCESS" : "FAILED") << std::endl;
        std::cout << "  Ciphertext size: " << large_ciphertext.size() << " bytes" << std::endl;

        std::cout << std::endl;

        // Test key extraction
        std::cout << "Testing public key extraction..." << std::endl;
        HybridPublicKey extracted_pk = keypair.private_key().get_public_key();
        bool keys_match = (extracted_pk.data() == keypair.public_key().data());
        std::cout << "Extracted public key matches original: " << (keys_match ? "YES" : "NO") << std::endl;

        // Test that extracted key works
        bytes test_message = {'T', 'e', 's', 't'};
        bytes test_ciphertext = hybrid_encrypt(extracted_pk, test_message);
        bytes test_decrypted = hybrid_decrypt(keypair.private_key(), test_ciphertext);
        bool extracted_key_works = (test_decrypted == test_message);
        std::cout << "Extracted public key works for encryption: " << (extracted_key_works ? "YES" : "NO") << std::endl;

        std::cout << std::endl;

        // Test error handling
        std::cout << "Testing error handling..." << std::endl;

        // Wrong key
        HybridKeyPair wrong_keypair = generate_hybrid_keypair();
        try {
            bytes wrong_decrypted = hybrid_decrypt(wrong_keypair.private_key(), ciphertext);
            std::cout << "Decryption with wrong key: UNEXPECTED SUCCESS" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "Decryption with wrong key: EXPECTED FAILURE (" << e.what() << ")" << std::endl;
        }

        // Corrupted ciphertext
        if (!ciphertext.empty()) {
            bytes corrupted_ciphertext = ciphertext;
            corrupted_ciphertext[4] ^= 0xFF; // Modify PQ encrypted key part
            try {
                bytes corrupted_decrypted = hybrid_decrypt(keypair.private_key(), corrupted_ciphertext);
                std::cout << "Decryption with corrupted ciphertext: UNEXPECTED SUCCESS" << std::endl;
            } catch (const std::exception& e) {
                std::cout << "Decryption with corrupted ciphertext: EXPECTED FAILURE (" << e.what() << ")" << std::endl;
            }
        }

        std::cout << std::endl;

        // Test key serialization
        std::cout << "Testing key serialization..." << std::endl;

        // Serialize keys
        bytes pk_data = keypair.public_key().data();
        bytes sk_data = keypair.private_key().data();

        // Reconstruct keys
        HybridPublicKey reconstructed_pk(pk_data);
        HybridPrivateKey reconstructed_sk(sk_data);

        // Test reconstructed keys
        bytes reconstructed_ciphertext = hybrid_encrypt(reconstructed_pk, message);
        bytes reconstructed_decrypted = hybrid_decrypt(reconstructed_sk, reconstructed_ciphertext);
        bool reconstructed_keys_work = (reconstructed_decrypted == message);
        std::cout << "Reconstructed keys work: " << (reconstructed_keys_work ? "YES" : "NO") << std::endl;

        // Test cross-compatibility
        bytes cross_decrypted = hybrid_decrypt(keypair.private_key(), reconstructed_ciphertext);
        bool cross_compatible = (cross_decrypted == message);
        std::cout << "Original private key works with reconstructed public key: " << (cross_compatible ? "YES" : "NO") << std::endl;

        std::cout << std::endl;

        // Test security properties
        std::cout << "Testing security properties..." << std::endl;

        // Test tamper resistance
        bytes tampered_ciphertext = ciphertext;
        size_t tamper_pos = 4 + 32; // Somewhere in the PQ encrypted key part
        if (tamper_pos < tampered_ciphertext.size()) {
            tampered_ciphertext[tamper_pos] ^= 0xFF;
            try {
                bytes tampered_decrypted = hybrid_decrypt(keypair.private_key(), tampered_ciphertext);
                std::cout << "Tampered ciphertext detected: NO - Authentication failed!" << std::endl;
            } catch (const std::exception& e) {
                std::cout << "Tampered ciphertext detected: YES - " << e.what() << std::endl;
            }
        }

        // Test confidentiality (ciphertext doesn't reveal message)
        bool ciphertext_looks_random = true;
        for (size_t i = 0; i < std::min(ciphertext.size(), size_t(100)); ++i) {
            // Check if ciphertext contains patterns that might indicate plaintext
            if (i < message.size() && ciphertext[i] == message[i]) {
                // This is not a robust test, just a basic check
                ciphertext_looks_random = false;
                break;
            }
        }
        std::cout << "Ciphertext appears randomized: " << (ciphertext_looks_random ? "YES" : "NO") << std::endl;

        std::cout << std::endl;

        std::cout << "=== Hybrid Encryption Example Complete ===" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}