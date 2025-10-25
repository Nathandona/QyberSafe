#include "qybersafe/qybersafe.h"
#include <iostream>
#include <iomanip>
#include <string>

using namespace qybersafe;
using namespace qybersafe::dilithium;
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
    std::cout << "=== QyberSafe Dilithium Signature Example ===" << std::endl;
    std::cout << std::endl;

    try {
        // Generate a Dilithium key pair
        std::cout << "Generating Dilithium3 key pair..." << std::endl;
        SigningKeyPair keypair = generate_keypair(SecurityLevel::Dilithium3);

        print_hex("Verifying key", keypair.verifying_key().data());
        print_hex("Signing key", keypair.signing_key().data());
        std::cout << std::endl;

        // Test signing and verification
        std::cout << "Testing digital signature..." << std::endl;
        std::string message_str = "Hello, Dilithium!";
        bytes message(message_str.begin(), message_str.end());

        std::cout << "Original message: " << message_str << std::endl;

        // Sign the message
        auto signature_result = sign(keypair.signing_key(), message);
        if (signature_result.is_success()) {
            bytes signature = signature_result.value();
            print_hex("Signature", signature);

            // Verify the signature
            bool verification_result = verify(keypair.verifying_key(), message, signature);
            std::cout << "Signature verification: " << (verification_result ? "SUCCESS" : "FAILED") << std::endl;
        } else {
            std::cout << "Signing failed: " << signature_result.error() << std::endl;
        }
        std::cout << std::endl;

        // Test different security levels
        std::cout << "Testing different security levels..." << std::endl;

        // Dilithium2
        std::cout << "\nDilithium2:" << std::endl;
        SigningKeyPair keypair_2 = generate_keypair(SecurityLevel::Dilithium2);
        std::cout << "  Verifying key size: " << keypair_2.verifying_key().size() << " bytes" << std::endl;
        std::cout << "  Signing key size: " << keypair_2.signing_key().size() << " bytes" << std::endl;
        std::cout << "  Signature size: " << get_signature_size(SecurityLevel::Dilithium2) << " bytes" << std::endl;

        // Dilithium3
        std::cout << "\nDilithium3:" << std::endl;
        std::cout << "  Verifying key size: " << keypair.verifying_key().size() << " bytes" << std::endl;
        std::cout << "  Signing key size: " << keypair.signing_key().size() << " bytes" << std::endl;
        std::cout << "  Signature size: " << get_signature_size(SecurityLevel::Dilithium3) << " bytes" << std::endl;

        // Dilithium5
        std::cout << "\nDilithium5:" << std::endl;
        SigningKeyPair keypair_5 = generate_keypair(SecurityLevel::Dilithium5);
        std::cout << "  Verifying key size: " << keypair_5.verifying_key().size() << " bytes" << std::endl;
        std::cout << "  Signing key size: " << keypair_5.signing_key().size() << " bytes" << std::endl;
        std::cout << "  Signature size: " << get_signature_size(SecurityLevel::Dilithium5) << " bytes" << std::endl;

        std::cout << std::endl;

        // Test multiple signatures
        std::cout << "Testing multiple signatures..." << std::endl;
        auto sig1_result = sign(keypair.signing_key(), message);
        auto sig2_result = sign(keypair.signing_key(), message);

        if (sig1_result.is_success() && sig2_result.is_success()) {
            bytes sig1 = sig1_result.value();
            bytes sig2 = sig2_result.value();

            bool signatures_different = (sig1 != sig2);
            std::cout << "Multiple signatures are different: " << (signatures_different ? "YES" : "NO") << std::endl;

            // Both should verify
            bool sig1_valid = verify(keypair.verifying_key(), message, sig1);
            bool sig2_valid = verify(keypair.verifying_key(), message, sig2);
            std::cout << "Both signatures verify: " << (sig1_valid && sig2_valid ? "YES" : "NO") << std::endl;
        }

        std::cout << std::endl;

        // Test message hashing
        std::cout << "Testing message hashing..." << std::endl;
        bytes message_hash = hash_message(message);
        print_hex("Message hash", message_hash);
        std::cout << std::endl;

        // Test key extraction
        std::cout << "Testing public key extraction..." << std::endl;
        VerifyingKey extracted_vk = keypair.signing_key().get_verifying_key();
        bool keys_match = (extracted_vk.data() == keypair.verifying_key().data());
        std::cout << "Extracted public key matches original: " << (keys_match ? "YES" : "NO") << std::endl;

        // Test that extracted key works for verification
        if (sig1_result.is_success()) {
            bytes sig1 = sig1_result.value();
            bool extracted_key_verifies = verify(extracted_vk, message, sig1);
            std::cout << "Extracted key can verify signatures: " << (extracted_key_verifies ? "YES" : "NO") << std::endl;
        }

        std::cout << std::endl;

        // Test error handling
        std::cout << "Testing error handling..." << std::endl;

        if (sig1_result.is_success()) {
            bytes signature = sig1_result.value();

            // Wrong message
            std::string wrong_message_str = "Wrong message";
            bytes wrong_message(wrong_message_str.begin(), wrong_message_str.end());
            bool wrong_message_verification = verify(keypair.verifying_key(), wrong_message, signature);
            std::cout << "Verify with wrong message: " << (wrong_message_verification ? "UNEXPECTED SUCCESS" : "EXPECTED FAILURE") << std::endl;

            // Wrong key
            bool wrong_key_verification = verify(keypair_2.verifying_key(), message, signature);
            std::cout << "Verify with wrong key: " << (wrong_key_verification ? "UNEXPECTED SUCCESS" : "EXPECTED FAILURE") << std::endl;

            // Corrupted signature
            if (!signature.empty()) {
                bytes corrupted_signature = signature;
                corrupted_signature[0] ^= 0xFF;
                bool corrupted_verification = verify(keypair.verifying_key(), message, corrupted_signature);
                std::cout << "Verify with corrupted signature: " << (corrupted_verification ? "UNEXPECTED SUCCESS" : "EXPECTED FAILURE") << std::endl;
            }
        }

        std::cout << std::endl;

        // Test different message sizes
        std::cout << "Testing different message sizes..." << std::endl;

        // Empty message
        bytes empty_message;
        auto empty_sig_result = sign(keypair.signing_key(), empty_message);
        if (empty_sig_result.is_success()) {
            bool empty_verification = verify(keypair.verifying_key(), empty_message, empty_sig_result.value());
            std::cout << "Empty message signature: " << (empty_verification ? "SUCCESS" : "FAILED") << std::endl;
        }

        // Large message (1KB)
        bytes large_message(1024, 0x42);
        auto large_sig_result = sign(keypair.signing_key(), large_message);
        if (large_sig_result.is_success()) {
            bool large_verification = verify(keypair.verifying_key(), large_message, large_sig_result.value());
            std::cout << "Large message (1KB) signature: " << (large_verification ? "SUCCESS" : "FAILED") << std::endl;
        }

        std::cout << std::endl;

        // Test key serialization
        std::cout << "Testing key serialization..." << std::endl;

        // Serialize keys
        bytes vk_data = keypair.verifying_key().data();
        bytes sk_data = keypair.signing_key().data();

        // Reconstruct keys
        VerifyingKey reconstructed_vk(vk_data);
        SigningKey reconstructed_sk(sk_data);

        // Test reconstructed keys
        if (sig1_result.is_success()) {
            bytes signature = sig1_result.value();
            bool reconstructed_verifies = verify(reconstructed_vk, message, signature);
            std::cout << "Reconstructed verifying key works: " << (reconstructed_verifies ? "YES" : "NO") << std::endl;

            // Test signing with reconstructed key
            auto reconstructed_sig_result = sign(reconstructed_sk, message);
            if (reconstructed_sig_result.is_success()) {
                bool reconstructed_sig_verifies = verify(keypair.verifying_key(), message, reconstructed_sig_result.value());
                std::cout << "Signature from reconstructed signing key verifies: " << (reconstructed_sig_verifies ? "YES" : "NO") << std::endl;
            }
        }

        std::cout << std::endl;

        std::cout << "=== Dilithium Signature Example Complete ===" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}