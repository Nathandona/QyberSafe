#include <iostream>
#include <vector>
#include "qybersafe/core/crypto_types.h"

using namespace qybersafe::core;

int main() {
    std::cout << "=== QyberSafe RAII Memory Management Examples ===\n\n";

    // Example 1: SecureBuffer usage
    std::cout << "1. SecureBuffer RAII usage:\n";
    {
        // SecureBuffer automatically allocates and locks memory
        SecureBuffer buffer(1024);

        // Fill with some test data
        for (size_t i = 0; i < buffer.size(); ++i) {
            buffer[i] = static_cast<uint8_t>(i % 256);
        }

        std::cout << "   Created secure buffer of " << buffer.size() << " bytes\n";
        std::cout << "   Memory locked: " << (buffer.is_locked() ? "Yes" : "No") << "\n";

        // Convert to regular bytes for display
        bytes data = buffer.to_bytes();
        std::cout << "   First 5 bytes: ";
        for (size_t i = 0; i < 5 && i < data.size(); ++i) {
            std::cout << static_cast<int>(data[i]) << " ";
        }
        std::cout << "\n";

        // Buffer is automatically zeroed and freed when it goes out of scope
    }
    std::cout << "   Secure buffer automatically zeroed and freed\n\n";

    // Example 2: EvpMdContext RAII wrapper
    std::cout << "2. EVP_MD_CTX RAII wrapper:\n";
    {
        // Context is automatically managed
        raii::EvpMdContext ctx;

        // Initialize SHA256 context
        EVP_MD_CTX* raw_ctx = EVP_MD_CTX_new();
        ctx.reset(raw_ctx);

        std::cout << "   Created managed hash context\n";
        std::cout << "   Context pointer: " << (ctx.get() ? "Valid" : "Null") << "\n";

        // Context is automatically freed when it goes out of scope
    }
    std::cout << "   Hash context automatically freed\n\n";

    // Example 3: Moving RAII objects
    std::cout << "3. Moving RAII objects:\n";
    {
        SecureBuffer original(512);
        original[0] = 42;

        std::cout << "   Original buffer size: " << original.size() << "\n";
        std::cout << "   Original buffer first byte: " << static_cast<int>(original[0]) << "\n";

        // Move to new buffer
        SecureBuffer moved = std::move(original);

        std::cout << "   After move:\n";
        std::cout << "   Original buffer valid: " << (original.data() ? "Yes" : "No") << "\n";
        std::cout << "   Moved buffer size: " << moved.size() << "\n";
        std::cout << "   Moved buffer first byte: " << static_cast<int>(moved[0]) << "\n";
    }
    std::cout << "   Both buffers automatically cleaned up\n\n";

    // Example 4: Comparison with traditional memory management
    std::cout << "4. RAII vs manual management:\n";
    std::cout << "   RAII advantages:\n";
    std::cout << "   - Automatic cleanup (no leaks)\n";
    std::cout << "   - Exception safety\n";
    std::cout << "   - Clear ownership semantics\n";
    std::cout << "   - Memory locking for sensitive data\n";
    std::cout << "   - Secure zeroing on destruction\n";

    return 0;
}