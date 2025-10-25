#include "qybersafe/core/crypto_types.h"
#include "qybersafe/utils/hex.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cctype>

namespace qybersafe::utils {

std::string encode_hex(const core::bytes& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (const auto& byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }

    return ss.str();
}

core::bytes decode_hex(const std::string& hex_str) {
    if (hex_str.empty()) {
        return {};
    }

    // Remove optional prefix
    std::string clean_hex = hex_str;
    if (clean_hex.substr(0, 2) == "0x" || clean_hex.substr(0, 2) == "0X") {
        clean_hex = clean_hex.substr(2);
    }

    // Check if length is even
    if (clean_hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }

    core::bytes result;
    result.reserve(clean_hex.length() / 2);

    for (size_t i = 0; i < clean_hex.length(); i += 2) {
        std::string byte_string = clean_hex.substr(i, 2);

        // Validate hex characters
        for (char c : byte_string) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) {
                throw std::invalid_argument("Invalid hex character: " + std::string(1, c));
            }
        }

        uint8_t byte = static_cast<uint8_t>(std::strtol(byte_string.c_str(), nullptr, 16));
        result.push_back(byte);
    }

    return result;
}

bool is_valid_hex(const std::string& hex_str) {
    if (hex_str.empty()) {
        return true;
    }

    std::string clean_hex = hex_str;
    if (clean_hex.substr(0, 2) == "0x" || clean_hex.substr(0, 2) == "0X") {
        clean_hex = clean_hex.substr(2);
    }

    if (clean_hex.length() % 2 != 0) {
        return false;
    }

    for (char c : clean_hex) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }

    return true;
}

std::string format_hex(const core::bytes& data, bool uppercase, bool prefix) {
    std::stringstream ss;

    if (uppercase) {
        ss << std::uppercase;
    }

    ss << std::hex << std::setfill('0');

    if (prefix) {
        ss << "0x";
    }

    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0 && i % 16 == 0) {
            ss << "\n";
        } else if (i > 0 && i % 8 == 0) {
            ss << "  ";
        } else if (i > 0) {
            ss << " ";
        }

        ss << std::setw(2) << static_cast<int>(data[i]);
    }

    return ss.str();
}

} // namespace qybersafe::utils