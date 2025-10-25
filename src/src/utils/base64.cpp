#include "qybersafe/core/crypto_types.h"
#include "qybersafe/utils/base64.h"
#include <sstream>
#include <stdexcept>
#include <vector>
#include <cstring>

namespace qybersafe::utils {

using core::bytes;

// Base64 encoding table
static const char ENCODE_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 decoding table
static const int8_t DECODE_TABLE[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};

std::string encode_base64(const core::bytes& data) {
    if (data.empty()) {
        return "";
    }

    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < data.size()) {
        // Get 3 bytes (24 bits)
        uint32_t triple = (static_cast<uint32_t>(data[i]) << 16);
        if (i + 1 < data.size()) {
            triple |= (static_cast<uint32_t>(data[i + 1]) << 8);
        }
        if (i + 2 < data.size()) {
            triple |= static_cast<uint32_t>(data[i + 2]);
        }

        // Extract 4 groups of 6 bits
        result += ENCODE_TABLE[(triple >> 18) & 0x3F];
        result += ENCODE_TABLE[(triple >> 12) & 0x3F];
        result += (i + 1 < data.size()) ? ENCODE_TABLE[(triple >> 6) & 0x3F] : '=';
        result += (i + 2 < data.size()) ? ENCODE_TABLE[triple & 0x3F] : '=';

        i += 3;
    }

    return result;
}

core::bytes decode_base64(const std::string& base64_str) {
    if (base64_str.empty()) {
        return {};
    }

    // Remove whitespace
    std::string clean_str;
    clean_str.reserve(base64_str.length());
    for (char c : base64_str) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean_str += c;
        }
    }

    // Check if length is valid (must be multiple of 4)
    if (clean_str.length() % 4 != 0) {
        throw std::invalid_argument("Base64 string length must be multiple of 4");
    }

    // Count padding characters
    size_t padding = 0;
    if (!clean_str.empty() && clean_str.back() == '=') {
        padding = 1;
        if (clean_str.length() > 1 && clean_str[clean_str.length() - 2] == '=') {
            padding = 2;
        }
    }

    // Validate characters
    for (char c : clean_str) {
        if (c != '=' && (c < 0 || c >= 128 || DECODE_TABLE[c] == -1)) {
            throw std::invalid_argument("Invalid Base64 character: " + std::string(1, c));
        }
    }

    bytes result;
    result.reserve((clean_str.length() / 4) * 3 - padding);

    for (size_t i = 0; i < clean_str.length(); i += 4) {
        // Get 4 characters
        uint32_t quadruple = 0;
        for (int j = 0; j < 4; ++j) {
            char c = clean_str[i + j];
            if (c == '=') {
                // Padding character
                quadruple <<= 6;
            } else {
                quadruple = (quadruple << 6) | static_cast<uint32_t>(DECODE_TABLE[c]);
            }
        }

        // Extract 3 bytes
        result.push_back(static_cast<uint8_t>((quadruple >> 16) & 0xFF));
        if (i + 2 < clean_str.length() && clean_str[i + 2] != '=') {
            result.push_back(static_cast<uint8_t>((quadruple >> 8) & 0xFF));
        }
        if (i + 3 < clean_str.length() && clean_str[i + 3] != '=') {
            result.push_back(static_cast<uint8_t>(quadruple & 0xFF));
        }
    }

    return result;
}

bool is_valid_base64(const std::string& base64_str) {
    if (base64_str.empty()) {
        return true;
    }

    // Remove whitespace
    std::string clean_str;
    clean_str.reserve(base64_str.length());
    for (char c : base64_str) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean_str += c;
        }
    }

    // Check if length is valid
    if (clean_str.length() % 4 != 0) {
        return false;
    }

    // Validate characters
    for (size_t i = 0; i < clean_str.length(); ++i) {
        char c = clean_str[i];
        if (c == '=') {
            // Padding can only appear at the end
            if (i < clean_str.length() - 2) {
                return false;
            }
            if (i == clean_str.length() - 2 && clean_str[i + 1] != '=') {
                return false;
            }
        } else if (c < 0 || c >= 128 || DECODE_TABLE[c] == -1) {
            return false;
        }
    }

    return true;
}

std::string format_base64(const std::string& base64_str, size_t line_length) {
    if (base64_str.empty() || line_length == 0) {
        return base64_str;
    }

    std::string result;
    result.reserve(base64_str.length() + base64_str.length() / line_length);

    for (size_t i = 0; i < base64_str.length(); ++i) {
        result += base64_str[i];

        if (i > 0 && (i + 1) % line_length == 0 && i + 1 < base64_str.length()) {
            result += '\n';
        }
    }

    return result;
}

} // namespace qybersafe::utils