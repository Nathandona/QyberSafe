#ifndef QYBERSAFE_UTILS_BASE64_H
#define QYBERSAFE_UTILS_BASE64_H

#include <string>
#include "qybersafe/core/crypto_types.h"

namespace qybersafe::utils {

std::string encode_base64(const core::bytes& data);
core::bytes decode_base64(const std::string& base64_str);
bool is_valid_base64(const std::string& base64_str);
std::string format_base64(const std::string& base64_str, size_t line_length = 76);

} // namespace qybersafe::utils

#endif // QYBERSAFE_UTILS_BASE64_H