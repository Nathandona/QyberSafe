#ifndef QYBERSAFE_UTILS_HEX_H
#define QYBERSAFE_UTILS_HEX_H

#include <string>
#include "qybersafe/core/crypto_types.h"

namespace qybersafe::utils {

std::string encode_hex(const core::bytes& data);
core::bytes decode_hex(const std::string& hex_str);
bool is_valid_hex(const std::string& hex_str);
std::string format_hex(const core::bytes& data, bool uppercase = false, bool prefix = false);

} // namespace qybersafe::utils

#endif // QYBERSAFE_UTILS_HEX_H