#include <iostream>
#include "qybersafe/core/crypto_types.h"
#include "qybersafe/core/exceptions.h"

using namespace qybersafe::core;

// Example function demonstrating enhanced error handling
Result<int> divide_numbers(int a, int b) {
    if (b == 0) {
        return Result<int>::error(ErrorCode::INVALID_PARAMETERS);
    }
    return Result<int>::success(a / b);
}

// Example showing functional chaining
Result<std::string> process_number(int input) {
    return divide_numbers(input, 2)
        .map([](int result) {
            return result * 10;
        })
        .map([](int result) {
            return "Result: " + std::to_string(result);
        });
}

int main() {
    std::cout << "=== QyberSafe Enhanced Error Handling Examples ===\n\n";

    // Example 1: Basic Result usage
    std::cout << "1. Basic Result usage:\n";
    auto result1 = divide_numbers(10, 2);
    if (result1.is_success()) {
        std::cout << "   Success: " << result1.value() << "\n";
    } else {
        std::cout << "   Error: " << result1.error() << "\n";
    }

    auto result2 = divide_numbers(10, 0);
    if (result2.is_success()) {
        std::cout << "   Success: " << result2.value() << "\n";
    } else {
        std::cout << "   Error: " << result2.error() << "\n";
    }

    // Example 2: Functional chaining
    std::cout << "\n2. Functional chaining:\n";
    auto chain_result = process_number(20);
    if (chain_result.is_success()) {
        std::cout << "   Chained result: " << chain_result.value() << "\n";
    } else {
        std::cout << "   Chain error: " << chain_result.error() << "\n";
    }

    // Example 3: Exception handling
    std::cout << "\n3. Exception handling:\n";
    try {
        auto bad_result = Result<std::string>::error("Invalid operation");
        std::cout << "   Attempting to get value from error result...\n";
        auto value = bad_result.value(); // This will throw
        std::cout << "   Value: " << value << "\n";
    } catch (const QyberSafeException& e) {
        std::cout << "   Caught QyberSafeException: " << e.what() << "\n";
    }

    // Example 4: Value or default
    std::cout << "\n4. Value or default:\n";
    auto success_result = divide_numbers(8, 2);
    auto error_result = divide_numbers(8, 0);

    std::cout << "   Success value or default: " << success_result.value_or(-1) << "\n";
    std::cout << "   Error value or default: " << error_result.value_or(-1) << "\n";

    // Example 5: Error codes
    std::cout << "\n5. Error codes:\n";
    auto error_code_result = Result<int>::error(ErrorCode::INVALID_PARAMETERS);
    std::cout << "   Error code result: " << error_code_result.error() << "\n";

    return 0;
}