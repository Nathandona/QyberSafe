# Testing configuration for QyberSafe
cmake_minimum_required(VERSION 3.16)

# Find GoogleTest
find_package(GTest REQUIRED)

# Enable testing
enable_testing()

# Test source files
set(TEST_SOURCES
    test_crypto_types.cpp
    test_kyber.cpp
    test_dilithium.cpp
    test_sphincsplus.cpp
    test_hybrid.cpp
    test_secure_random.cpp
    test_memory.cpp
)

# Create test executable
add_executable(qybersafe_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(qybersafe_tests
    GTest::GTest
    GTest::Main
    qybersafe
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Add include directories
target_include_directories(qybersafe_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Set compiler flags for tests
target_compile_options(qybersafe_tests PRIVATE
    $<$<CONFIG:Debug>:-g -O0 -DDEBUG>
    $<$<CONFIG:Release>:-O2 -DNDEBUG>
    -Wall -Wextra -Wpedantic
)

# Add tests
add_test(NAME AllTests COMMAND qybersafe_tests)

# Individual test targets
foreach(TEST_FILE ${TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
    add_test(NAME ${TEST_NAME} COMMAND qybersafe_tests --gtest_filter=${TEST_NAME}.*)
endforeach()

# Custom target to run all tests
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS qybersafe_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running all QyberSafe tests"
)