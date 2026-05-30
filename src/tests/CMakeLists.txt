# Testing configuration for QyberSafe.
#
# GoogleTest is fetched and built so the suite is never silently skipped.
# For M0 only the ML-KEM (Kyber) tests are wired in; tests for the other
# modules are re-added as those modules are rewritten on top of liboqs.

include(FetchContent)
FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
    GIT_SHALLOW TRUE
)
# Use the shared C runtime on Windows/MSVC to match the rest of the build.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

set(TEST_SOURCES
    test_kyber.cpp
    test_dilithium.cpp
    test_sphincsplus.cpp
    # test_crypto_types.cpp   # re-enable as core types are finalized
    # test_secure_random.cpp
    # test_memory.cpp
    # test_hybrid.cpp         # M2: rewrite on the hybrid envelope
)

add_executable(qybersafe_tests ${TEST_SOURCES})

target_link_libraries(qybersafe_tests PRIVATE
    qybersafe
    OpenSSL::SSL
    OpenSSL::Crypto
    oqs
    gtest
    gtest_main
)

target_include_directories(qybersafe_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

add_test(NAME qybersafe_tests COMMAND qybersafe_tests)

add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS qybersafe_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running QyberSafe tests"
)
