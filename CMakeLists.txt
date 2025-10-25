cmake_minimum_required(VERSION 3.16)

# Project configuration with version details
project(QyberSafe
    VERSION 0.1.0
    DESCRIPTION "Post-quantum cryptography library"
    HOMEPAGE_URL "https://github.com/qyber/qybersafe"
    LANGUAGES CXX
)

# Extract version components
math(EXPR QYBERSAFE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
math(EXPR QYBERSAFE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
math(EXPR QYBERSAFE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4 /WX)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    # Additional security warnings
    add_compile_options(-Wformat=2 -Wformat-security -Wnull-dereference)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-Wextra-semi)
    endif()
endif()

# Build type configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Build type specific flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Enable sanitizers for debug builds
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-fsanitize=address -fsanitize=undefined)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    endif()
    add_compile_definitions(DEBUG_BUILD)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    # Optimizations for release builds
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-O3 -march=native)
    endif()
    add_compile_definitions(NDEBUG)
endif()

# Find dependencies
find_package(OpenSSL REQUIRED)

# Include directories - using target_include_directories for better scope
include_directories(src/include)

# Create interface library for headers only
add_library(qybersafe_headers INTERFACE)
add_library(qybersafe::headers ALIAS qybersafe_headers)

# Set include directories for the interface target
target_include_directories(qybersafe_headers INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/include>
    $<INSTALL_INTERFACE:include>
)

# Add subdirectories
add_subdirectory(src/src)

# Testing configuration
option(BUILD_TESTS "Build tests" ON)
option(BUILD_BENCHMARKS "Build benchmarks" OFF)
option(BUILD_EXAMPLES "Build examples" ON)

# Only add tests and benchmarks if enabled and they exist
if(BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/tests")
    enable_testing()
    add_subdirectory(src/tests)
endif()

if(BUILD_BENCHMARKS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks")
    add_subdirectory(src/benchmarks)
endif()

# Examples are optional - only add if CMakeLists.txt exists
if(BUILD_EXAMPLES)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/examples/CMakeLists.txt")
        add_subdirectory(src/examples)
    endif()
endif()

# Static analysis configuration
find_program(CLANG_TIDY_PATH clang-tidy)
if(CLANG_TIDY_PATH)
    option(ENABLE_CLANG_TIDY "Enable clang-tidy static analysis" ON)
    if(ENABLE_CLANG_TIDY)
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_PATH}")
    endif()
endif()

# Installation configuration
include(GNUInstallDirs)

# Install the library
install(TARGETS qybersafe
    EXPORT QyberSafeTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install the headers
install(DIRECTORY src/include/qybersafe
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h"
)

# Export configuration
install(EXPORT QyberSafeTargets
    FILE QyberSafeTargets.cmake
    NAMESPACE qybersafe::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/QyberSafe
)

# Create and install config files (only if template exists)
include(CMakePackageConfigHelpers)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/QyberSafeConfig.cmake.in")
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/QyberSafeConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/QyberSafeConfig.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/QyberSafe
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/QyberSafeConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/QyberSafeConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/QyberSafeConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/QyberSafe
    )
endif()

# Create pkg-config file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/qybersafe.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/qybersafe.pc"
    @ONLY
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/qybersafe.pc"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# Print configuration summary
message(STATUS "")
message(STATUS "QyberSafe Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build benchmarks: ${BUILD_BENCHMARKS}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "  Enable clang-tidy: ${ENABLE_CLANG_TIDY}")
message(STATUS "")