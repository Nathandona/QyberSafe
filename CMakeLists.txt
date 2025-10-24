cmake_minimum_required(VERSION 3.16)
project(QyberSafe VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Find dependencies
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(src/include)
include_directories(src/src)

# Add subdirectories
add_subdirectory(src/src)
add_subdirectory(tests)
add_subdirectory(benchmarks)

# Installation
include(GNUInstallDirs)

install(DIRECTORY src/include/qybersafe
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Create pkg-config file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/qybersafe.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/qybersafe.pc"
    @ONLY
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/qybersafe.pc"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)