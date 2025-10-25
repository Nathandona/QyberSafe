# Benchmark configuration for QyberSafe
cmake_minimum_required(VERSION 3.16)

# Find Google Benchmark
find_package(benchmark QUIET)

# Benchmark source files
set(BENCHMARK_SOURCES
    benchmark_kyber.cpp
    benchmark_dilithium.cpp
    benchmark_sphincsplus.cpp
    benchmark_hybrid.cpp
    benchmark_memory.cpp
)

# Only create benchmarks if Google Benchmark is found
if(benchmark_FOUND)
    # Create benchmark executable
    add_executable(qybersafe_benchmarks ${BENCHMARK_SOURCES})

    # Link libraries
    target_link_libraries(qybersafe_benchmarks
        benchmark::benchmark
        benchmark::benchmark_main
        qybersafe
        OpenSSL::SSL
        OpenSSL::Crypto
    )

    # Add include directories
    target_include_directories(qybersafe_benchmarks PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )

    # Set compiler flags for benchmarks
    target_compile_options(qybersafe_benchmarks PRIVATE
        $<$<CONFIG:Debug>:-g -O0 -DDEBUG>
        $<$<CONFIG:Release>:-O3 -DNDEBUG -march=native>
        -Wall -Wextra -Wpedantic
    )

    # Custom target to run benchmarks
    add_custom_target(run_benchmarks
        COMMAND qybersafe_benchmarks --benchmark_format=json --benchmark_out=benchmark_results.json
        DEPENDS qybersafe_benchmarks
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running QyberSafe benchmarks"
    )
else()
    message(STATUS "Google Benchmark not found - skipping benchmarks")
endif()