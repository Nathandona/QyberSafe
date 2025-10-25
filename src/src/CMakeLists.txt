# Main QyberSafe library
add_library(qybersafe STATIC
    core/crypto_types.cpp
    core/secure_random.cpp
    core/memory.cpp
    kyber/kyber_kem.cpp
    dilithium/dilithium_sig.cpp
    sphincsplus/sphincsplus_sig.cpp
    hybrid/hybrid_encryption.cpp
    utils/hex.cpp
    utils/base64.cpp
)

target_link_libraries(qybersafe PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(qybersafe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# Set library properties
set_target_properties(qybersafe PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "../include/qybersafe/qybersafe.h"
)

# Find pybind11 for Python bindings
find_package(pybind11 QUIET)
if(pybind11_FOUND)
    # Create Python bindings
    pybind11_add_module(qybersafe_python
        ../bindings.cpp
        $<TARGET_OBJECTS:qybersafe>
    )

    target_compile_definitions(qybersafe_python PRIVATE VERSION_INFO=${PROJECT_VERSION})
    target_link_libraries(qybersafe_python PRIVATE qybersafe)

    # Set Python module properties
    set_target_properties(qybersafe_python PROPERTIES
        OUTPUT_NAME qybersafe
        SUFFIX "${PYTHON_MODULE_EXTENSION}"
    )
endif()

# Installation
install(TARGETS qybersafe
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qybersafe
)

# Install Python bindings if available
if(pybind11_FOUND AND TARGET qybersafe_python)
    install(TARGETS qybersafe_python
        LIBRARY DESTINATION ${PYTHON_SITE_PACKAGES}
    )
endif()