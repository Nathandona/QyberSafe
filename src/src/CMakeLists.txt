# Main QyberSafe library
add_library(qybersafe STATIC
    core/crypto_types.cpp
    core/random.cpp
    core/memory.cpp
    kyber/kyber_kem.cpp
    dilithium/dilithium_sig.cpp
    sphincsplus/sphincsplus_sig.cpp
    hybrid/hybrid_encryption.cpp
    utils/hex.cpp
    utils/base64.cpp
)

target_link_libraries(qybersafe OpenSSL::SSL OpenSSL::Crypto)

# Set library properties
set_target_properties(qybersafe PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "../include/qybersafe/qybersafe.h"
)

# Installation
install(TARGETS qybersafe
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qybersafe
)