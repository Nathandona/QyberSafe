# QyberSafe core library.
#
# Only modules that have been ported onto liboqs are compiled. The toy utils
# sources remain in the tree but are excluded from the build until they are
# needed (see SPEC.md).
add_library(qybersafe STATIC
    core/crypto_types.cpp
    core/secure_random.cpp
    core/memory.cpp
    core/aead.cpp
    kyber/kyber_kem.cpp
    dilithium/dilithium_sig.cpp
    sphincsplus/sphincsplus_sig.cpp
    hybrid/hybrid_encryption.cpp
    api/qybersafe_api.cpp
    # utils/hex.cpp                       # re-add when needed
    # utils/base64.cpp                    # re-add when needed
)

# oqs and qybersafe_warnings are wrapped in BUILD_INTERFACE so they are not
# recorded in the exported target set. Proper install-time bundling of liboqs
# is handled by the packaging milestone (see SPEC.md, M5).
target_link_libraries(qybersafe PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    $<BUILD_INTERFACE:oqs>
    $<BUILD_INTERFACE:qybersafe_warnings>
)
target_include_directories(qybersafe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${QYBERSAFE_LIBOQS_INCLUDE_DIR}
)

# Set library properties
set_target_properties(qybersafe PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "../include/qybersafe/qybersafe.h"
)

# Python bindings (enabled with -DQYBERSAFE_BUILD_PYTHON=ON). The module binds
# the envelope-first public API and is emitted as `_core` inside the Python
# package directory so it can be imported in-tree.
if(QYBERSAFE_BUILD_PYTHON)
    find_package(pybind11 CONFIG REQUIRED)
    pybind11_add_module(qybersafe_python ../bindings.cpp)
    target_link_libraries(qybersafe_python PRIVATE
        qybersafe
        OpenSSL::SSL
        OpenSSL::Crypto
        $<BUILD_INTERFACE:oqs>
    )
    target_include_directories(qybersafe_python PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${QYBERSAFE_LIBOQS_INCLUDE_DIR}
    )
    set_target_properties(qybersafe_python PROPERTIES
        OUTPUT_NAME _core
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/python/qybersafe
    )
endif()

# Installation
if(QYBERSAFE_INSTALL_CXX)
    install(TARGETS qybersafe
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qybersafe
    )
endif()

# The Python extension installs into the package directory; scikit-build-core
# places it in the wheel under qybersafe/.
if(QYBERSAFE_BUILD_PYTHON AND TARGET qybersafe_python)
    install(TARGETS qybersafe_python LIBRARY DESTINATION qybersafe)
endif()
