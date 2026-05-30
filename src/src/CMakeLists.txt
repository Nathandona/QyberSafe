# QyberSafe core library.
#
# Only modules that have been ported onto liboqs are compiled. The toy
# dilithium/sphincsplus/hybrid/utils sources remain in the tree but are excluded
# from the build until their respective milestones rewrite them (see SPEC.md).
add_library(qybersafe STATIC
    core/crypto_types.cpp
    core/secure_random.cpp
    core/memory.cpp
    kyber/kyber_kem.cpp
    # dilithium/dilithium_sig.cpp        # M1
    # sphincsplus/sphincsplus_sig.cpp    # M1
    # hybrid/hybrid_encryption.cpp       # M2
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

# Python bindings are deferred to the Python-parity milestone (SPEC.md, M4).
# The current bindings.cpp still references the unported modules.
option(QYBERSAFE_BUILD_PYTHON "Build the pybind11 Python module" OFF)
if(QYBERSAFE_BUILD_PYTHON)
    find_package(pybind11 QUIET)
    if(pybind11_FOUND)
        pybind11_add_module(qybersafe_python
            ../bindings.cpp
            $<TARGET_OBJECTS:qybersafe>
        )
        target_compile_definitions(qybersafe_python PRIVATE VERSION_INFO=${PROJECT_VERSION})
        target_link_libraries(qybersafe_python PRIVATE qybersafe)
        set_target_properties(qybersafe_python PROPERTIES
            OUTPUT_NAME qybersafe
            SUFFIX "${PYTHON_MODULE_EXTENSION}"
        )
    endif()
endif()

# Installation
install(TARGETS qybersafe
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qybersafe
)

if(QYBERSAFE_BUILD_PYTHON AND TARGET qybersafe_python)
    install(TARGETS qybersafe_python
        LIBRARY DESTINATION ${PYTHON_SITE_PACKAGES}
    )
endif()
