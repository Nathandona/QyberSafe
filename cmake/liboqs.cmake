# Fetch and build liboqs (Open Quantum Safe) as a vendored dependency.
#
# QyberSafe wraps liboqs for its post-quantum primitives rather than shipping
# its own implementations. The build is pinned to a release tag and trimmed to
# only the algorithms QyberSafe currently exposes; expand OQS_MINIMAL_BUILD as
# new milestones wrap more algorithms (ML-DSA, SLH-DSA).

include(FetchContent)

set(QYBERSAFE_LIBOQS_TAG "0.15.0" CACHE STRING "liboqs git tag to build against")

set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
# Only the algorithms QyberSafe currently wraps: ML-KEM (FIPS 203), ML-DSA
# (FIPS 204), and SLH-DSA (FIPS 205, "pure" SHA2 small-signature variants).
set(OQS_MINIMAL_BUILD
    "KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_slh_dsa_pure_sha2_128s;SIG_slh_dsa_pure_sha2_192s;SIG_slh_dsa_pure_sha2_256s"
    CACHE STRING "" FORCE)

FetchContent_Declare(liboqs
    GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
    GIT_TAG ${QYBERSAFE_LIBOQS_TAG}
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(liboqs)

# The in-tree `oqs` target does not export its generated include directory, so
# expose it for consumers that link `oqs`.
set(QYBERSAFE_LIBOQS_INCLUDE_DIR "${liboqs_BINARY_DIR}/include"
    CACHE INTERNAL "liboqs generated headers")
