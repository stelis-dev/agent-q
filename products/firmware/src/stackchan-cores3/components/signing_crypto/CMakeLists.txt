if(DEFINED ENV{AGENT_Q_SIGNING_CRYPTO_ROOT})
    set(SIGNING_CRYPTO_ROOT "$ENV{AGENT_Q_SIGNING_CRYPTO_ROOT}")
else()
    get_filename_component(AGENT_Q_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../../.." ABSOLUTE)
    set(SIGNING_CRYPTO_ROOT "${AGENT_Q_REPO_ROOT}/third_party/sui_signing")
endif()

idf_component_register(
    SRCS
        "${SIGNING_CRYPTO_ROOT}/src/core/sign.c"
        "${SIGNING_CRYPTO_ROOT}/src/core/byte_conversions.c"
        "${SIGNING_CRYPTO_ROOT}/src/core/lib/monocypher/monocypher.c"
    INCLUDE_DIRS
        "${SIGNING_CRYPTO_ROOT}/src/core"
)
