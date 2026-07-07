if(NOT DEFINED ENV{SIGNING_CRYPTO_ROOT})
    message(FATAL_ERROR "SIGNING_CRYPTO_ROOT must point to the pinned signing source checkout.")
endif()

set(SIGNING_CRYPTO_ROOT "$ENV{SIGNING_CRYPTO_ROOT}")
set(SIGNING_CRYPTO_CORE "${SIGNING_CRYPTO_ROOT}/src/microsui_core")

if(NOT EXISTS "${SIGNING_CRYPTO_CORE}/key_management.c")
    message(FATAL_ERROR "SIGNING_CRYPTO_ROOT does not contain src/microsui_core/key_management.c: ${SIGNING_CRYPTO_ROOT}")
endif()

idf_component_register(
    SRCS
        "${SIGNING_CRYPTO_CORE}/byte_conversions.c"
        "${SIGNING_CRYPTO_CORE}/key_management.c"
        "${SIGNING_CRYPTO_CORE}/sign.c"
        "${SIGNING_CRYPTO_CORE}/lib/monocypher/monocypher.c"
    INCLUDE_DIRS
        "."
        "${SIGNING_CRYPTO_CORE}"
)
