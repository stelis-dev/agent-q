if(NOT DEFINED ENV{SIGNING_CRYPTO_ROOT})
    message(FATAL_ERROR "SIGNING_CRYPTO_ROOT must point to the pinned signing source checkout.")
endif()

set(SIGNING_CRYPTO_ROOT "$ENV{SIGNING_CRYPTO_ROOT}")
set(SIGNING_CRYPTO_CORE "${SIGNING_CRYPTO_ROOT}/src/microsui_core")

if(NOT EXISTS "${SIGNING_CRYPTO_CORE}/sign.c")
    message(FATAL_ERROR "SIGNING_CRYPTO_ROOT does not contain src/microsui_core/sign.c: ${SIGNING_CRYPTO_ROOT}")
endif()

idf_component_register(
    SRCS
        "${SIGNING_CRYPTO_CORE}/sign.c"
        "${SIGNING_CRYPTO_CORE}/byte_conversions.c"
        "${SIGNING_CRYPTO_CORE}/key_management.c"
        "${SIGNING_CRYPTO_CORE}/lib/monocypher/monocypher.c"
    INCLUDE_DIRS
        "."
        "${SIGNING_CRYPTO_CORE}"
)

target_compile_definitions(
    ${COMPONENT_LIB}
    PRIVATE
        microsui_sign=sui_signing_sign
        microsui_sign_ed25519=sui_signing_sign_ed25519
        microsui_sign_ed25519_with_keys=sui_signing_sign_ed25519_with_keys
        microsui_sign_ed25519_from_digest=sui_signing_sign_ed25519_from_digest
        microsui_verify_signature=sui_signing_verify_signature
        microsui_verify_signature_with_public_key=sui_signing_verify_signature_with_public_key
        microsui_verify_signature_ed25519=sui_signing_verify_signature_ed25519
        microsui_verify_signature_ed25519_from_digest=sui_signing_verify_signature_ed25519_from_digest
        microsui_verify_signature_ed25519_with_public_key=sui_signing_verify_signature_ed25519_with_public_key
        microsui_verify_signature_ed25519_with_public_key_from_digest=sui_signing_verify_signature_ed25519_with_public_key_from_digest
        microsui_sign_message=sui_signing_sign_message
)
