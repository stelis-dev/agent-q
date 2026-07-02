#ifndef SIGNING_CRYPTO_SIGN_H
#define SIGNING_CRYPTO_SIGN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int sui_signing_sign(uint8_t sui_sig_out[97], uint8_t scheme, const uint8_t* message, const size_t message_len, const uint8_t seed[32]);

int sui_signing_sign_ed25519(uint8_t sui_sig_out[97], const uint8_t* message, const size_t message_len, const uint8_t seed[32]);

void sui_signing_sign_ed25519_with_keys(uint8_t sui_sig_out[97], const uint8_t* message, const size_t message_len, const uint8_t secret_key[64], const uint8_t public_key[32]);

void sui_signing_sign_ed25519_from_digest(uint8_t sui_sig_out[97], const uint8_t digest[32], const uint8_t secret_key[64], const uint8_t public_key[32]);

int sui_signing_verify_signature_ed25519(uint8_t sui_sig[97], const uint8_t* message, const size_t message_len);

int sui_signing_verify_signature_ed25519_from_digest(uint8_t sui_sig[97], const uint8_t digest[32]);

int sui_signing_verify_signature_ed25519_with_public_key(uint8_t sui_sig[97], const uint8_t* message, const size_t message_len, uint8_t public_key[32]);

int sui_signing_verify_signature_ed25519_with_public_key_from_digest(uint8_t sui_sig[97], const uint8_t digest[32], uint8_t public_key[32]);

int sui_signing_verify_signature(uint8_t sui_sig[97], const uint8_t* message, const size_t message_len);

int sui_signing_verify_signature_with_public_key(uint8_t sui_sig[97], const uint8_t* message, const size_t message_len, uint8_t public_key[32]);

int sui_signing_sign_message(uint8_t sui_sig_out[97], const char* message_hex, const uint8_t seed[32]);

#ifdef __cplusplus
}
#endif

#endif
