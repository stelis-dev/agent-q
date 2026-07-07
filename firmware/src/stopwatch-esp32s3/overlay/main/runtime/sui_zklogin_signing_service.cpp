#include "sui_zklogin_signing_service.h"

#include <stdlib.h>
#include <string.h>

#include "sensitive_memory.h"
#include "sui_zklogin_credential_store.h"
#include "sui/personal_message_intent.h"

extern "C" {
#include "key_management.h"
#include "lib/monocypher/monocypher.h"
#include "sign.h"
}

namespace stopwatch_target {
namespace {

void clear_signature_output(uint8_t* signature_out, size_t signature_size)
{
    if (signature_out != nullptr && signature_size > 0) {
        wipe_sensitive_buffer(signature_out, signature_size);
    }
}

SuiZkLoginSigningResult build_zklogin_signature(
    const SuiZkLoginCredentialRecord& credential,
    const uint8_t user_signature[signing::kSuiEd25519SignatureBytes],
    uint8_t signature_out[signing::kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out)
{
    const signing::SuiZkLoginSignatureBuildResult result =
        signing::build_sui_zklogin_signature_envelope(
            credential.proof.inputs,
            credential.proof.max_epoch,
            user_signature,
            signing::kSuiEd25519SignatureBytes,
            signature_out,
            signing::kSuiSignatureEnvelopeMaxBytes,
            signature_size_out);
    switch (result) {
        case signing::SuiZkLoginSignatureBuildResult::ok:
            return SuiZkLoginSigningResult::ok;
        case signing::SuiZkLoginSignatureBuildResult::output_too_small:
            return SuiZkLoginSigningResult::signature_output_too_small;
        case signing::SuiZkLoginSignatureBuildResult::invalid_input:
        case signing::SuiZkLoginSignatureBuildResult::bcs_too_large:
        default:
            return SuiZkLoginSigningResult::zklogin_envelope_error;
    }
}

SuiZkLoginSigningResult read_active_credential(SuiZkLoginCredentialRecord* credential)
{
    if (credential == nullptr) {
        return SuiZkLoginSigningResult::invalid_input;
    }
    const SuiZkLoginCredentialStatus status = read_sui_zklogin_credential(credential);
    return status == SuiZkLoginCredentialStatus::active
               ? SuiZkLoginSigningResult::ok
               : SuiZkLoginSigningResult::account_unavailable;
}

SuiZkLoginCredentialRecord* allocate_credential_record()
{
    SuiZkLoginCredentialRecord* credential =
        static_cast<SuiZkLoginCredentialRecord*>(malloc(sizeof(SuiZkLoginCredentialRecord)));
    if (credential != nullptr) {
        memset(credential, 0, sizeof(*credential));
    }
    return credential;
}

void wipe_and_free_credential_record(SuiZkLoginCredentialRecord* credential)
{
    if (credential != nullptr) {
        wipe_sensitive_buffer(credential, sizeof(*credential));
        free(credential);
    }
}

}  // namespace

SuiZkLoginSigningResult sign_sui_zklogin_personal_message(
    const uint8_t* message,
    size_t message_size,
    uint8_t signature_out[signing::kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out)
{
    clear_signature_output(signature_out, signing::kSuiSignatureEnvelopeMaxBytes);
    if (signature_size_out != nullptr) {
        *signature_size_out = 0;
    }
    if (message == nullptr ||
        message_size == 0 ||
        message_size > signing::kSuiSignPersonalMessageMaxBytes ||
        signature_out == nullptr ||
        signature_size_out == nullptr) {
        return SuiZkLoginSigningResult::invalid_input;
    }

    SuiZkLoginCredentialRecord* credential = allocate_credential_record();
    if (credential == nullptr) {
        return SuiZkLoginSigningResult::signing_error;
    }
    const SuiZkLoginSigningResult credential_result = read_active_credential(credential);
    if (credential_result != SuiZkLoginSigningResult::ok) {
        wipe_and_free_credential_record(credential);
        return credential_result;
    }

    uint8_t secret_key[64] = {};
    uint8_t public_key[32] = {};
    uint8_t digest[signing::kSuiPersonalMessageIntentDigestBytes] = {};
    uint8_t user_signature[signing::kSuiEd25519SignatureBytes] = {};
    if (microsui_derive_keypair_ed25519(
            secret_key,
            public_key,
            credential->prepared_seed) != 0 ||
        !signing::build_sui_personal_message_intent_digest(message, message_size, digest)) {
        wipe_sensitive_buffer(secret_key, sizeof(secret_key));
        wipe_sensitive_buffer(public_key, sizeof(public_key));
        wipe_sensitive_buffer(digest, sizeof(digest));
        wipe_sensitive_buffer(user_signature, sizeof(user_signature));
        wipe_and_free_credential_record(credential);
        return SuiZkLoginSigningResult::signing_error;
    }

    microsui_sign_ed25519_from_digest(
        user_signature,
        digest,
        secret_key,
        public_key);
    const SuiZkLoginSigningResult envelope_result =
        build_zklogin_signature(
            *credential,
            user_signature,
            signature_out,
            signature_size_out);
    wipe_sensitive_buffer(secret_key, sizeof(secret_key));
    wipe_sensitive_buffer(public_key, sizeof(public_key));
    wipe_sensitive_buffer(digest, sizeof(digest));
    wipe_sensitive_buffer(user_signature, sizeof(user_signature));
    wipe_and_free_credential_record(credential);
    return envelope_result;
}

SuiZkLoginSigningResult sign_sui_zklogin_transaction(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[signing::kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out)
{
    clear_signature_output(signature_out, signing::kSuiSignatureEnvelopeMaxBytes);
    if (signature_size_out != nullptr) {
        *signature_size_out = 0;
    }
    if (tx_bytes == nullptr ||
        tx_bytes_size == 0 ||
        tx_bytes_size > signing::kSuiSignTransactionTxBytesMaxBytes ||
        signature_out == nullptr ||
        signature_size_out == nullptr) {
        return SuiZkLoginSigningResult::invalid_input;
    }

    SuiZkLoginCredentialRecord* credential = allocate_credential_record();
    if (credential == nullptr) {
        return SuiZkLoginSigningResult::signing_error;
    }
    const SuiZkLoginSigningResult credential_result = read_active_credential(credential);
    if (credential_result != SuiZkLoginSigningResult::ok) {
        wipe_and_free_credential_record(credential);
        return credential_result;
    }

    uint8_t user_signature[signing::kSuiEd25519SignatureBytes] = {};
    if (microsui_sign_ed25519(user_signature, tx_bytes, tx_bytes_size, credential->prepared_seed) != 0) {
        wipe_sensitive_buffer(user_signature, sizeof(user_signature));
        wipe_and_free_credential_record(credential);
        return SuiZkLoginSigningResult::signing_error;
    }

    const SuiZkLoginSigningResult envelope_result =
        build_zklogin_signature(
            *credential,
            user_signature,
            signature_out,
            signature_size_out);
    wipe_sensitive_buffer(user_signature, sizeof(user_signature));
    wipe_and_free_credential_record(credential);
    return envelope_result;
}

const char* sui_zklogin_signing_result_name(SuiZkLoginSigningResult result)
{
    switch (result) {
        case SuiZkLoginSigningResult::ok:
            return "ok";
        case SuiZkLoginSigningResult::invalid_input:
            return "invalid_input";
        case SuiZkLoginSigningResult::account_unavailable:
            return "account_unavailable";
        case SuiZkLoginSigningResult::signing_error:
            return "signing_error";
        case SuiZkLoginSigningResult::signature_output_too_small:
            return "signature_output_too_small";
        case SuiZkLoginSigningResult::zklogin_envelope_error:
            return "zklogin_envelope_error";
    }
    return "unknown";
}

}  // namespace stopwatch_target
