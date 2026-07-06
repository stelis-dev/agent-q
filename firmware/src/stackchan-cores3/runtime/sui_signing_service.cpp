#include "sui_signing_service.h"

#include <string.h>

#include "bip39.h"
#include "root_material.h"
#include "sui/signing_limits.h"
#include "sui_key_derivation.h"
#include "sui_zklogin_proof_store.h"
#include "sui/personal_message_intent.h"
#include "sui/zklogin_signature.h"

extern "C" {
#include "lib/monocypher/monocypher.h"
#include "sign.h"
}

namespace signing {
namespace {

void clear_signature_output(uint8_t* signature_out, size_t signature_size)
{
    if (signature_out != nullptr && signature_size > 0) {
        wipe_sensitive_buffer(signature_out, signature_size);
    }
}

struct TransactionSigningContext {
    const uint8_t* tx_bytes;
    size_t tx_bytes_size;
    uint8_t* signature_out;
    bool attempted;
};

struct PersonalMessageSigningContext {
    const uint8_t* message;
    size_t message_size;
    uint8_t* signature_out;
    bool attempted;
};

bool sign_transaction_with_seed(
    const uint8_t private_seed[kSuiEd25519PrivateSeedBytes],
    void* context_ptr)
{
    TransactionSigningContext* context =
        static_cast<TransactionSigningContext*>(context_ptr);
    if (context == nullptr || context->tx_bytes == nullptr || context->tx_bytes_size == 0 ||
        context->signature_out == nullptr) {
        return false;
    }
    context->attempted = true;
    return sui_signing_sign_ed25519(
               context->signature_out,
               context->tx_bytes,
               context->tx_bytes_size,
               private_seed) == 0;
}

bool sign_personal_message_with_seed(
    const uint8_t private_seed[kSuiEd25519PrivateSeedBytes],
    void* context_ptr)
{
    PersonalMessageSigningContext* context =
        static_cast<PersonalMessageSigningContext*>(context_ptr);
    if (context == nullptr || context->message == nullptr || context->message_size == 0 ||
        context->signature_out == nullptr) {
        return false;
    }
    context->attempted = true;

    uint8_t seed_copy[kSuiEd25519PrivateSeedBytes] = {};
    uint8_t secret_key[64] = {};
    uint8_t public_key[32] = {};
    uint8_t digest[kSuiPersonalMessageIntentDigestBytes] = {};
    memcpy(seed_copy, private_seed, sizeof(seed_copy));
    crypto_ed25519_key_pair(secret_key, public_key, seed_copy);
    wipe_sensitive_buffer(seed_copy, sizeof(seed_copy));
    const bool digest_ok = build_sui_personal_message_intent_digest(
        context->message,
        context->message_size,
        digest);
    if (!digest_ok) {
        wipe_sensitive_buffer(secret_key, sizeof(secret_key));
        wipe_sensitive_buffer(public_key, sizeof(public_key));
        wipe_sensitive_buffer(digest, sizeof(digest));
        return false;
    }
    sui_signing_sign_ed25519_from_digest(
        context->signature_out,
        digest,
        secret_key,
        public_key);
    wipe_sensitive_buffer(secret_key, sizeof(secret_key));
    wipe_sensitive_buffer(public_key, sizeof(public_key));
    wipe_sensitive_buffer(digest, sizeof(digest));
    return true;
}

SuiSigningStatus sign_sui_ed25519_transaction_from_mnemonic(
    const char* mnemonic,
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes])
{
    clear_signature_output(signature_out, kSuiEd25519SignatureBytes);
    if (mnemonic == nullptr || mnemonic[0] == '\0' || tx_bytes == nullptr || tx_bytes_size == 0 ||
        signature_out == nullptr) {
        return SuiSigningStatus::invalid_input;
    }

    TransactionSigningContext context{
        tx_bytes,
        tx_bytes_size,
        signature_out,
        false,
    };
    if (!with_sui_ed25519_private_seed(mnemonic, sign_transaction_with_seed, &context)) {
        clear_signature_output(signature_out, kSuiEd25519SignatureBytes);
        return context.attempted ? SuiSigningStatus::signing_error
                                 : SuiSigningStatus::mnemonic_error;
    }
    return SuiSigningStatus::ok;
}

SuiSigningStatus sign_sui_ed25519_personal_message_from_mnemonic(
    const char* mnemonic,
    const uint8_t* message,
    size_t message_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes])
{
    clear_signature_output(signature_out, kSuiEd25519SignatureBytes);
    if (mnemonic == nullptr || mnemonic[0] == '\0' || message == nullptr || message_size == 0 ||
        message_size > kSuiSignPersonalMessageMaxBytes || signature_out == nullptr) {
        return SuiSigningStatus::invalid_input;
    }

    PersonalMessageSigningContext context{
        message,
        message_size,
        signature_out,
        false,
    };
    if (!with_sui_ed25519_private_seed(mnemonic, sign_personal_message_with_seed, &context)) {
        clear_signature_output(signature_out, kSuiEd25519SignatureBytes);
        return context.attempted ? SuiSigningStatus::signing_error
                                 : SuiSigningStatus::mnemonic_error;
    }
    return SuiSigningStatus::ok;
}

SuiSigningStatus build_zklogin_signature_for_active_identity(
    const SuiActiveIdentity& active_identity,
    const uint8_t user_signature[kSuiEd25519SignatureBytes],
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out)
{
    const SuiZkLoginSignatureBuildResult envelope_status =
        build_sui_zklogin_signature_envelope(
            active_identity.zklogin.inputs,
            active_identity.zklogin.max_epoch,
            user_signature,
            kSuiEd25519SignatureBytes,
            signature_out,
            kSuiSignatureEnvelopeMaxBytes,
            signature_size_out);
    if (envelope_status == SuiZkLoginSignatureBuildResult::ok) {
        return SuiSigningStatus::ok;
    }
    if (envelope_status == SuiZkLoginSignatureBuildResult::output_too_small) {
        return SuiSigningStatus::signature_output_too_small;
    }
    return envelope_status == SuiZkLoginSignatureBuildResult::invalid_input
               ? SuiSigningStatus::invalid_input
               : SuiSigningStatus::zklogin_envelope_error;
}

}  // namespace

SuiSigningStatus sign_sui_ed25519_transaction_from_stored_root(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes])
{
    clear_signature_output(signature_out, kSuiEd25519SignatureBytes);
    if (tx_bytes == nullptr || tx_bytes_size == 0 || signature_out == nullptr) {
        return SuiSigningStatus::invalid_input;
    }

    uint8_t root_material[kRootMaterialBytes] = {};
    if (!read_root_material(root_material, sizeof(root_material))) {
        wipe_sensitive_buffer(root_material, sizeof(root_material));
        return SuiSigningStatus::root_material_unavailable;
    }

    char mnemonic[kBip39MnemonicMaxChars] = {};
    const bool mnemonic_ok =
        make_bip39_mnemonic_12_words(root_material, mnemonic, sizeof(mnemonic));
    wipe_sensitive_buffer(root_material, sizeof(root_material));
    if (!mnemonic_ok) {
        wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
        return SuiSigningStatus::mnemonic_error;
    }

    const SuiSigningStatus result =
        sign_sui_ed25519_transaction_from_mnemonic(
            mnemonic, tx_bytes, tx_bytes_size, signature_out);
    wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
    return result;
}

SuiSigningStatus sign_sui_transaction_from_active_identity(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out)
{
    clear_signature_output(signature_out, kSuiSignatureEnvelopeMaxBytes);
    if (signature_size_out != nullptr) {
        *signature_size_out = 0;
    }
    if (tx_bytes == nullptr || tx_bytes_size == 0 ||
        signature_out == nullptr || signature_size_out == nullptr) {
        return SuiSigningStatus::invalid_input;
    }

    const SuiActiveIdentity active_identity = resolve_active_sui_identity();
    if (active_identity.kind == SuiActiveIdentityKind::native) {
        const SuiSigningStatus result =
            sign_sui_ed25519_transaction_from_stored_root(
                tx_bytes,
                tx_bytes_size,
                signature_out);
        if (result == SuiSigningStatus::ok) {
            *signature_size_out = kSuiEd25519SignatureBytes;
        }
        return result;
    }
    if (active_identity.kind != SuiActiveIdentityKind::zklogin) {
        return SuiSigningStatus::active_identity_unavailable;
    }

    uint8_t user_signature[kSuiEd25519SignatureBytes] = {};
    const SuiSigningStatus user_signature_status =
        sign_sui_ed25519_transaction_from_stored_root(
            tx_bytes,
            tx_bytes_size,
            user_signature);
    if (user_signature_status != SuiSigningStatus::ok) {
        wipe_sensitive_buffer(user_signature, sizeof(user_signature));
        return user_signature_status;
    }

    const SuiSigningStatus envelope_status =
        build_zklogin_signature_for_active_identity(
            active_identity,
            user_signature,
            signature_out,
            signature_size_out);
    wipe_sensitive_buffer(user_signature, sizeof(user_signature));
    return envelope_status;
}

SuiSigningStatus sign_sui_ed25519_personal_message_from_stored_root(
    const uint8_t* message,
    size_t message_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes])
{
    clear_signature_output(signature_out, kSuiEd25519SignatureBytes);
    if (message == nullptr || message_size == 0 ||
        message_size > kSuiSignPersonalMessageMaxBytes ||
        signature_out == nullptr) {
        return SuiSigningStatus::invalid_input;
    }

    uint8_t root_material[kRootMaterialBytes] = {};
    if (!read_root_material(root_material, sizeof(root_material))) {
        wipe_sensitive_buffer(root_material, sizeof(root_material));
        return SuiSigningStatus::root_material_unavailable;
    }

    char mnemonic[kBip39MnemonicMaxChars] = {};
    const bool mnemonic_ok =
        make_bip39_mnemonic_12_words(root_material, mnemonic, sizeof(mnemonic));
    wipe_sensitive_buffer(root_material, sizeof(root_material));
    if (!mnemonic_ok) {
        wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
        return SuiSigningStatus::mnemonic_error;
    }

    const SuiSigningStatus result =
        sign_sui_ed25519_personal_message_from_mnemonic(
            mnemonic,
            message,
            message_size,
            signature_out);
    wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
    return result;
}

SuiSigningStatus sign_sui_personal_message_from_active_identity(
    const uint8_t* message,
    size_t message_size,
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out)
{
    clear_signature_output(signature_out, kSuiSignatureEnvelopeMaxBytes);
    if (signature_size_out != nullptr) {
        *signature_size_out = 0;
    }
    if (message == nullptr || message_size == 0 ||
        message_size > kSuiSignPersonalMessageMaxBytes ||
        signature_out == nullptr || signature_size_out == nullptr) {
        return SuiSigningStatus::invalid_input;
    }

    const SuiActiveIdentity active_identity = resolve_active_sui_identity();
    if (active_identity.kind == SuiActiveIdentityKind::native) {
        const SuiSigningStatus result =
            sign_sui_ed25519_personal_message_from_stored_root(
                message,
                message_size,
                signature_out);
        if (result == SuiSigningStatus::ok) {
            *signature_size_out = kSuiEd25519SignatureBytes;
        }
        return result;
    }
    if (active_identity.kind != SuiActiveIdentityKind::zklogin) {
        return SuiSigningStatus::active_identity_unavailable;
    }

    uint8_t user_signature[kSuiEd25519SignatureBytes] = {};
    const SuiSigningStatus user_signature_status =
        sign_sui_ed25519_personal_message_from_stored_root(
            message,
            message_size,
            user_signature);
    if (user_signature_status != SuiSigningStatus::ok) {
        wipe_sensitive_buffer(user_signature, sizeof(user_signature));
        return user_signature_status;
    }

    const SuiSigningStatus envelope_status =
        build_zklogin_signature_for_active_identity(
            active_identity,
            user_signature,
            signature_out,
            signature_size_out);
    wipe_sensitive_buffer(user_signature, sizeof(user_signature));
    return envelope_status;
}

const char* sui_signing_status_to_string(SuiSigningStatus result)
{
    switch (result) {
        case SuiSigningStatus::ok:
            return "ok";
        case SuiSigningStatus::invalid_input:
            return "invalid_input";
        case SuiSigningStatus::root_material_unavailable:
            return "root_material_unavailable";
        case SuiSigningStatus::mnemonic_error:
            return "mnemonic_error";
        case SuiSigningStatus::signing_error:
            return "signing_error";
        case SuiSigningStatus::active_identity_unavailable:
            return "active_identity_unavailable";
        case SuiSigningStatus::signature_output_too_small:
            return "signature_output_too_small";
        case SuiSigningStatus::zklogin_envelope_error:
            return "zklogin_envelope_error";
    }
    return "unknown";
}

}  // namespace signing
