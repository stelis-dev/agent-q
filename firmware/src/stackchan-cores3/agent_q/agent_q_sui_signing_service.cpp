#include "agent_q_sui_signing_service.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_root_material.h"
#include "agent_q_sign_personal_message_limits.h"
#include "agent_q_sui_key_derivation.h"
#include "agent_q_sui_zklogin_proof_store.h"
#include "agent_q_sui_zklogin_signature.h"

extern "C" {
#include "lib/monocypher/monocypher.h"
#include "sign.h"
}

namespace agent_q {
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

size_t encode_uleb128_size(size_t value, uint8_t* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return 0;
    }
    size_t written = 0;
    do {
        if (written >= output_size) {
            return 0;
        }
        uint8_t byte = static_cast<uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0) {
            byte |= 0x80U;
        }
        output[written++] = byte;
    } while (value != 0);
    return written;
}

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
    uint8_t digest[kAgentQSuiPersonalMessageIntentDigestBytes] = {};
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
        message_size > kAgentQSuiSignPersonalMessageMaxBytes || signature_out == nullptr) {
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
    const AgentQSuiActiveIdentity& active_identity,
    const uint8_t user_signature[kSuiEd25519SignatureBytes],
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out)
{
    const AgentQSuiZkLoginSignatureBuildResult envelope_status =
        build_sui_zklogin_signature_envelope(
            active_identity.zklogin.inputs,
            active_identity.zklogin.max_epoch,
            user_signature,
            kSuiEd25519SignatureBytes,
            signature_out,
            kSuiSignatureEnvelopeMaxBytes,
            signature_size_out);
    if (envelope_status == AgentQSuiZkLoginSignatureBuildResult::ok) {
        return SuiSigningStatus::ok;
    }
    if (envelope_status == AgentQSuiZkLoginSignatureBuildResult::output_too_small) {
        return SuiSigningStatus::signature_output_too_small;
    }
    return envelope_status == AgentQSuiZkLoginSignatureBuildResult::invalid_input
               ? SuiSigningStatus::invalid_input
               : SuiSigningStatus::zklogin_envelope_error;
}

}  // namespace

bool build_sui_personal_message_intent_digest(
    const uint8_t* message,
    size_t message_size,
    uint8_t digest_out[32])
{
    if (digest_out != nullptr) {
        memset(digest_out, 0, 32);
    }
    if (message == nullptr || message_size == 0 ||
        message_size > kAgentQSuiSignPersonalMessageMaxBytes ||
        digest_out == nullptr) {
        return false;
    }

    uint8_t length_prefix[4] = {};
    const size_t length_prefix_size =
        encode_uleb128_size(message_size, length_prefix, sizeof(length_prefix));
    if (length_prefix_size == 0) {
        return false;
    }

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    const uint8_t personal_message_intent[3] = {0x03, 0x00, 0x00};
    crypto_blake2b_update(&ctx, personal_message_intent, sizeof(personal_message_intent));
    crypto_blake2b_update(&ctx, length_prefix, length_prefix_size);
    crypto_blake2b_update(&ctx, message, message_size);
    crypto_blake2b_final(&ctx, digest_out);
    wipe_sensitive_buffer(length_prefix, sizeof(length_prefix));
    wipe_sensitive_buffer(&ctx, sizeof(ctx));
    return true;
}

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

    const AgentQSuiActiveIdentity active_identity = resolve_active_sui_identity();
    if (active_identity.kind == AgentQSuiActiveIdentityKind::native) {
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
    if (active_identity.kind != AgentQSuiActiveIdentityKind::zklogin) {
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
        message_size > kAgentQSuiSignPersonalMessageMaxBytes ||
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
        message_size > kAgentQSuiSignPersonalMessageMaxBytes ||
        signature_out == nullptr || signature_size_out == nullptr) {
        return SuiSigningStatus::invalid_input;
    }

    const AgentQSuiActiveIdentity active_identity = resolve_active_sui_identity();
    if (active_identity.kind == AgentQSuiActiveIdentityKind::native) {
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
    if (active_identity.kind != AgentQSuiActiveIdentityKind::zklogin) {
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

}  // namespace agent_q
