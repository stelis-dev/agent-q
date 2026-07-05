#include "credential_preparation_state.h"

#include <stdio.h>
#include <string.h>

#include "sensitive_memory.h"

namespace stopwatch_target {
namespace {

struct CredentialPreparationState {
    bool active = false;
    char session_id[kSessionIdSize] = {};
    uint8_t seed[kSuiEd25519SeedBytes] = {};
    SuiEd25519Preparation preparation = {};

    void clear()
    {
        wipe_sensitive_buffer(seed, sizeof(seed));
        memset(session_id, 0, sizeof(session_id));
        memset(&preparation, 0, sizeof(preparation));
        active = false;
    }
};

CredentialPreparationState g_preparation;

}  // namespace

void credential_preparation_state_init()
{
    credential_preparation_state_clear();
}

void credential_preparation_state_clear()
{
    g_preparation.clear();
}

CredentialPreparationBeginResult credential_preparation_begin(
    const char* session_id,
    CredentialPreparationRandomFn random_fn,
    void* random_context)
{
    if (!session_id_format_valid(session_id) || random_fn == nullptr) {
        return CredentialPreparationBeginResult::invalid_session;
    }

    g_preparation.clear();

    CredentialPreparationState next;
    if (!random_fn(next.seed, sizeof(next.seed), random_context)) {
        next.clear();
        return CredentialPreparationBeginResult::rng_error;
    }
    const SuiPublicMaterialResult derived =
        derive_sui_ed25519_preparation_from_seed(next.seed, &next.preparation);
    if (derived != SuiPublicMaterialResult::ok) {
        next.clear();
        return CredentialPreparationBeginResult::crypto_error;
    }
    snprintf(next.session_id, sizeof(next.session_id), "%s", session_id);
    next.active = true;

    g_preparation = next;
    wipe_sensitive_buffer(next.seed, sizeof(next.seed));
    return CredentialPreparationBeginResult::ok;
}

CredentialPreparationSnapshot credential_preparation_snapshot()
{
    if (!g_preparation.active) {
        return CredentialPreparationSnapshot{false, "", "", ""};
    }
    return CredentialPreparationSnapshot{
        true,
        g_preparation.session_id,
        g_preparation.preparation.address,
        g_preparation.preparation.public_key_base64,
    };
}

bool credential_preparation_copy_seed_for_session(
    const char* session_id,
    uint8_t out[kSuiEd25519SeedBytes])
{
    if (out != nullptr) {
        memset(out, 0, kSuiEd25519SeedBytes);
    }
    if (out == nullptr ||
        !g_preparation.active ||
        session_id == nullptr ||
        strcmp(session_id, g_preparation.session_id) != 0) {
        return false;
    }
    memcpy(out, g_preparation.seed, kSuiEd25519SeedBytes);
    return true;
}

}  // namespace stopwatch_target
