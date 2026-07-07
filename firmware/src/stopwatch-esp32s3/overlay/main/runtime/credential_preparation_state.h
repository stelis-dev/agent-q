#pragma once

#include <stddef.h>
#include <stdint.h>

#include "protocol/session_state.h"
#include "sui_public_material.h"

namespace stopwatch_target {

using CredentialPreparationRandomFn = bool (*)(void* output, size_t size, void* context);

enum class CredentialPreparationBeginResult {
    ok,
    invalid_session,
    rng_error,
    crypto_error,
};

struct CredentialPreparationSnapshot {
    bool active;
    const char* session_id;
    const char* address;
    const char* public_key_base64;
};

void credential_preparation_state_init();
void credential_preparation_state_clear();
CredentialPreparationBeginResult credential_preparation_begin(
    const char* session_id,
    CredentialPreparationRandomFn random_fn,
    void* random_context);
CredentialPreparationSnapshot credential_preparation_snapshot();
bool credential_preparation_copy_seed_for_session(
    const char* session_id,
    uint8_t out[kSuiEd25519SeedBytes]);

}  // namespace stopwatch_target
