#include "state_projection.h"

namespace stopwatch_target {

const char* stopwatch_device_state(StateProjectionInput input)
{
    if (input.auth_status == LocalAuthProjectionStatus::invalid ||
        input.auth_status == LocalAuthProjectionStatus::storage_error ||
        input.credential_status == CredentialProjectionStatus::invalid ||
        input.credential_status == CredentialProjectionStatus::storage_error) {
        return "error";
    }
    if (input.auth_status == LocalAuthProjectionStatus::locked ||
        (input.auth_status == LocalAuthProjectionStatus::active && !input.locally_unlocked)) {
        return "locked";
    }
    if (input.ui_busy) {
        return "busy";
    }
    return "idle";
}

const char* stopwatch_provisioning_state(StateProjectionInput input)
{
    if (input.auth_status == LocalAuthProjectionStatus::invalid ||
        input.auth_status == LocalAuthProjectionStatus::storage_error ||
        input.credential_status == CredentialProjectionStatus::invalid ||
        input.credential_status == CredentialProjectionStatus::storage_error) {
        return "error";
    }
    if (input.auth_status == LocalAuthProjectionStatus::missing) {
        return "unprovisioned";
    }
    if (input.credential_status == CredentialProjectionStatus::active) {
        return "provisioned";
    }
    return "unprovisioned";
}

}  // namespace stopwatch_target
