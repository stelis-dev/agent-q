#include "state_projection.h"

namespace stopwatch_target {

bool stopwatch_projection_is_error(StateProjectionInput input)
{
    const bool configured_auth_requires_settings =
        input.auth_status == LocalAuthProjectionStatus::active ||
        input.auth_status == LocalAuthProjectionStatus::locked;
    const bool auth_gate_missing_with_material =
        input.auth_status == LocalAuthProjectionStatus::missing &&
        (input.credential_status != CredentialProjectionStatus::missing ||
         input.settings_status != SettingsProjectionStatus::missing);

    return input.auth_status == LocalAuthProjectionStatus::invalid ||
           input.auth_status == LocalAuthProjectionStatus::storage_error ||
           auth_gate_missing_with_material ||
           (configured_auth_requires_settings &&
            input.settings_status != SettingsProjectionStatus::active) ||
           input.credential_status == CredentialProjectionStatus::invalid ||
           input.credential_status == CredentialProjectionStatus::storage_error;
}

const char* stopwatch_device_state(StateProjectionInput input)
{
    if (stopwatch_projection_is_error(input)) {
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
    if (stopwatch_projection_is_error(input)) {
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
