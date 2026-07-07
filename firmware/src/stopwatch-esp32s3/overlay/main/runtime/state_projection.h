#pragma once

namespace stopwatch_target {

enum class LocalAuthProjectionStatus {
    missing,
    active,
    locked,
    invalid,
    storage_error,
};

enum class CredentialProjectionStatus {
    missing,
    active,
    invalid,
    storage_error,
};

enum class SettingsProjectionStatus {
    missing,
    active,
    invalid,
    storage_error,
};

struct StateProjectionInput {
    LocalAuthProjectionStatus auth_status;
    CredentialProjectionStatus credential_status;
    SettingsProjectionStatus settings_status;
    bool locally_unlocked;
    bool ui_busy;
};

const char* stopwatch_device_state(StateProjectionInput input);
const char* stopwatch_provisioning_state(StateProjectionInput input);
bool stopwatch_projection_is_error(StateProjectionInput input);

}  // namespace stopwatch_target
