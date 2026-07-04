#pragma once

namespace stopwatch_target {

enum class LocalAuthProjectionStatus {
    missing,
    active,
    locked,
    invalid,
    storage_error,
};

struct StateProjectionInput {
    LocalAuthProjectionStatus auth_status;
    bool locally_unlocked;
    bool ui_busy;
};

const char* stopwatch_device_state(StateProjectionInput input);
const char* stopwatch_provisioning_state(LocalAuthProjectionStatus auth_status);

}  // namespace stopwatch_target
