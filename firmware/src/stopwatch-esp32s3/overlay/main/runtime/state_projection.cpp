#include "state_projection.h"

namespace stopwatch_target {

const char* stopwatch_device_state(StateProjectionInput input)
{
    if (input.auth_status == LocalAuthProjectionStatus::invalid ||
        input.auth_status == LocalAuthProjectionStatus::storage_error) {
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

const char* stopwatch_provisioning_state(LocalAuthProjectionStatus auth_status)
{
    if (auth_status == LocalAuthProjectionStatus::invalid ||
        auth_status == LocalAuthProjectionStatus::storage_error) {
        return "error";
    }
    return "unprovisioned";
}

}  // namespace stopwatch_target
