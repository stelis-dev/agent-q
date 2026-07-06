#pragma once

#include "policy/policy_update_flow.h"

namespace signing {

bool usb_policy_propose_outcome_write(
    const char* id,
    const char* status,
    const char* reason_code,
    const PolicyUpdateFlowSnapshot* policy);

}  // namespace signing
