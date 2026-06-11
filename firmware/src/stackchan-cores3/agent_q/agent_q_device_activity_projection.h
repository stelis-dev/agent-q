#pragma once

#include "agent_q_local_reset.h"
#include "agent_q_policy_update_flow.h"
#include "agent_q_user_signing_flow.h"

namespace agent_q {

enum class AgentQProjectedDeviceState {
    idle,
    busy,
    awaiting_approval,
    error,
};

struct AgentQDeviceActivityFacts {
    bool persistent_material_consistency_error;
    bool provisioned;
    bool ui_idle_for_local_settings;
    bool identification_display_active;
    bool connect_approval_active;
    bool protocol_pin_approval_active;
    bool provisioning_flow_active;
    bool local_pin_auth_flow_active;
    AgentQPolicyUpdateFlowSnapshot policy_update;
    AgentQLocalResetSnapshot local_reset;
    AgentQUserSigningFlowCoreSnapshot user_signing;
};

struct AgentQDeviceActivityProjection {
    AgentQProjectedDeviceState device_state;
    bool persistent_material_consistency_error;
    bool provisioned;
    bool ui_idle_for_local_settings;
    bool identification_display_active;
    bool connect_approval_active;
    bool protocol_pin_approval_active;
    bool policy_update_active;
    bool policy_update_awaiting_approval;
    bool policy_update_busy;
    bool provisioning_flow_active;
    bool local_reset_active;
    bool local_reset_settings_menu;
    bool local_pin_auth_flow_active;
    bool user_signing_active;
    bool user_signing_awaiting_approval;
};

struct AgentQDeviceActivityUsbRequestOptions {
    bool allow_settings_menu;
};

struct AgentQDeviceActivityUsbRequestBlock {
    bool blocked;
    const char* code;
    const char* message;
};

AgentQDeviceActivityProjection project_device_activity(
    const AgentQDeviceActivityFacts& facts);
const char* device_activity_state_name(AgentQProjectedDeviceState state);
bool device_activity_blocks_user_signing_ingress(
    const AgentQDeviceActivityProjection& activity);
bool device_activity_allows_local_settings_touch_entry(
    const AgentQDeviceActivityProjection& activity);
bool device_activity_allows_local_settings_start(
    const AgentQDeviceActivityProjection& activity);
bool device_activity_allows_local_error_recovery(
    const AgentQDeviceActivityProjection& activity);
AgentQDeviceActivityUsbRequestBlock device_activity_usb_request_block(
    const AgentQDeviceActivityProjection& activity,
    AgentQDeviceActivityUsbRequestOptions options);

}  // namespace agent_q
