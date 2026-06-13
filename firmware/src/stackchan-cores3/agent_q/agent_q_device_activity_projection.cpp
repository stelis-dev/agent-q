#include "agent_q_device_activity_projection.h"

namespace agent_q {
namespace {

bool policy_update_stage_awaiting_approval(AgentQPolicyUpdateFlowStage stage)
{
    return stage == AgentQPolicyUpdateFlowStage::reviewing ||
           stage == AgentQPolicyUpdateFlowStage::pin_entry;
}

bool user_signing_stage_awaiting_approval(AgentQUserSigningStage stage)
{
    return stage == AgentQUserSigningStage::reviewing ||
           stage == AgentQUserSigningStage::pin_entry;
}

bool local_settings_common_blocked(const AgentQDeviceActivityProjection& activity)
{
    return activity.connect_approval_active ||
           activity.protocol_pin_approval_active ||
           activity.policy_update_active ||
           activity.identification_display_active ||
           activity.provisioning_flow_active ||
           activity.local_pin_auth_flow_active ||
           activity.payload_delivery_active ||
           activity.user_signing_active ||
           activity.local_reset_active;
}

}  // namespace

AgentQDeviceActivityProjection project_device_activity(
    const AgentQDeviceActivityFacts& facts)
{
    const bool policy_update_awaiting =
        facts.policy_update.active &&
        policy_update_stage_awaiting_approval(facts.policy_update.stage);
    const bool policy_update_busy =
        facts.policy_update.active &&
        !policy_update_awaiting;
    const bool user_signing_awaiting =
        facts.user_signing.active &&
        user_signing_stage_awaiting_approval(facts.user_signing.stage);
    const bool local_reset_settings_menu =
        facts.local_reset.flow_active &&
        facts.local_reset.stage == AgentQLocalResetStage::settings_menu;
    const bool payload_delivery_active =
        facts.payload_delivery_receiving || facts.payload_delivery_finalized;

    AgentQProjectedDeviceState state = AgentQProjectedDeviceState::idle;
    if (facts.persistent_material_consistency_error) {
        state = AgentQProjectedDeviceState::error;
    } else if (
        facts.connect_approval_active ||
        facts.protocol_pin_approval_active ||
        policy_update_awaiting ||
        user_signing_awaiting) {
        state = AgentQProjectedDeviceState::awaiting_approval;
    } else if (
        facts.provisioning_flow_active ||
        payload_delivery_active ||
        policy_update_busy ||
        (facts.local_reset.flow_active && !local_reset_settings_menu) ||
        facts.local_pin_auth_flow_active ||
        facts.user_signing.active) {
        state = AgentQProjectedDeviceState::busy;
    }

    return {
        state,
        facts.persistent_material_consistency_error,
        facts.provisioned,
        facts.ui_idle_for_local_settings,
        facts.identification_display_active,
        facts.connect_approval_active,
        facts.protocol_pin_approval_active,
        facts.policy_update.active,
        policy_update_awaiting,
        policy_update_busy,
        facts.provisioning_flow_active,
        payload_delivery_active,
        facts.payload_delivery_receiving,
        facts.payload_delivery_finalized,
        facts.local_reset.flow_active,
        local_reset_settings_menu,
        facts.local_pin_auth_flow_active,
        facts.user_signing.active,
        user_signing_awaiting,
    };
}

const char* device_activity_state_name(AgentQProjectedDeviceState state)
{
    switch (state) {
        case AgentQProjectedDeviceState::idle:
            return "idle";
        case AgentQProjectedDeviceState::busy:
            return "busy";
        case AgentQProjectedDeviceState::awaiting_approval:
            return "awaiting_approval";
        case AgentQProjectedDeviceState::error:
            return "error";
    }
    return "error";
}

bool device_activity_blocks_user_signing_ingress(
    const AgentQDeviceActivityProjection& activity)
{
    return activity.connect_approval_active ||
           activity.protocol_pin_approval_active ||
           activity.policy_update_active ||
           activity.provisioning_flow_active ||
           activity.payload_delivery_receiving ||
           activity.local_reset_active ||
           activity.local_pin_auth_flow_active ||
           activity.user_signing_active;
}

bool device_activity_allows_local_settings_touch_entry(
    const AgentQDeviceActivityProjection& activity)
{
    return activity.provisioned &&
           !local_settings_common_blocked(activity) &&
           activity.ui_idle_for_local_settings;
}

bool device_activity_allows_local_settings_start(
    const AgentQDeviceActivityProjection& activity)
{
    return !local_settings_common_blocked(activity) &&
           activity.ui_idle_for_local_settings;
}

bool device_activity_allows_local_error_recovery(
    const AgentQDeviceActivityProjection& activity)
{
    return !local_settings_common_blocked(activity);
}

AgentQDeviceActivityUsbRequestBlock device_activity_usb_request_block(
    const AgentQDeviceActivityProjection& activity,
    AgentQDeviceActivityUsbRequestOptions options)
{
    if (activity.connect_approval_active) {
        return { true, "busy", "Device is awaiting local input." };
    }
    if (activity.protocol_pin_approval_active) {
        return { true, "busy", "Device is awaiting local PIN approval." };
    }
    if (activity.policy_update_active) {
        return { true, "busy", "Device has a pending policy update." };
    }
    if (activity.provisioning_flow_active) {
        return { true, "busy", "Device is showing setup material." };
    }
    if (activity.payload_delivery_active && !options.allow_payload_delivery) {
        return {
            true,
            "busy",
            activity.payload_delivery_receiving
                ? "Device has a pending payload upload."
                : "Device has a pending signable payload.",
        };
    }
    if (activity.local_reset_active) {
        if (options.allow_settings_menu && activity.local_reset_settings_menu) {
            return { false, nullptr, nullptr };
        }
        return {
            true,
            "busy",
            activity.local_reset_settings_menu
                ? "Device is showing local settings UI."
                : "Device is showing local reset UI.",
        };
    }
    if (activity.local_pin_auth_flow_active) {
        return { true, "busy", "Device is showing local PIN UI." };
    }
    if (activity.user_signing_active) {
        return { true, "busy", "Device has a pending signing request." };
    }
    return { false, nullptr, nullptr };
}

}  // namespace agent_q
