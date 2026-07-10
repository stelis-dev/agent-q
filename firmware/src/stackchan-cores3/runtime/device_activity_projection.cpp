#include "device_activity_projection.h"

namespace signing {
namespace {

bool policy_update_stage_awaiting_approval(PolicyUpdateFlowStage stage)
{
    return stage == PolicyUpdateFlowStage::reviewing ||
           stage == PolicyUpdateFlowStage::pin_entry;
}

bool user_signing_stage_awaiting_approval(UserSigningStage stage)
{
    return stage == UserSigningStage::reviewing ||
           stage == UserSigningStage::pin_entry;
}

bool sui_zklogin_proposal_stage_awaiting_approval(SuiZkLoginProposalStage stage)
{
    return stage == SuiZkLoginProposalStage::reviewing ||
           stage == SuiZkLoginProposalStage::pin_entry;
}

bool local_settings_common_blocked(const DeviceActivityProjection& activity)
{
    return activity.connect_approval_active ||
           activity.protocol_pin_approval_active ||
           activity.policy_update_active ||
           activity.sui_zklogin_proposal_active ||
           activity.identification_display_active ||
           activity.provisioning_flow_active ||
           activity.local_pin_auth_flow_active ||
           activity.payload_delivery_active ||
           activity.user_signing_active ||
           activity.storage_maintenance_active;
}

}  // namespace

DeviceActivityProjection project_device_activity(
    const DeviceActivityFacts& facts)
{
    const bool policy_update_awaiting =
        facts.policy_update.active &&
        policy_update_stage_awaiting_approval(facts.policy_update.stage);
    const bool policy_update_busy =
        facts.policy_update.active &&
        !policy_update_awaiting;
    const bool sui_zklogin_proposal_awaiting =
        facts.sui_zklogin_proposal.active &&
        sui_zklogin_proposal_stage_awaiting_approval(facts.sui_zklogin_proposal.stage);
    const bool sui_zklogin_proposal_busy =
        facts.sui_zklogin_proposal.active &&
        !sui_zklogin_proposal_awaiting;
    const bool user_signing_awaiting =
        facts.user_signing.active &&
        user_signing_stage_awaiting_approval(facts.user_signing.stage);
    const bool storage_maintenance_settings_menu =
        facts.storage_maintenance.flow_active &&
        facts.storage_maintenance.stage == StorageMaintenanceStage::settings_menu;
    const bool payload_delivery_active =
        facts.payload_delivery_receiving || facts.payload_delivery_finalized;

    ProjectedDeviceState state = ProjectedDeviceState::idle;
    if (facts.persistent_material_consistency_error) {
        state = ProjectedDeviceState::error;
    } else if (
        facts.connect_approval_active ||
        facts.protocol_pin_approval_active ||
        policy_update_awaiting ||
        sui_zklogin_proposal_awaiting ||
        user_signing_awaiting) {
        state = ProjectedDeviceState::awaiting_approval;
    } else if (
        facts.provisioning_flow_active ||
        payload_delivery_active ||
        policy_update_busy ||
        sui_zklogin_proposal_busy ||
        (facts.storage_maintenance.flow_active && !storage_maintenance_settings_menu) ||
        facts.local_pin_auth_flow_active ||
        facts.user_signing.active) {
        state = ProjectedDeviceState::busy;
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
        facts.sui_zklogin_proposal.active,
        sui_zklogin_proposal_awaiting,
        sui_zklogin_proposal_busy,
        facts.provisioning_flow_active,
        payload_delivery_active,
        facts.payload_delivery_receiving,
        facts.payload_delivery_finalized,
        facts.storage_maintenance.flow_active,
        storage_maintenance_settings_menu,
        facts.local_pin_auth_flow_active,
        facts.user_signing.active,
        user_signing_awaiting,
    };
}

const char* device_activity_state_name(ProjectedDeviceState state)
{
    switch (state) {
        case ProjectedDeviceState::idle:
            return "idle";
        case ProjectedDeviceState::busy:
            return "busy";
        case ProjectedDeviceState::awaiting_approval:
            return "awaiting_approval";
        case ProjectedDeviceState::error:
            return "error";
    }
    return "error";
}

bool device_activity_blocks_user_signing_ingress(
    const DeviceActivityProjection& activity)
{
    return activity.connect_approval_active ||
           activity.protocol_pin_approval_active ||
           activity.policy_update_active ||
           activity.sui_zklogin_proposal_active ||
           activity.provisioning_flow_active ||
           activity.payload_delivery_active ||
           activity.storage_maintenance_active ||
           activity.local_pin_auth_flow_active ||
           activity.user_signing_active;
}

bool device_activity_allows_local_settings_touch_entry(
    const DeviceActivityProjection& activity)
{
    return activity.provisioned &&
           !local_settings_common_blocked(activity) &&
           activity.ui_idle_for_local_settings;
}

bool device_activity_allows_local_settings_start(
    const DeviceActivityProjection& activity)
{
    return !local_settings_common_blocked(activity) &&
           activity.ui_idle_for_local_settings;
}

bool device_activity_allows_local_error_recovery(
    const DeviceActivityProjection& activity)
{
    return !local_settings_common_blocked(activity);
}

DeviceActivityRequestBlock device_activity_request_block(
    const DeviceActivityProjection& activity,
    DeviceActivityRequestOptions options)
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
    if (activity.sui_zklogin_proposal_active) {
        return { true, "busy", "Device has a pending Sui zkLogin proposal." };
    }
    if (activity.provisioning_flow_active) {
        return { true, "busy", "Device is showing setup material." };
    }
    if (activity.payload_delivery_active && !options.allow_payload_delivery) {
        return {
            true,
            "busy",
            activity.payload_delivery_receiving
                ? "Device has a pending payload transfer."
                : "Device has a pending signable payload.",
        };
    }
    if (activity.storage_maintenance_active) {
        if (options.allow_settings_menu && activity.storage_maintenance_settings_menu) {
            return { false, nullptr, nullptr };
        }
        return {
            true,
            "busy",
            activity.storage_maintenance_settings_menu
                ? "Device is showing local settings UI."
                : "Device is showing storage maintenance UI.",
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

}  // namespace signing
