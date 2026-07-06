#pragma once

#include "storage_maintenance.h"
#include "policy/policy_update_flow.h"
#include "sui_zklogin_proposal_flow.h"
#include "user_signing_flow.h"

namespace signing {

enum class ProjectedDeviceState {
    idle,
    busy,
    awaiting_approval,
    error,
};

struct DeviceActivityFacts {
    bool persistent_material_consistency_error;
    bool provisioned;
    bool ui_idle_for_local_settings;
    bool identification_display_active;
    bool connect_approval_active;
    bool protocol_pin_approval_active;
    bool provisioning_flow_active;
    bool local_pin_auth_flow_active;
    bool payload_delivery_receiving;
    bool payload_delivery_finalized;
    PolicyUpdateFlowSnapshot policy_update;
    SuiZkLoginProposalSnapshot sui_zklogin_proposal;
    StorageMaintenanceSnapshot storage_maintenance;
    UserSigningFlowCoreSnapshot user_signing;
};

struct DeviceActivityProjection {
    ProjectedDeviceState device_state;
    bool persistent_material_consistency_error;
    bool provisioned;
    bool ui_idle_for_local_settings;
    bool identification_display_active;
    bool connect_approval_active;
    bool protocol_pin_approval_active;
    bool policy_update_active;
    bool policy_update_awaiting_approval;
    bool policy_update_busy;
    bool sui_zklogin_proposal_active;
    bool sui_zklogin_proposal_awaiting_approval;
    bool sui_zklogin_proposal_busy;
    bool provisioning_flow_active;
    bool payload_delivery_active;
    bool payload_delivery_receiving;
    bool payload_delivery_finalized;
    bool storage_maintenance_active;
    bool storage_maintenance_settings_menu;
    bool local_pin_auth_flow_active;
    bool user_signing_active;
    bool user_signing_awaiting_approval;
};

struct DeviceActivityUsbRequestOptions {
    bool allow_settings_menu;
    bool allow_payload_delivery;
};

struct DeviceActivityUsbRequestBlock {
    bool blocked;
    const char* code;
    const char* message;
};

DeviceActivityProjection project_device_activity(
    const DeviceActivityFacts& facts);
const char* device_activity_state_name(ProjectedDeviceState state);
bool device_activity_blocks_user_signing_ingress(
    const DeviceActivityProjection& activity);
bool device_activity_allows_local_settings_touch_entry(
    const DeviceActivityProjection& activity);
bool device_activity_allows_local_settings_start(
    const DeviceActivityProjection& activity);
bool device_activity_allows_local_error_recovery(
    const DeviceActivityProjection& activity);
DeviceActivityUsbRequestBlock device_activity_usb_request_block(
    const DeviceActivityProjection& activity,
    DeviceActivityUsbRequestOptions options);

}  // namespace signing
