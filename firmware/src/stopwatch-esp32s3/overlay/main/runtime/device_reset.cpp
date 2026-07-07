#include "device_reset.h"

#include "credential_preparation_state.h"
#include "local_auth.h"
#include "policy/policy_store.h"
#include "policy/policy_update_flow.h"
#include "policy/policy_update_marker.h"
#include "protocol/approval_history.h"
#include "protocol/signing_mode.h"
#include "protocol/signing_response_store.h"
#include "sui_zklogin_credential_store.h"
#include "sui_zklogin_proposal_state.h"
#include "transport/payload_delivery_store.h"
#include "usb_transport.h"

namespace stopwatch_target {

bool device_reset_all()
{
    usb_transport_clear_session_scoped_state();
    credential_preparation_state_clear();
    sui_zklogin_proposal_state_clear();
    signing::policy_update_flow_clear();
    signing::payload_delivery_store_reset();
    signing::signing_response_clear_all();

    bool wiped = true;
    wiped = wipe_sui_zklogin_credential() && wiped;
    wiped = local_auth_clear() && wiped;
    wiped = signing::wipe_policy() && wiped;
    wiped = signing::wipe_signing_authorization_mode() && wiped;
    wiped = signing::approval_history_wipe() && wiped;
    wiped = signing::policy_update_marker_clear() && wiped;

    const bool reset_complete =
        wiped &&
        sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing &&
        local_auth_snapshot(0).status == LocalAuthStoreStatus::missing;
    if (reset_complete) {
        usb_transport_set_runtime_state(UsbRuntimeState{
            LocalAuthProjectionStatus::missing,
            false,
            false,
        });
    }
    return reset_complete;
}

}  // namespace stopwatch_target
