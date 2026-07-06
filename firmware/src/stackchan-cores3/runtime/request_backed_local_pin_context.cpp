#include "request_backed_local_pin_context.h"

#include <stdio.h>
#include <string.h>

#include "policy/policy_update_flow.h"
#include "protocol_pin_approval.h"
#include "sui_zklogin_proposal_flow.h"
#include "user_signing_confirmation.h"
#include "user_signing_flow.h"

namespace signing {

RequestBackedLocalPinOwner request_backed_local_pin_owner_for_purpose(
    LocalPinAuthPurpose purpose)
{
    switch (purpose) {
        case LocalPinAuthPurpose::connect:
        case LocalPinAuthPurpose::policy_update:
        case LocalPinAuthPurpose::sui_zklogin_proposal:
            return RequestBackedLocalPinOwner::protocol_pin_approval;
        case LocalPinAuthPurpose::user_signing:
            return RequestBackedLocalPinOwner::user_signing;
        default:
            return RequestBackedLocalPinOwner::none;
    }
}

bool request_backed_local_pin_purpose(LocalPinAuthPurpose purpose)
{
    return request_backed_local_pin_owner_for_purpose(purpose) !=
           RequestBackedLocalPinOwner::none;
}

bool request_backed_local_pin_request_id(
    LocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case RequestBackedLocalPinOwner::user_signing: {
            if (output == nullptr || output_size == 0) {
                return false;
            }
            output[0] = '\0';
            const UserSigningFlowCoreSnapshot snapshot =
                user_signing_flow_core_snapshot();
            if (!snapshot.active || snapshot.request_id[0] == '\0') {
                return false;
            }
            if (strlen(snapshot.request_id) >= output_size) {
                return false;
            }
            snprintf(output, output_size, "%s", snapshot.request_id);
            return true;
        }
        case RequestBackedLocalPinOwner::protocol_pin_approval:
            return protocol_pin_approval_request_id_for_local_pin_purpose(
                purpose,
                output,
                output_size);
        case RequestBackedLocalPinOwner::none:
        default:
            if (output != nullptr && output_size > 0) {
                output[0] = '\0';
            }
            return false;
    }
}

TimeoutWindow request_backed_local_pin_cap_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now,
    TimeoutWindow input_window)
{
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return kTimeoutWindowNone;
    }

    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case RequestBackedLocalPinOwner::user_signing: {
            TimeoutWindow capped = kTimeoutWindowNone;
            const UserSigningTransitionResult result =
                user_signing_flow_cap_request_backed_pin_input_window(
                    now,
                    input_window,
                    &capped);
            if (result != UserSigningTransitionResult::ok) {
                return kTimeoutWindowNone;
            }
            return capped;
        }
        case RequestBackedLocalPinOwner::protocol_pin_approval: {
            const ProtocolPinApprovalSnapshot snapshot =
                protocol_pin_approval_snapshot();
            if (!snapshot.active) {
                return kTimeoutWindowNone;
            }
            const TickType_t capped_deadline =
                timeout_window_cap_deadline(
                    snapshot.request_window,
                    input_window.deadline);
            return timeout_window_from_deadline(
                input_window.started_at,
                capped_deadline);
        }
        case RequestBackedLocalPinOwner::none:
        default:
            return kTimeoutWindowNone;
    }
}

bool request_backed_local_pin_resume_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case RequestBackedLocalPinOwner::user_signing:
            return user_signing_flow_refresh_pin_deadline(now) ==
                   UserSigningTransitionResult::ok;
        case RequestBackedLocalPinOwner::protocol_pin_approval:
            return protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
                purpose,
                now);
        case RequestBackedLocalPinOwner::none:
        default:
            return false;
    }
}

bool request_backed_local_pin_pause_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case RequestBackedLocalPinOwner::user_signing:
            return user_signing_confirmation_mark_pin_verification_started(now) ==
                   UserSigningConfirmationResult::ok;
        case RequestBackedLocalPinOwner::protocol_pin_approval:
            if (purpose == LocalPinAuthPurpose::policy_update &&
                policy_update_flow_mark_pin_verifying() !=
                    PolicyUpdateFlowTransitionResult::ok) {
                return false;
            }
            if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
                sui_zklogin_proposal_flow_mark_pin_verifying() !=
                    SuiZkLoginProposalTransitionResult::ok) {
                return false;
            }
            return protocol_pin_approval_pause_deadline_for_local_pin_purpose(
                purpose,
                now);
        case RequestBackedLocalPinOwner::none:
        default:
            return true;
    }
}

bool request_backed_local_pin_deadline_reached(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case RequestBackedLocalPinOwner::user_signing:
            return user_signing_flow_apply_deadline_transition(now);
        case RequestBackedLocalPinOwner::protocol_pin_approval:
            return protocol_pin_approval_deadline_reached_for_local_pin_purpose(
                purpose,
                now);
        case RequestBackedLocalPinOwner::none:
        default:
            return false;
    }
}

}  // namespace signing
