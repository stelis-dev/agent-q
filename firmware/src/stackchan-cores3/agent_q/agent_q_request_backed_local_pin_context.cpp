#include "agent_q_request_backed_local_pin_context.h"

#include <stdio.h>
#include <string.h>

#include "agent_q_policy_update_flow.h"
#include "agent_q_protocol_pin_approval.h"
#include "agent_q_sui_zklogin_proposal_flow.h"
#include "agent_q_user_signing_confirmation.h"
#include "agent_q_user_signing_flow.h"

namespace agent_q {

AgentQRequestBackedLocalPinOwner request_backed_local_pin_owner_for_purpose(
    AgentQLocalPinAuthPurpose purpose)
{
    switch (purpose) {
        case AgentQLocalPinAuthPurpose::connect:
        case AgentQLocalPinAuthPurpose::policy_update:
        case AgentQLocalPinAuthPurpose::sui_zklogin_proposal:
            return AgentQRequestBackedLocalPinOwner::protocol_pin_approval;
        case AgentQLocalPinAuthPurpose::user_signing:
            return AgentQRequestBackedLocalPinOwner::user_signing;
        default:
            return AgentQRequestBackedLocalPinOwner::none;
    }
}

bool request_backed_local_pin_purpose(AgentQLocalPinAuthPurpose purpose)
{
    return request_backed_local_pin_owner_for_purpose(purpose) !=
           AgentQRequestBackedLocalPinOwner::none;
}

bool request_backed_local_pin_request_id(
    AgentQLocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case AgentQRequestBackedLocalPinOwner::user_signing: {
            if (output == nullptr || output_size == 0) {
                return false;
            }
            output[0] = '\0';
            const AgentQUserSigningFlowCoreSnapshot snapshot =
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
        case AgentQRequestBackedLocalPinOwner::protocol_pin_approval:
            return protocol_pin_approval_request_id_for_local_pin_purpose(
                purpose,
                output,
                output_size);
        case AgentQRequestBackedLocalPinOwner::none:
        default:
            if (output != nullptr && output_size > 0) {
                output[0] = '\0';
            }
            return false;
    }
}

AgentQTimeoutWindow request_backed_local_pin_cap_input_window(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now,
    AgentQTimeoutWindow input_window)
{
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return kAgentQTimeoutWindowNone;
    }

    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case AgentQRequestBackedLocalPinOwner::user_signing: {
            const AgentQUserSigningFlowCoreSnapshot snapshot =
                user_signing_flow_core_snapshot();
            if (!snapshot.active) {
                return kAgentQTimeoutWindowNone;
            }
            const TickType_t capped_deadline =
                timeout_window_cap_deadline(
                    snapshot.request_window,
                    input_window.deadline);
            return timeout_window_from_deadline(
                input_window.started_at,
                capped_deadline);
        }
        case AgentQRequestBackedLocalPinOwner::protocol_pin_approval: {
            const AgentQProtocolPinApprovalSnapshot snapshot =
                protocol_pin_approval_snapshot();
            if (!snapshot.active) {
                return kAgentQTimeoutWindowNone;
            }
            const TickType_t capped_deadline =
                timeout_window_cap_deadline(
                    snapshot.request_window,
                    input_window.deadline);
            return timeout_window_from_deadline(
                input_window.started_at,
                capped_deadline);
        }
        case AgentQRequestBackedLocalPinOwner::none:
        default:
            return kAgentQTimeoutWindowNone;
    }
}

bool request_backed_local_pin_resume_input_window(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case AgentQRequestBackedLocalPinOwner::user_signing:
            return user_signing_flow_refresh_pin_deadline(now) ==
                   AgentQUserSigningTransitionResult::ok;
        case AgentQRequestBackedLocalPinOwner::protocol_pin_approval:
            return protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
                purpose,
                now);
        case AgentQRequestBackedLocalPinOwner::none:
        default:
            return false;
    }
}

bool request_backed_local_pin_pause_input_window(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case AgentQRequestBackedLocalPinOwner::user_signing:
            return user_signing_confirmation_mark_pin_verification_started(now) ==
                   AgentQUserSigningConfirmationResult::ok;
        case AgentQRequestBackedLocalPinOwner::protocol_pin_approval:
            if (purpose == AgentQLocalPinAuthPurpose::policy_update &&
                policy_update_flow_mark_pin_verifying() !=
                    AgentQPolicyUpdateFlowTransitionResult::ok) {
                return false;
            }
            if (purpose == AgentQLocalPinAuthPurpose::sui_zklogin_proposal &&
                sui_zklogin_proposal_flow_mark_pin_verifying() !=
                    AgentQSuiZkLoginProposalTransitionResult::ok) {
                return false;
            }
            return protocol_pin_approval_pause_deadline_for_local_pin_purpose(
                purpose,
                now);
        case AgentQRequestBackedLocalPinOwner::none:
        default:
            return true;
    }
}

bool request_backed_local_pin_deadline_reached(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case AgentQRequestBackedLocalPinOwner::user_signing:
            return user_signing_flow_deadline_reached(now);
        case AgentQRequestBackedLocalPinOwner::protocol_pin_approval:
            return protocol_pin_approval_deadline_reached_for_local_pin_purpose(
                purpose,
                now);
        case AgentQRequestBackedLocalPinOwner::none:
        default:
            return false;
    }
}

}  // namespace agent_q
