#include "agent_q_payload_delivery_admission.h"

namespace agent_q {
namespace {

AgentQPayloadDeliveryAdmissionDecision decision(
    AgentQPayloadDeliveryAdmissionResult result,
    AgentQPayloadDeliveryAdmissionReason reason)
{
    return { result, reason };
}

}  // namespace

AgentQPayloadDeliveryAdmissionDecision payload_delivery_admit_operation(
    const AgentQPayloadDeliveryOperationAdmissionInput& input)
{
    const AgentQPayloadDeliverySnapshot snapshot = payload_delivery_advance_and_snapshot(input.now_tick);
    if (snapshot.state == AgentQPayloadDeliveryState::idle) {
        switch (input.operation) {
            case AgentQPayloadDeliveryOperationKind::payload_transfer_chunk:
            case AgentQPayloadDeliveryOperationKind::payload_transfer_finish:
            case AgentQPayloadDeliveryOperationKind::payload_transfer_abort:
                return decision(
                    AgentQPayloadDeliveryAdmissionResult::unknown_request,
                    AgentQPayloadDeliveryAdmissionReason::missing_active_payload);
            case AgentQPayloadDeliveryOperationKind::safe_read:
            case AgentQPayloadDeliveryOperationKind::retained_response_read_cleanup:
            case AgentQPayloadDeliveryOperationKind::payload_transfer_begin:
            case AgentQPayloadDeliveryOperationKind::sign_transaction:
            case AgentQPayloadDeliveryOperationKind::sign_personal_message:
            case AgentQPayloadDeliveryOperationKind::policy_propose:
            case AgentQPayloadDeliveryOperationKind::credential_propose:
            case AgentQPayloadDeliveryOperationKind::connect:
            case AgentQPayloadDeliveryOperationKind::identify_device:
            case AgentQPayloadDeliveryOperationKind::disconnect:
                return decision(
                    AgentQPayloadDeliveryAdmissionResult::ok,
                    AgentQPayloadDeliveryAdmissionReason::idle_passthrough);
        }
        return decision(
            AgentQPayloadDeliveryAdmissionResult::unknown_request,
            AgentQPayloadDeliveryAdmissionReason::missing_active_payload);
    }

    switch (input.operation) {
        case AgentQPayloadDeliveryOperationKind::safe_read:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::ok,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::receiving_safe_read
                    : AgentQPayloadDeliveryAdmissionReason::finalized_safe_read);
        case AgentQPayloadDeliveryOperationKind::retained_response_read_cleanup:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::ok,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::receiving_retained_response
                    : AgentQPayloadDeliveryAdmissionReason::finalized_retained_response);
        case AgentQPayloadDeliveryOperationKind::disconnect:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::ok,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::receiving_disconnect_cleanup
                    : AgentQPayloadDeliveryAdmissionReason::finalized_disconnect_cleanup);
        case AgentQPayloadDeliveryOperationKind::payload_transfer_begin:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::busy,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_transfer
                    : AgentQPayloadDeliveryAdmissionReason::blocked_pending_finalized_payload);
        case AgentQPayloadDeliveryOperationKind::payload_transfer_chunk:
        case AgentQPayloadDeliveryOperationKind::payload_transfer_finish:
            return snapshot.state == AgentQPayloadDeliveryState::receiving
                       ? decision(
                             AgentQPayloadDeliveryAdmissionResult::ok,
                             AgentQPayloadDeliveryAdmissionReason::receiving_transfer_continue)
                       : decision(
                             AgentQPayloadDeliveryAdmissionResult::busy,
                             AgentQPayloadDeliveryAdmissionReason::blocked_pending_finalized_payload);
        case AgentQPayloadDeliveryOperationKind::payload_transfer_abort:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::ok,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::receiving_transfer_abort
                    : AgentQPayloadDeliveryAdmissionReason::finalized_transfer_abort);
        case AgentQPayloadDeliveryOperationKind::sign_transaction:
        case AgentQPayloadDeliveryOperationKind::sign_personal_message:
        case AgentQPayloadDeliveryOperationKind::policy_propose:
        case AgentQPayloadDeliveryOperationKind::credential_propose:
        case AgentQPayloadDeliveryOperationKind::connect:
        case AgentQPayloadDeliveryOperationKind::identify_device:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::busy,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_transfer
                    : AgentQPayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow);
    }
    return decision(
        AgentQPayloadDeliveryAdmissionResult::busy,
        AgentQPayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow);
}

const char* payload_delivery_admission_result_name(
    AgentQPayloadDeliveryAdmissionResult result)
{
    switch (result) {
        case AgentQPayloadDeliveryAdmissionResult::ok:
            return "ok";
        case AgentQPayloadDeliveryAdmissionResult::busy:
            return "busy";
        case AgentQPayloadDeliveryAdmissionResult::unknown_request:
            return "unknown_request";
    }
    return "unknown";
}

const char* payload_delivery_admission_reason_name(
    AgentQPayloadDeliveryAdmissionReason reason)
{
    switch (reason) {
        case AgentQPayloadDeliveryAdmissionReason::idle_passthrough:
            return "idle_passthrough";
        case AgentQPayloadDeliveryAdmissionReason::receiving_safe_read:
            return "receiving_safe_read";
        case AgentQPayloadDeliveryAdmissionReason::receiving_retained_response:
            return "receiving_retained_response";
        case AgentQPayloadDeliveryAdmissionReason::receiving_disconnect_cleanup:
            return "receiving_disconnect_cleanup";
        case AgentQPayloadDeliveryAdmissionReason::receiving_transfer_continue:
            return "receiving_transfer_continue";
        case AgentQPayloadDeliveryAdmissionReason::receiving_transfer_abort:
            return "receiving_transfer_abort";
        case AgentQPayloadDeliveryAdmissionReason::finalized_safe_read:
            return "finalized_safe_read";
        case AgentQPayloadDeliveryAdmissionReason::finalized_retained_response:
            return "finalized_retained_response";
        case AgentQPayloadDeliveryAdmissionReason::finalized_disconnect_cleanup:
            return "finalized_disconnect_cleanup";
        case AgentQPayloadDeliveryAdmissionReason::finalized_transfer_abort:
            return "finalized_transfer_abort";
        case AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_transfer:
            return "blocked_incomplete_transfer";
        case AgentQPayloadDeliveryAdmissionReason::blocked_pending_finalized_payload:
            return "blocked_pending_finalized_payload";
        case AgentQPayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow:
            return "blocked_unrelated_sensitive_flow";
        case AgentQPayloadDeliveryAdmissionReason::missing_active_payload:
            return "missing_active_payload";
    }
    return "unknown";
}

}  // namespace agent_q
