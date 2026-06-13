#include "agent_q_payload_delivery_admission.h"

#include <string.h>

#include "agent_q_session.h"

namespace agent_q {
namespace {

bool strings_equal(const char* left, const char* right)
{
    if (left == nullptr || right == nullptr) {
        return false;
    }
    return strcmp(left, right) == 0;
}

AgentQPayloadDeliveryAdmissionDecision decision(
    AgentQPayloadDeliveryAdmissionResult result,
    AgentQPayloadDeliveryAdmissionReason reason)
{
    return { result, reason };
}

AgentQPayloadDeliveryAdmissionDecision admit_sign_transaction_from_snapshot(
    const AgentQPayloadDeliverySnapshot& snapshot,
    const AgentQPayloadDeliveryOperationAdmissionInput& input)
{
    if (snapshot.state == AgentQPayloadDeliveryState::idle) {
        return decision(
            AgentQPayloadDeliveryAdmissionResult::ok,
            AgentQPayloadDeliveryAdmissionReason::idle_passthrough);
    }
    if (snapshot.state == AgentQPayloadDeliveryState::receiving) {
        return decision(
            AgentQPayloadDeliveryAdmissionResult::busy,
            AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_upload);
    }

    if (!input.staged_payload_ref) {
        return decision(
            AgentQPayloadDeliveryAdmissionResult::busy,
            AgentQPayloadDeliveryAdmissionReason::blocked_pending_finalized_payload);
    }
    if (!session_id_format_valid(input.session_id) ||
        !strings_equal(snapshot.session_id, input.session_id)) {
        return decision(
            AgentQPayloadDeliveryAdmissionResult::invalid_session,
            AgentQPayloadDeliveryAdmissionReason::invalid_consumer_session);
    }
    if (!payload_delivery_payload_ref_format_valid(input.payload_ref) ||
        !strings_equal(snapshot.payload_ref, input.payload_ref)) {
        return decision(
            AgentQPayloadDeliveryAdmissionResult::invalid_payload_ref,
            AgentQPayloadDeliveryAdmissionReason::invalid_consumer_payload_ref);
    }
    return decision(
        AgentQPayloadDeliveryAdmissionResult::ok,
        AgentQPayloadDeliveryAdmissionReason::finalized_matching_staged_consumer);
}

}  // namespace

AgentQPayloadDeliveryAdmissionDecision payload_delivery_admit_operation(
    const AgentQPayloadDeliveryOperationAdmissionInput& input)
{
    const AgentQPayloadDeliverySnapshot snapshot = payload_delivery_advance_and_snapshot(input.now_tick);
    if (snapshot.state == AgentQPayloadDeliveryState::idle) {
        switch (input.operation) {
            case AgentQPayloadDeliveryOperationKind::payload_upload_chunk:
            case AgentQPayloadDeliveryOperationKind::payload_upload_finish:
            case AgentQPayloadDeliveryOperationKind::payload_upload_abort:
                return decision(
                    AgentQPayloadDeliveryAdmissionResult::unknown_request,
                    AgentQPayloadDeliveryAdmissionReason::missing_active_payload);
            case AgentQPayloadDeliveryOperationKind::sign_transaction:
                return admit_sign_transaction_from_snapshot(snapshot, input);
            case AgentQPayloadDeliveryOperationKind::safe_read:
            case AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup:
            case AgentQPayloadDeliveryOperationKind::payload_upload_begin:
            case AgentQPayloadDeliveryOperationKind::sign_personal_message:
            case AgentQPayloadDeliveryOperationKind::policy_propose:
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
        case AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::ok,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::receiving_retained_result
                    : AgentQPayloadDeliveryAdmissionReason::finalized_retained_result);
        case AgentQPayloadDeliveryOperationKind::disconnect:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::ok,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::receiving_disconnect_cleanup
                    : AgentQPayloadDeliveryAdmissionReason::finalized_disconnect_cleanup);
        case AgentQPayloadDeliveryOperationKind::payload_upload_begin:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::busy,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_upload
                    : AgentQPayloadDeliveryAdmissionReason::blocked_pending_finalized_payload);
        case AgentQPayloadDeliveryOperationKind::payload_upload_chunk:
        case AgentQPayloadDeliveryOperationKind::payload_upload_finish:
            return snapshot.state == AgentQPayloadDeliveryState::receiving
                       ? decision(
                             AgentQPayloadDeliveryAdmissionResult::ok,
                             AgentQPayloadDeliveryAdmissionReason::receiving_upload_continue)
                       : decision(
                             AgentQPayloadDeliveryAdmissionResult::busy,
                             AgentQPayloadDeliveryAdmissionReason::blocked_pending_finalized_payload);
        case AgentQPayloadDeliveryOperationKind::payload_upload_abort:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::ok,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::receiving_upload_abort
                    : AgentQPayloadDeliveryAdmissionReason::finalized_upload_abort);
        case AgentQPayloadDeliveryOperationKind::sign_transaction:
            return admit_sign_transaction_from_snapshot(snapshot, input);
        case AgentQPayloadDeliveryOperationKind::sign_personal_message:
        case AgentQPayloadDeliveryOperationKind::policy_propose:
        case AgentQPayloadDeliveryOperationKind::connect:
        case AgentQPayloadDeliveryOperationKind::identify_device:
            return decision(
                AgentQPayloadDeliveryAdmissionResult::busy,
                snapshot.state == AgentQPayloadDeliveryState::receiving
                    ? AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_upload
                    : AgentQPayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow);
    }
    return decision(
        AgentQPayloadDeliveryAdmissionResult::busy,
        AgentQPayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow);
}

AgentQPayloadDeliveryAdmissionDecision payload_delivery_admit_sign_transaction(
    const AgentQPayloadDeliverySignTransactionAdmissionInput& input,
    void*)
{
    return payload_delivery_admit_operation(
        AgentQPayloadDeliveryOperationAdmissionInput{
            input.now_tick,
            AgentQPayloadDeliveryOperationKind::sign_transaction,
            input.session_id,
            input.staged_payload_ref,
            input.payload_ref,
        });
}

const char* payload_delivery_admission_result_name(
    AgentQPayloadDeliveryAdmissionResult result)
{
    switch (result) {
        case AgentQPayloadDeliveryAdmissionResult::ok:
            return "ok";
        case AgentQPayloadDeliveryAdmissionResult::busy:
            return "busy";
        case AgentQPayloadDeliveryAdmissionResult::invalid_session:
            return "invalid_session";
        case AgentQPayloadDeliveryAdmissionResult::invalid_payload_ref:
            return "invalid_payload_ref";
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
        case AgentQPayloadDeliveryAdmissionReason::receiving_retained_result:
            return "receiving_retained_result";
        case AgentQPayloadDeliveryAdmissionReason::receiving_disconnect_cleanup:
            return "receiving_disconnect_cleanup";
        case AgentQPayloadDeliveryAdmissionReason::receiving_upload_continue:
            return "receiving_upload_continue";
        case AgentQPayloadDeliveryAdmissionReason::receiving_upload_abort:
            return "receiving_upload_abort";
        case AgentQPayloadDeliveryAdmissionReason::finalized_safe_read:
            return "finalized_safe_read";
        case AgentQPayloadDeliveryAdmissionReason::finalized_retained_result:
            return "finalized_retained_result";
        case AgentQPayloadDeliveryAdmissionReason::finalized_disconnect_cleanup:
            return "finalized_disconnect_cleanup";
        case AgentQPayloadDeliveryAdmissionReason::finalized_upload_abort:
            return "finalized_upload_abort";
        case AgentQPayloadDeliveryAdmissionReason::finalized_matching_staged_consumer:
            return "finalized_matching_staged_consumer";
        case AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_upload:
            return "blocked_incomplete_upload";
        case AgentQPayloadDeliveryAdmissionReason::blocked_pending_finalized_payload:
            return "blocked_pending_finalized_payload";
        case AgentQPayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow:
            return "blocked_unrelated_sensitive_flow";
        case AgentQPayloadDeliveryAdmissionReason::invalid_consumer_session:
            return "invalid_consumer_session";
        case AgentQPayloadDeliveryAdmissionReason::invalid_consumer_payload_ref:
            return "invalid_consumer_payload_ref";
        case AgentQPayloadDeliveryAdmissionReason::missing_active_payload:
            return "missing_active_payload";
    }
    return "unknown";
}

}  // namespace agent_q
