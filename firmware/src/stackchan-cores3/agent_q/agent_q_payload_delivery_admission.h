#pragma once

#include "agent_q_payload_delivery_store.h"

namespace agent_q {

// Operation-permission source of truth for volatile payload delivery state.
// The payload store owns bytes and state, the device activity projection owns
// status/UI terms, and the USB request server owns persistent material/session
// guards. This module only decides whether an already state-eligible operation
// may proceed while payload delivery is idle, receiving, or finalized.
enum class AgentQPayloadDeliveryAdmissionResult {
    ok,
    busy,
    invalid_session,
    invalid_payload_ref,
    unknown_request,
};

enum class AgentQPayloadDeliveryAdmissionReason {
    idle_passthrough,
    receiving_safe_read,
    receiving_retained_result,
    receiving_disconnect_cleanup,
    receiving_upload_continue,
    receiving_upload_abort,
    finalized_safe_read,
    finalized_retained_result,
    finalized_disconnect_cleanup,
    finalized_upload_abort,
    finalized_matching_staged_consumer,
    blocked_incomplete_upload,
    blocked_pending_finalized_payload,
    blocked_unrelated_sensitive_flow,
    invalid_consumer_session,
    invalid_consumer_payload_ref,
    missing_active_payload,
};

enum class AgentQPayloadDeliveryOperationKind {
    safe_read,
    retained_result_read_cleanup,
    payload_upload_begin,
    payload_upload_chunk,
    payload_upload_finish,
    payload_upload_abort,
    sign_transaction,
    sign_personal_message,
    policy_propose,
    connect,
    identify_device,
    disconnect,
};

struct AgentQPayloadDeliveryOperationAdmissionInput {
    AgentQTimeoutTick now_tick;
    AgentQPayloadDeliveryOperationKind operation;
    const char* session_id;
    bool staged_payload_ref;
    const char* payload_ref;
};

struct AgentQPayloadDeliverySignTransactionAdmissionInput {
    AgentQTimeoutTick now_tick;
    const char* session_id;
    bool staged_payload_ref;
    const char* payload_ref;
};

struct AgentQPayloadDeliveryAdmissionDecision {
    AgentQPayloadDeliveryAdmissionResult result;
    AgentQPayloadDeliveryAdmissionReason reason;
};

inline bool operator==(
    const AgentQPayloadDeliveryAdmissionDecision& decision,
    AgentQPayloadDeliveryAdmissionResult result)
{
    return decision.result == result;
}

inline bool operator!=(
    const AgentQPayloadDeliveryAdmissionDecision& decision,
    AgentQPayloadDeliveryAdmissionResult result)
{
    return !(decision == result);
}

using AgentQPayloadDeliverySignTransactionAdmissionFn =
    AgentQPayloadDeliveryAdmissionDecision (*)(
        const AgentQPayloadDeliverySignTransactionAdmissionInput& input,
        void* context);

AgentQPayloadDeliveryAdmissionDecision payload_delivery_admit_operation(
    const AgentQPayloadDeliveryOperationAdmissionInput& input);
AgentQPayloadDeliveryAdmissionDecision payload_delivery_admit_sign_transaction(
    const AgentQPayloadDeliverySignTransactionAdmissionInput& input,
    void* context);

inline bool payload_delivery_admission_allowed(
    const AgentQPayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == AgentQPayloadDeliveryAdmissionResult::ok;
}

inline bool payload_delivery_admission_busy(
    const AgentQPayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == AgentQPayloadDeliveryAdmissionResult::busy;
}

inline bool payload_delivery_admission_blocks_sensitive_flow(
    const AgentQPayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == AgentQPayloadDeliveryAdmissionResult::busy &&
           (decision.reason ==
                AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_upload ||
            decision.reason ==
                AgentQPayloadDeliveryAdmissionReason::blocked_pending_finalized_payload ||
            decision.reason ==
                AgentQPayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow);
}

inline bool payload_delivery_admission_allows_safe_read(
    const AgentQPayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == AgentQPayloadDeliveryAdmissionResult::ok &&
           (decision.reason == AgentQPayloadDeliveryAdmissionReason::idle_passthrough ||
            decision.reason == AgentQPayloadDeliveryAdmissionReason::receiving_safe_read ||
            decision.reason == AgentQPayloadDeliveryAdmissionReason::finalized_safe_read);
}

inline bool payload_delivery_admission_allows_retained_result_cleanup(
    const AgentQPayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == AgentQPayloadDeliveryAdmissionResult::ok &&
           (decision.reason == AgentQPayloadDeliveryAdmissionReason::idle_passthrough ||
            decision.reason == AgentQPayloadDeliveryAdmissionReason::receiving_retained_result ||
            decision.reason == AgentQPayloadDeliveryAdmissionReason::finalized_retained_result);
}

inline bool payload_delivery_admission_allows_disconnect_cleanup(
    const AgentQPayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == AgentQPayloadDeliveryAdmissionResult::ok &&
           (decision.reason == AgentQPayloadDeliveryAdmissionReason::idle_passthrough ||
            decision.reason == AgentQPayloadDeliveryAdmissionReason::receiving_disconnect_cleanup ||
            decision.reason == AgentQPayloadDeliveryAdmissionReason::finalized_disconnect_cleanup);
}

inline bool payload_delivery_admission_allows_staged_consumer(
    const AgentQPayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == AgentQPayloadDeliveryAdmissionResult::ok &&
           decision.reason ==
               AgentQPayloadDeliveryAdmissionReason::finalized_matching_staged_consumer;
}

const char* payload_delivery_admission_result_name(
    AgentQPayloadDeliveryAdmissionResult result);
const char* payload_delivery_admission_reason_name(
    AgentQPayloadDeliveryAdmissionReason reason);

}  // namespace agent_q
