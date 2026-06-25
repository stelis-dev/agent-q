#pragma once

#include "agent_q_payload_delivery_operation_kind.h"
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
    unknown_request,
};

enum class AgentQPayloadDeliveryAdmissionReason {
    idle_passthrough,
    receiving_safe_read,
    receiving_retained_result,
    receiving_disconnect_cleanup,
    receiving_transfer_continue,
    receiving_transfer_abort,
    finalized_safe_read,
    finalized_retained_result,
    finalized_disconnect_cleanup,
    finalized_transfer_abort,
    blocked_incomplete_transfer,
    blocked_pending_finalized_payload,
    blocked_unrelated_sensitive_flow,
    missing_active_payload,
};

struct AgentQPayloadDeliveryOperationAdmissionInput {
    AgentQTimeoutTick now_tick;
    AgentQPayloadDeliveryOperationKind operation;
    const char* session_id;
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

using AgentQPayloadDeliveryOperationAdmissionFn =
    AgentQPayloadDeliveryAdmissionDecision (*)(
        const AgentQPayloadDeliveryOperationAdmissionInput& input);

AgentQPayloadDeliveryAdmissionDecision payload_delivery_admit_operation(
    const AgentQPayloadDeliveryOperationAdmissionInput& input);

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
                AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_transfer ||
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

const char* payload_delivery_admission_result_name(
    AgentQPayloadDeliveryAdmissionResult result);
const char* payload_delivery_admission_reason_name(
    AgentQPayloadDeliveryAdmissionReason reason);

}  // namespace agent_q
