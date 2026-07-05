#pragma once

#include "transport/payload_delivery_operation_kind.h"

namespace signing {

enum class PayloadDeliveryAdmissionState {
    idle,
    receiving,
    finalized,
};

enum class PayloadDeliveryAdmissionResult {
    ok,
    busy,
    unknown_request,
};

enum class PayloadDeliveryAdmissionReason {
    idle_passthrough,
    receiving_safe_read,
    receiving_retained_response,
    receiving_disconnect_cleanup,
    receiving_transfer_continue,
    receiving_transfer_abort,
    finalized_safe_read,
    finalized_retained_response,
    finalized_disconnect_cleanup,
    finalized_transfer_abort,
    blocked_incomplete_transfer,
    blocked_pending_finalized_payload,
    blocked_unrelated_sensitive_flow,
    missing_active_payload,
};

struct PayloadDeliveryAdmissionDecision {
    PayloadDeliveryAdmissionResult result;
    PayloadDeliveryAdmissionReason reason;
};

inline bool operator==(
    const PayloadDeliveryAdmissionDecision& decision,
    PayloadDeliveryAdmissionResult result)
{
    return decision.result == result;
}

inline bool operator!=(
    const PayloadDeliveryAdmissionDecision& decision,
    PayloadDeliveryAdmissionResult result)
{
    return !(decision == result);
}

PayloadDeliveryAdmissionDecision payload_delivery_admit_operation_for_state(
    PayloadDeliveryAdmissionState state,
    PayloadDeliveryOperationKind operation);

inline bool payload_delivery_admission_allowed(
    const PayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == PayloadDeliveryAdmissionResult::ok;
}

inline bool payload_delivery_admission_busy(
    const PayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == PayloadDeliveryAdmissionResult::busy;
}

inline bool payload_delivery_admission_blocks_sensitive_flow(
    const PayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == PayloadDeliveryAdmissionResult::busy &&
           (decision.reason ==
                PayloadDeliveryAdmissionReason::blocked_incomplete_transfer ||
            decision.reason ==
                PayloadDeliveryAdmissionReason::blocked_pending_finalized_payload ||
            decision.reason ==
                PayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow);
}

inline bool payload_delivery_admission_allows_safe_read(
    const PayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == PayloadDeliveryAdmissionResult::ok &&
           (decision.reason == PayloadDeliveryAdmissionReason::idle_passthrough ||
            decision.reason == PayloadDeliveryAdmissionReason::receiving_safe_read ||
            decision.reason == PayloadDeliveryAdmissionReason::finalized_safe_read);
}

inline bool payload_delivery_admission_allows_retained_response_cleanup(
    const PayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == PayloadDeliveryAdmissionResult::ok &&
           (decision.reason == PayloadDeliveryAdmissionReason::idle_passthrough ||
            decision.reason == PayloadDeliveryAdmissionReason::receiving_retained_response ||
            decision.reason == PayloadDeliveryAdmissionReason::finalized_retained_response);
}

inline bool payload_delivery_admission_allows_disconnect_cleanup(
    const PayloadDeliveryAdmissionDecision& decision)
{
    return decision.result == PayloadDeliveryAdmissionResult::ok &&
           (decision.reason == PayloadDeliveryAdmissionReason::idle_passthrough ||
            decision.reason == PayloadDeliveryAdmissionReason::receiving_disconnect_cleanup ||
            decision.reason == PayloadDeliveryAdmissionReason::finalized_disconnect_cleanup);
}

const char* payload_delivery_admission_result_name(
    PayloadDeliveryAdmissionResult result);
const char* payload_delivery_admission_reason_name(
    PayloadDeliveryAdmissionReason reason);

}  // namespace signing
