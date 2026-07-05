#include "transport/payload_delivery_admission.h"

namespace signing {
namespace {

PayloadDeliveryAdmissionDecision decision(
    PayloadDeliveryAdmissionResult result,
    PayloadDeliveryAdmissionReason reason)
{
    return {result, reason};
}

}  // namespace

PayloadDeliveryAdmissionDecision payload_delivery_admit_operation_for_state(
    PayloadDeliveryAdmissionState state,
    PayloadDeliveryOperationKind operation)
{
    if (state == PayloadDeliveryAdmissionState::idle) {
        switch (operation) {
            case PayloadDeliveryOperationKind::payload_transfer_chunk:
            case PayloadDeliveryOperationKind::payload_transfer_finish:
            case PayloadDeliveryOperationKind::payload_transfer_abort:
                return decision(
                    PayloadDeliveryAdmissionResult::unknown_request,
                    PayloadDeliveryAdmissionReason::missing_active_payload);
            case PayloadDeliveryOperationKind::safe_read:
            case PayloadDeliveryOperationKind::retained_response_read_cleanup:
            case PayloadDeliveryOperationKind::payload_transfer_begin:
            case PayloadDeliveryOperationKind::sign_transaction:
            case PayloadDeliveryOperationKind::sign_personal_message:
            case PayloadDeliveryOperationKind::policy_propose:
            case PayloadDeliveryOperationKind::credential_propose:
            case PayloadDeliveryOperationKind::connect:
            case PayloadDeliveryOperationKind::identify_device:
            case PayloadDeliveryOperationKind::disconnect:
                return decision(
                    PayloadDeliveryAdmissionResult::ok,
                    PayloadDeliveryAdmissionReason::idle_passthrough);
        }
        return decision(
            PayloadDeliveryAdmissionResult::unknown_request,
            PayloadDeliveryAdmissionReason::missing_active_payload);
    }

    switch (operation) {
        case PayloadDeliveryOperationKind::safe_read:
            return decision(
                PayloadDeliveryAdmissionResult::ok,
                state == PayloadDeliveryAdmissionState::receiving
                    ? PayloadDeliveryAdmissionReason::receiving_safe_read
                    : PayloadDeliveryAdmissionReason::finalized_safe_read);
        case PayloadDeliveryOperationKind::retained_response_read_cleanup:
            return decision(
                PayloadDeliveryAdmissionResult::ok,
                state == PayloadDeliveryAdmissionState::receiving
                    ? PayloadDeliveryAdmissionReason::receiving_retained_response
                    : PayloadDeliveryAdmissionReason::finalized_retained_response);
        case PayloadDeliveryOperationKind::disconnect:
            return decision(
                PayloadDeliveryAdmissionResult::ok,
                state == PayloadDeliveryAdmissionState::receiving
                    ? PayloadDeliveryAdmissionReason::receiving_disconnect_cleanup
                    : PayloadDeliveryAdmissionReason::finalized_disconnect_cleanup);
        case PayloadDeliveryOperationKind::payload_transfer_begin:
            return decision(
                PayloadDeliveryAdmissionResult::busy,
                state == PayloadDeliveryAdmissionState::receiving
                    ? PayloadDeliveryAdmissionReason::blocked_incomplete_transfer
                    : PayloadDeliveryAdmissionReason::blocked_pending_finalized_payload);
        case PayloadDeliveryOperationKind::payload_transfer_chunk:
        case PayloadDeliveryOperationKind::payload_transfer_finish:
            return state == PayloadDeliveryAdmissionState::receiving
                       ? decision(
                             PayloadDeliveryAdmissionResult::ok,
                             PayloadDeliveryAdmissionReason::receiving_transfer_continue)
                       : decision(
                             PayloadDeliveryAdmissionResult::busy,
                             PayloadDeliveryAdmissionReason::blocked_pending_finalized_payload);
        case PayloadDeliveryOperationKind::payload_transfer_abort:
            return decision(
                PayloadDeliveryAdmissionResult::ok,
                state == PayloadDeliveryAdmissionState::receiving
                    ? PayloadDeliveryAdmissionReason::receiving_transfer_abort
                    : PayloadDeliveryAdmissionReason::finalized_transfer_abort);
        case PayloadDeliveryOperationKind::sign_transaction:
        case PayloadDeliveryOperationKind::sign_personal_message:
        case PayloadDeliveryOperationKind::policy_propose:
        case PayloadDeliveryOperationKind::credential_propose:
        case PayloadDeliveryOperationKind::connect:
        case PayloadDeliveryOperationKind::identify_device:
            return decision(
                PayloadDeliveryAdmissionResult::busy,
                state == PayloadDeliveryAdmissionState::receiving
                    ? PayloadDeliveryAdmissionReason::blocked_incomplete_transfer
                    : PayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow);
    }
    return decision(
        PayloadDeliveryAdmissionResult::busy,
        PayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow);
}

const char* payload_delivery_admission_result_name(
    PayloadDeliveryAdmissionResult result)
{
    switch (result) {
        case PayloadDeliveryAdmissionResult::ok:
            return "ok";
        case PayloadDeliveryAdmissionResult::busy:
            return "busy";
        case PayloadDeliveryAdmissionResult::unknown_request:
            return "unknown_request";
    }
    return "unknown";
}

const char* payload_delivery_admission_reason_name(
    PayloadDeliveryAdmissionReason reason)
{
    switch (reason) {
        case PayloadDeliveryAdmissionReason::idle_passthrough:
            return "idle_passthrough";
        case PayloadDeliveryAdmissionReason::receiving_safe_read:
            return "receiving_safe_read";
        case PayloadDeliveryAdmissionReason::receiving_retained_response:
            return "receiving_retained_response";
        case PayloadDeliveryAdmissionReason::receiving_disconnect_cleanup:
            return "receiving_disconnect_cleanup";
        case PayloadDeliveryAdmissionReason::receiving_transfer_continue:
            return "receiving_transfer_continue";
        case PayloadDeliveryAdmissionReason::receiving_transfer_abort:
            return "receiving_transfer_abort";
        case PayloadDeliveryAdmissionReason::finalized_safe_read:
            return "finalized_safe_read";
        case PayloadDeliveryAdmissionReason::finalized_retained_response:
            return "finalized_retained_response";
        case PayloadDeliveryAdmissionReason::finalized_disconnect_cleanup:
            return "finalized_disconnect_cleanup";
        case PayloadDeliveryAdmissionReason::finalized_transfer_abort:
            return "finalized_transfer_abort";
        case PayloadDeliveryAdmissionReason::blocked_incomplete_transfer:
            return "blocked_incomplete_transfer";
        case PayloadDeliveryAdmissionReason::blocked_pending_finalized_payload:
            return "blocked_pending_finalized_payload";
        case PayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow:
            return "blocked_unrelated_sensitive_flow";
        case PayloadDeliveryAdmissionReason::missing_active_payload:
            return "missing_active_payload";
    }
    return "unknown";
}

}  // namespace signing
