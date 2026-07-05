#include "payload_delivery_admission.h"

namespace signing {
namespace {

PayloadDeliveryAdmissionState admission_state_from_store(PayloadDeliveryState state)
{
    switch (state) {
        case PayloadDeliveryState::idle:
            return PayloadDeliveryAdmissionState::idle;
        case PayloadDeliveryState::receiving:
            return PayloadDeliveryAdmissionState::receiving;
        case PayloadDeliveryState::finalized:
            return PayloadDeliveryAdmissionState::finalized;
    }
    return PayloadDeliveryAdmissionState::idle;
}

}  // namespace

PayloadDeliveryAdmissionDecision payload_delivery_admit_operation(
    const PayloadDeliveryOperationAdmissionInput& input)
{
    const PayloadDeliverySnapshot snapshot = payload_delivery_advance_and_snapshot(input.now_tick);
    return payload_delivery_admit_operation_for_state(
        admission_state_from_store(snapshot.state),
        input.operation);
}

}  // namespace signing
