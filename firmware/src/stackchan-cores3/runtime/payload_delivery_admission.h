#pragma once

#include "transport/payload_delivery_store.h"
#include "transport/payload_delivery_admission.h"

namespace signing {

struct PayloadDeliveryOperationAdmissionInput {
    TimeoutTick now_tick;
    PayloadDeliveryOperationKind operation;
    const char* session_id;
};

using PayloadDeliveryOperationAdmissionFn =
    PayloadDeliveryAdmissionDecision (*)(
        const PayloadDeliveryOperationAdmissionInput& input);

PayloadDeliveryAdmissionDecision payload_delivery_admit_operation(
    const PayloadDeliveryOperationAdmissionInput& input);

}  // namespace signing
