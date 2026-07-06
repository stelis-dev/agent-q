#include "transport/payload_delivery_resolution.h"

#include "protocol/json_input.h"

namespace signing {

bool payload_delivery_payload_ref_wrapper(JsonDocument& request, const char** payload_ref)
{
    if (payload_ref != nullptr) {
        *payload_ref = nullptr;
    }
    JsonObjectConst payload = request["payload"].as<JsonObjectConst>();
    if (payload.isNull()) {
        return false;
    }
    const char* const payload_ref_fields[] = {"payloadRef"};
    if (!json_object_fields_supported(payload, payload_ref_fields, 1)) {
        return false;
    }
    const char* ref = nullptr;
    if (!json_value_c_string(payload["payloadRef"], &ref)) {
        return false;
    }
    if (payload_ref != nullptr) {
        *payload_ref = ref;
    }
    return true;
}

const char* payload_delivery_resolve_error_code(PayloadDeliveryResult result)
{
    switch (result) {
        case PayloadDeliveryResult::invalid_session:
            return "invalid_session";
        case PayloadDeliveryResult::payload_too_large:
            return "payload_too_large";
        case PayloadDeliveryResult::allocation_failed:
        case PayloadDeliveryResult::digest_error:
            return "internal_output_error";
        case PayloadDeliveryResult::invalid_argument:
            return "invalid_params";
        case PayloadDeliveryResult::invalid_payload_ref:
        case PayloadDeliveryResult::invalid_state:
        case PayloadDeliveryResult::not_found:
            return "payload_unavailable";
        case PayloadDeliveryResult::ok:
        case PayloadDeliveryResult::invalid_payload_digest:
        case PayloadDeliveryResult::invalid_transfer_id:
        case PayloadDeliveryResult::chunk_too_large:
        case PayloadDeliveryResult::offset_mismatch:
        case PayloadDeliveryResult::payload_overflow:
        case PayloadDeliveryResult::size_mismatch:
        case PayloadDeliveryResult::digest_mismatch:
        default:
            return "invalid_params";
    }
}

}  // namespace signing
