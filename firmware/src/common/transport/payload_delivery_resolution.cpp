#include "transport/payload_delivery_resolution.h"

#include <stdlib.h>

#include "protocol/json_input.h"
#include "transport/payload_delivery_store.h"

namespace signing {
namespace {

void wipe_bytes(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

void wipe_and_free_owned_payload(PayloadDeliveryOwnedPayload* payload)
{
    if (payload == nullptr) {
        return;
    }
    if (payload->bytes != nullptr) {
        wipe_bytes(payload->bytes, payload->size_bytes);
        free(payload->bytes);
    }
    payload->bytes = nullptr;
    payload->size_bytes = 0;
}

}  // namespace

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

bool payload_delivery_resolve_request_payload_ref(
    JsonDocument& request,
    JsonDocument& resolved_payload,
    TimeoutTick now_tick,
    const RequestEnvelope& envelope,
    const ResponseWriter& writer)
{
    const char* payload_ref = nullptr;
    if (!payload_delivery_payload_ref_wrapper(request, &payload_ref)) {
        return true;
    }

    const char* session_id = nullptr;
    if (!json_value_c_string(request["sessionId"], &session_id)) {
        writer.write_error(envelope.id, "invalid_session");
        return false;
    }

    PayloadDeliveryOwnedPayload owned_payload = {};
    const PayloadDeliveryResult take_result =
        payload_delivery_take_finalized(
            now_tick,
            session_id,
            payload_ref,
            &owned_payload);
    if (take_result != PayloadDeliveryResult::ok) {
        writer.write_error(envelope.id, payload_delivery_resolve_error_code(take_result));
        return false;
    }

    const DeserializationError parse_error =
        deserializeJson(resolved_payload, owned_payload.bytes, owned_payload.size_bytes);
    wipe_and_free_owned_payload(&owned_payload);
    if (parse_error || resolved_payload.as<JsonObjectConst>().isNull()) {
        writer.write_error(envelope.id, "invalid_params");
        return false;
    }
    request["payload"].set(resolved_payload.as<JsonObjectConst>());
    return true;
}

}  // namespace signing
