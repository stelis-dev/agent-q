#include "transport/payload_transfer_handlers.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "protocol/base64.h"
#include "protocol/approval_history.h"
#include "protocol/json_input.h"
#include "transport/payload_delivery_admission.h"
#include "transport/payload_delivery_store.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_line.h"
#include "numeric/u64_decimal.h"
#include "protocol/active_session_request_guard.h"

extern "C" {
int base64_to_bytes(const char* input, size_t input_size, uint8_t* output, size_t output_size);
}

namespace signing {
namespace {

uint8_t g_chunk_decode_buffer[kPayloadDeliveryDefaultChunkMaxBytes];

void wipe_payload_transfer_buffer(void* buffer, size_t size)
{
    if (buffer == nullptr) {
        return;
    }
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(buffer);
    while (size-- > 0) {
        *cursor++ = 0;
    }
}

bool parse_size_string(const char* value, size_t* output)
{
    if (output == nullptr) {
        return false;
    }
    *output = 0;
    uint64_t parsed = 0;
    if (!parse_canonical_u64_decimal_string(value, &parsed)) {
        return false;
    }
    if (parsed > SIZE_MAX) {
        return false;
    }
    *output = static_cast<size_t>(parsed);
    return true;
}

bool request_fields_supported(JsonDocument& request, const char* const* fields, size_t field_count)
{
    return json_object_fields_supported(
        request.as<JsonVariantConst>(),
        fields,
        field_count);
}

bool request_has_key(JsonDocument& request, const char* key)
{
    if (key == nullptr) {
        return false;
    }
    for (JsonPairConst pair : request.as<JsonObjectConst>()) {
        if (json_string_equals(pair.key(), key)) {
            return true;
        }
    }
    return false;
}

bool guard_payload_transfer_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PayloadTransferHandlerOps& ops,
    OperationType operation,
    const char** session_id)
{
    if (ops.current_tick == nullptr) {
        writer.write_error(id, "internal_output_error");
        return false;
    }
    const ActiveSessionRequestGuardOps guard_ops = {
        ops.material_ready,
        ops.write_busy_if_pending_or_local_flow_active,
        nullptr,
        ops.require_active_matching_session,
    };
    return guard_active_session_request(
        id,
        request,
        writer,
        operation,
        guard_ops,
        SessionIdMode::required,
        nullptr,
        0,
        session_id);
}

bool write_unsupported_fields_error(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const char* const* fields,
    size_t field_count)
{
    if (request_fields_supported(request, fields, field_count)) {
        return false;
    }
    writer.write_error(id, "invalid_request");
    return true;
}

void write_store_error(
    const char* id,
    const ResponseWriter& writer,
    PayloadDeliveryResult result)
{
    writer.write_error(
        id,
        payload_delivery_transfer_error_code(result));
}

TimeoutTick handler_current_tick(const PayloadTransferHandlerOps& ops)
{
    return ops.current_tick();
}

bool write_operation_admission_error(
    const char* id,
    const ResponseWriter& writer,
    TimeoutTick now_tick,
    PayloadDeliveryOperationKind operation)
{
    const PayloadDeliveryAdmissionDecision admission =
        payload_delivery_admit_operation(
            PayloadDeliveryOperationAdmissionInput{
                now_tick,
                operation,
            });
    if (payload_delivery_admission_allowed(admission)) {
        return false;
    }
    switch (admission.result) {
        case PayloadDeliveryAdmissionResult::busy:
            writer.write_error(id, "busy");
            return true;
        case PayloadDeliveryAdmissionResult::unknown_request:
            writer.write_error(id, "unknown_request");
            return true;
        case PayloadDeliveryAdmissionResult::ok:
            break;
    }
    writer.write_error(id, "internal_output_error");
    return true;
}

bool write_size_string(JsonObject target, const char* key, size_t value)
{
    char buffer[kU64DecimalBufferBytes] = {};
    if (!format_u64_decimal(static_cast<uint64_t>(value), buffer, sizeof(buffer))) {
        return false;
    }
    target[key] = buffer;
    return true;
}

void write_payload_transfer_success(
    const char* id,
    JsonObjectConst result,
    const char* log_label,
    const ResponseWriter& writer)
{
    if (!writer.write_transport_success_result(id, result)) {
        writer.log_write_failure(log_label, id);
    }
}

void write_begin_success(
    const char* id,
    const PayloadDeliveryBeginOutput& output,
    const ResponseWriter& writer)
{
    JsonDocument result_doc;
    JsonObject result = result_doc.to<JsonObject>();
    result["transferId"] = output.transfer_id;
    if (!write_size_string(result, "receivedBytes", output.received_bytes) ||
        !write_size_string(result, "chunkMaxBytes", output.chunk_max_bytes)) {
        writer.log_write_failure("payload_transfer_begin", id);
        return;
    }
    write_payload_transfer_success(id, result_doc.as<JsonObjectConst>(), "payload_transfer_begin", writer);
}

void write_chunk_success(
    const char* id,
    size_t received_bytes,
    const ResponseWriter& writer)
{
    JsonDocument result_doc;
    JsonObject result = result_doc.to<JsonObject>();
    if (!write_size_string(result, "receivedBytes", received_bytes)) {
        writer.log_write_failure("payload_transfer_chunk", id);
        return;
    }
    write_payload_transfer_success(id, result_doc.as<JsonObjectConst>(), "payload_transfer_chunk", writer);
}

void write_finish_success(
    const char* id,
    const PayloadDeliveryFinishOutput& output,
    const ResponseWriter& writer)
{
    JsonDocument result_doc;
    JsonObject result = result_doc.to<JsonObject>();
    result["payloadRef"] = output.descriptor.payload_ref;
    write_payload_transfer_success(id, result_doc.as<JsonObjectConst>(), "payload_transfer_finish", writer);
}

void write_abort_success(const char* id, const ResponseWriter& writer)
{
    JsonDocument result_doc;
    result_doc.to<JsonObject>();
    write_payload_transfer_success(id, result_doc.as<JsonObjectConst>(), "payload_transfer_abort", writer);
}

}  // namespace

void handle_protocol_payload_transfer_begin_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {
        "id", "version", "type", "action", "sessionId", "totalBytes", "payloadDigest",
    };
    if (write_unsupported_fields_error(id, request, writer, fields, 7)) {
        return;
    }
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(
            id,
            request,
            writer,
            ops,
            OperationType::payload_transfer_begin,
            &session_id)) {
        return;
    }
    const TimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            PayloadDeliveryOperationKind::payload_transfer_begin)) {
        return;
    }

    const char* size_bytes_string = nullptr;
    const char* payload_digest = nullptr;
    size_t size_bytes = 0;
    if (!json_value_c_string(request["totalBytes"], &size_bytes_string) ||
        !parse_size_string(size_bytes_string, &size_bytes) ||
        !json_value_c_string(request["payloadDigest"], &payload_digest)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    PayloadDeliveryBeginOutput output = {};
    const PayloadDeliveryResult result = payload_delivery_begin(
        now_tick,
        PayloadDeliveryBeginInput{
            session_id,
            size_bytes,
            payload_digest,
            PayloadDeliveryLimits{
                kPayloadDeliveryDefaultChunkMaxBytes,
                kPayloadDeliveryDefaultMaxBytes,
            },
            ops.timeout_window_for_size != nullptr
                ? ops.timeout_window_for_size(size_bytes)
                : kTimeoutWindowNone,
        },
        &output);
    if (result != PayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_begin_success(id, output, writer);
}

void handle_protocol_payload_transfer_chunk_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {
        "id", "version", "type", "action", "sessionId", "transferId", "offsetBytes", "chunk",
    };
    if (write_unsupported_fields_error(id, request, writer, fields, 8)) {
        return;
    }
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(
            id,
            request,
            writer,
            ops,
            OperationType::payload_transfer_chunk,
            &session_id)) {
        return;
    }
    const TimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            PayloadDeliveryOperationKind::payload_transfer_chunk)) {
        return;
    }

    const char* transfer_id = nullptr;
    const char* offset_bytes_string = nullptr;
    const char* chunk_base64 = nullptr;
    size_t offset_bytes = 0;
    size_t decoded_size = 0;
    if (!json_value_c_string(request["transferId"], &transfer_id) ||
        !json_value_c_string(request["offsetBytes"], &offset_bytes_string) ||
        !parse_size_string(offset_bytes_string, &offset_bytes) ||
        !json_value_c_string(request["chunk"], &chunk_base64) ||
        !validate_canonical_base64_syntax(
            chunk_base64,
            kRequestLineMaxBytes,
            &decoded_size)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    if (decoded_size > kPayloadDeliveryDefaultChunkMaxBytes) {
        write_store_error(
            id,
            writer,
            payload_delivery_reject_chunk_too_large(now_tick, session_id, transfer_id));
        return;
    }
    if (base64_to_bytes(
            chunk_base64,
            strlen(chunk_base64),
            g_chunk_decode_buffer,
            sizeof(g_chunk_decode_buffer)) != 0) {
        wipe_payload_transfer_buffer(g_chunk_decode_buffer, sizeof(g_chunk_decode_buffer));
        writer.write_error(id, "invalid_params");
        return;
    }

    size_t received_bytes = 0;
    const PayloadDeliveryResult result = payload_delivery_append_chunk(
        now_tick,
        PayloadDeliveryChunkInput{
            session_id,
            transfer_id,
            offset_bytes,
            g_chunk_decode_buffer,
            decoded_size,
        },
        &received_bytes);
    wipe_payload_transfer_buffer(g_chunk_decode_buffer, sizeof(g_chunk_decode_buffer));
    if (result != PayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_chunk_success(id, received_bytes, writer);
}

void handle_protocol_payload_transfer_finish_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {"id", "version", "type", "action", "sessionId", "transferId"};
    if (write_unsupported_fields_error(id, request, writer, fields, 6)) {
        return;
    }
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(
            id,
            request,
            writer,
            ops,
            OperationType::payload_transfer_finish,
            &session_id)) {
        return;
    }
    const TimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            PayloadDeliveryOperationKind::payload_transfer_finish)) {
        return;
    }

    const char* transfer_id = nullptr;
    if (!json_value_c_string(request["transferId"], &transfer_id)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    PayloadDeliveryFinishOutput output = {};
    const PayloadDeliveryResult result = payload_delivery_finish(
        now_tick,
        PayloadDeliveryFinishInput{session_id, transfer_id, approval_history_digest_payload},
        &output);
    if (result != PayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_finish_success(id, output, writer);
}

void handle_protocol_payload_transfer_abort_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {"id", "version", "type", "action", "sessionId", "transferId", "payloadRef"};
    if (write_unsupported_fields_error(id, request, writer, fields, 7)) {
        return;
    }
    const bool has_transfer_id = request_has_key(request, "transferId");
    const bool has_payload_ref = request_has_key(request, "payloadRef");
    if (has_transfer_id && has_payload_ref) {
        writer.write_error(id, "invalid_request");
        return;
    }
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(
            id,
            request,
            writer,
            ops,
            OperationType::payload_transfer_abort,
            &session_id)) {
        return;
    }
    const TimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            PayloadDeliveryOperationKind::payload_transfer_abort)) {
        return;
    }

    const char* transfer_id = nullptr;
    const char* payload_ref = nullptr;
    if (has_transfer_id) {
        if (!json_value_c_string(request["transferId"], &transfer_id)) {
            writer.write_error(id, "invalid_params");
            return;
        }
    } else if (has_payload_ref) {
        if (!json_value_c_string(request["payloadRef"], &payload_ref)) {
            writer.write_error(id, "invalid_params");
            return;
        }
    } else {
        writer.write_error(id, "invalid_params");
        return;
    }

    const PayloadDeliveryResult result = payload_delivery_abort(
        now_tick,
        PayloadDeliveryAbortInput{
            session_id,
            transfer_id,
            payload_ref,
        });
    if (result != PayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_abort_success(id, writer);
}

}  // namespace signing
