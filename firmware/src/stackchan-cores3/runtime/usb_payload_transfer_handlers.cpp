#include "usb_payload_transfer_handlers.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "bip39.h"
#include "protocol/json_input.h"
#include "payload_delivery_admission.h"
#include "payload_delivery_store.h"
#include "protocol/protocol_constants.h"
#include "numeric/u64_decimal.h"
#include "usb_active_session_request_guard.h"
#include "usb_line_receiver.h"
#include "usb_response_writer.h"

extern "C" {
int base64_to_bytes(const char* input, size_t input_size, uint8_t* output, size_t output_size);
}

namespace signing {
namespace {

uint8_t g_chunk_decode_buffer[kPayloadDeliveryDefaultChunkMaxBytes];
constexpr const char* kPayloadTransferMethod = "payload_transfer";

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

bool guard_payload_transfer_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPayloadTransferHandlerOps& ops,
    UsbOperationType operation,
    const char** session_id)
{
    if (ops.current_tick == nullptr) {
        writer.write_error(id, "internal_output_error");
        return false;
    }
    const UsbActiveSessionRequestGuardOps guard_ops = {
        ops.material_ready,
        ops.write_busy_if_pending_or_local_flow_active,
        nullptr,
        ops.require_active_matching_session,
    };
    return guard_usb_active_session_request(
        id,
        request,
        writer,
        operation,
        guard_ops,
        UsbSessionIdMode::required,
        nullptr,
        0,
        session_id);
}

bool write_unsupported_fields_error(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const char* const* fields,
    size_t field_count)
{
    if (request_fields_supported(request, fields, field_count)) {
        return false;
    }
    writer.write_error(id, "invalid_params");
    return true;
}

const char* payload_transfer_error_code(PayloadDeliveryResult result)
{
    switch (result) {
        case PayloadDeliveryResult::invalid_session:
            return "invalid_session";
        case PayloadDeliveryResult::invalid_state:
            return "busy";
        case PayloadDeliveryResult::payload_too_large:
            return "payload_too_large";
        case PayloadDeliveryResult::allocation_failed:
        case PayloadDeliveryResult::digest_error:
            return "internal_output_error";
        case PayloadDeliveryResult::not_found:
            return "unknown_request";
        case PayloadDeliveryResult::ok:
            return "internal_output_error";
        case PayloadDeliveryResult::invalid_argument:
        case PayloadDeliveryResult::invalid_payload_digest:
        case PayloadDeliveryResult::invalid_transfer_id:
        case PayloadDeliveryResult::invalid_payload_ref:
        case PayloadDeliveryResult::chunk_too_large:
        case PayloadDeliveryResult::offset_mismatch:
        case PayloadDeliveryResult::payload_overflow:
        case PayloadDeliveryResult::size_mismatch:
        case PayloadDeliveryResult::digest_mismatch:
        default:
            return "invalid_params";
    }
}

void write_store_error(
    const char* id,
    const UsbOperationResponseWriter& writer,
    PayloadDeliveryResult result)
{
    writer.write_error(
        id,
        payload_transfer_error_code(result));
}

TimeoutTick handler_current_tick(const UsbPayloadTransferHandlerOps& ops)
{
    return ops.current_tick();
}

bool write_operation_admission_error(
    const char* id,
    const UsbOperationResponseWriter& writer,
    TimeoutTick now_tick,
    PayloadDeliveryOperationKind operation)
{
    const PayloadDeliveryAdmissionDecision admission =
        payload_delivery_admit_operation(
            PayloadDeliveryOperationAdmissionInput{
                now_tick,
                operation,
                nullptr,
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
    const UsbOperationResponseWriter& writer)
{
    if (!usb_response_write_success_result(id, kPayloadTransferMethod, result)) {
        writer.log_write_failure(log_label, id);
    }
}

void write_begin_success(
    const char* id,
    const PayloadDeliveryBeginOutput& output,
    const UsbOperationResponseWriter& writer)
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
    const UsbOperationResponseWriter& writer)
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
    const UsbOperationResponseWriter& writer)
{
    JsonDocument result_doc;
    JsonObject result = result_doc.to<JsonObject>();
    result["payloadRef"] = output.descriptor.payload_ref;
    write_payload_transfer_success(id, result_doc.as<JsonObjectConst>(), "payload_transfer_finish", writer);
}

void write_abort_success(const char* id, const UsbOperationResponseWriter& writer)
{
    JsonDocument result_doc;
    result_doc.to<JsonObject>();
    write_payload_transfer_success(id, result_doc.as<JsonObjectConst>(), "payload_transfer_abort", writer);
}

}  // namespace

void handle_usb_payload_transfer_begin_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {
        "id", "version", "type", "action", "sessionId", "totalBytes", "payloadDigest",
    };
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(
            id,
            request,
            writer,
            ops,
            UsbOperationType::payload_transfer_begin,
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
    if (write_unsupported_fields_error(id, request, writer, fields, 7)) {
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

void handle_usb_payload_transfer_chunk_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {
        "id", "version", "type", "action", "sessionId", "transferId", "offsetBytes", "chunk",
    };
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(
            id,
            request,
            writer,
            ops,
            UsbOperationType::payload_transfer_chunk,
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
    if (write_unsupported_fields_error(id, request, writer, fields, 8)) {
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
        wipe_sensitive_buffer(g_chunk_decode_buffer, sizeof(g_chunk_decode_buffer));
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
    wipe_sensitive_buffer(g_chunk_decode_buffer, sizeof(g_chunk_decode_buffer));
    if (result != PayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_chunk_success(id, received_bytes, writer);
}

void handle_usb_payload_transfer_finish_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {"id", "version", "type", "action", "sessionId", "transferId"};
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(
            id,
            request,
            writer,
            ops,
            UsbOperationType::payload_transfer_finish,
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
    if (write_unsupported_fields_error(id, request, writer, fields, 6)) {
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
        PayloadDeliveryFinishInput{session_id, transfer_id},
        &output);
    if (result != PayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_finish_success(id, output, writer);
}

void handle_usb_payload_transfer_abort_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {"id", "version", "type", "action", "sessionId", "transferId"};
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(
            id,
            request,
            writer,
            ops,
            UsbOperationType::payload_transfer_abort,
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
    if (write_unsupported_fields_error(id, request, writer, fields, 6)) {
        return;
    }

    const char* transfer_id = nullptr;
    if (!json_value_c_string(request["transferId"], &transfer_id)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    const PayloadDeliveryResult result = payload_delivery_abort(
        now_tick,
        PayloadDeliveryAbortInput{
            session_id,
            transfer_id,
            nullptr,
        });
    if (result != PayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_abort_success(id, writer);
}

}  // namespace signing
