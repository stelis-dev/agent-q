#include "agent_q_usb_payload_transfer_handlers.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_base64.h"
#include "agent_q_bip39.h"
#include "agent_q_json_input.h"
#include "agent_q_payload_delivery_admission.h"
#include "agent_q_payload_delivery_store.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_u64_decimal.h"
#include "agent_q_usb_line_receiver.h"
#include "agent_q_usb_response_writer.h"

extern "C" {
int base64_to_bytes(const char* input, size_t input_size, uint8_t* output, size_t output_size);
}

namespace agent_q {
namespace {

uint8_t g_chunk_decode_buffer[kAgentQPayloadDeliveryDefaultChunkMaxBytes];

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
    return agent_q_json_object_fields_supported(
        request.as<JsonVariantConst>(),
        fields,
        field_count);
}

bool parse_session_id_or_write_error(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const char** session_id)
{
    if (agent_q_json_value_c_string(request["sessionId"], session_id)) {
        return true;
    }
    writer.write_error(id, "invalid_session");
    return false;
}

bool guard_payload_transfer_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadTransferHandlerOps& ops,
    const char** session_id)
{
    if (ops.current_tick == nullptr) {
        writer.write_error(id, "internal_output_error");
        return false;
    }
    if (ops.material_ready == nullptr || !ops.material_ready()) {
        writer.write_error(
            id,
            "invalid_state");
        return false;
    }
    if (ops.write_busy_if_pending_or_local_flow_active != nullptr &&
        ops.write_busy_if_pending_or_local_flow_active(id, writer)) {
        return false;
    }
    if (!parse_session_id_or_write_error(id, request, writer, session_id)) {
        return false;
    }
    if (ops.require_active_matching_session == nullptr ||
        !ops.require_active_matching_session(id, *session_id, writer)) {
        return false;
    }
    return true;
}

bool write_unsupported_fields_error(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const char* const* fields,
    size_t field_count)
{
    if (request_fields_supported(request, fields, field_count)) {
        return false;
    }
    writer.write_error(id, "invalid_params");
    return true;
}

const char* payload_transfer_error_code(AgentQPayloadDeliveryResult result)
{
    switch (result) {
        case AgentQPayloadDeliveryResult::invalid_session:
            return "invalid_session";
        case AgentQPayloadDeliveryResult::invalid_state:
            return "busy";
        case AgentQPayloadDeliveryResult::payload_too_large:
            return "payload_too_large";
        case AgentQPayloadDeliveryResult::allocation_failed:
        case AgentQPayloadDeliveryResult::digest_error:
            return "internal_output_error";
        case AgentQPayloadDeliveryResult::not_found:
            return "unknown_request";
        case AgentQPayloadDeliveryResult::ok:
            return "internal_output_error";
        case AgentQPayloadDeliveryResult::invalid_argument:
        case AgentQPayloadDeliveryResult::invalid_payload_digest:
        case AgentQPayloadDeliveryResult::invalid_transfer_id:
        case AgentQPayloadDeliveryResult::invalid_payload_ref:
        case AgentQPayloadDeliveryResult::chunk_too_large:
        case AgentQPayloadDeliveryResult::offset_mismatch:
        case AgentQPayloadDeliveryResult::payload_overflow:
        case AgentQPayloadDeliveryResult::size_mismatch:
        case AgentQPayloadDeliveryResult::digest_mismatch:
        default:
            return "invalid_params";
    }
}

void write_store_error(
    const char* id,
    const AgentQUsbOperationResponseWriter& writer,
    AgentQPayloadDeliveryResult result)
{
    writer.write_error(
        id,
        payload_transfer_error_code(result));
}

AgentQTimeoutTick handler_current_tick(const AgentQUsbPayloadTransferHandlerOps& ops)
{
    return ops.current_tick();
}

bool write_operation_admission_error(
    const char* id,
    const AgentQUsbOperationResponseWriter& writer,
    AgentQTimeoutTick now_tick,
    AgentQPayloadDeliveryOperationKind operation)
{
    const AgentQPayloadDeliveryAdmissionDecision admission =
        payload_delivery_admit_operation(
            AgentQPayloadDeliveryOperationAdmissionInput{
                now_tick,
                operation,
                nullptr,
            });
    if (payload_delivery_admission_allowed(admission)) {
        return false;
    }
    switch (admission.result) {
        case AgentQPayloadDeliveryAdmissionResult::busy:
            writer.write_error(id, "busy");
            return true;
        case AgentQPayloadDeliveryAdmissionResult::unknown_request:
            writer.write_error(id, "unknown_request");
            return true;
        case AgentQPayloadDeliveryAdmissionResult::ok:
            break;
    }
    writer.write_error(id, "internal_output_error");
    return true;
}

bool write_size_string(JsonObject target, const char* key, size_t value)
{
    char buffer[kAgentQU64DecimalBufferBytes] = {};
    if (!format_u64_decimal(static_cast<uint64_t>(value), buffer, sizeof(buffer))) {
        return false;
    }
    target[key] = buffer;
    return true;
}

void write_begin_result(
    const char* id,
    const AgentQPayloadDeliveryBeginOutput& output,
    const AgentQUsbOperationResponseWriter& writer)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["success"] = true;
    JsonObject result = response["result"].to<JsonObject>();
    result["transferId"] = output.transfer_id;
    if (!write_size_string(result, "receivedBytes", output.received_bytes) ||
        !write_size_string(result, "chunkMaxBytes", output.chunk_max_bytes) ||
        !usb_response_write_json(response)) {
        writer.log_write_failure("payload_transfer_begin", id);
    }
}

void write_chunk_result(
    const char* id,
    size_t received_bytes,
    const AgentQUsbOperationResponseWriter& writer)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["success"] = true;
    JsonObject result = response["result"].to<JsonObject>();
    if (!write_size_string(result, "receivedBytes", received_bytes) ||
        !usb_response_write_json(response)) {
        writer.log_write_failure("payload_transfer_chunk", id);
    }
}

void write_finish_result(
    const char* id,
    const AgentQPayloadDeliveryFinishOutput& output,
    const AgentQUsbOperationResponseWriter& writer)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["success"] = true;
    JsonObject result = response["result"].to<JsonObject>();
    result["payloadRef"] = output.descriptor.payload_ref;
    if (!usb_response_write_json(response)) {
        writer.log_write_failure("payload_transfer_finish", id);
    }
}

void write_abort_result(const char* id, const AgentQUsbOperationResponseWriter& writer)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["success"] = true;
    response["result"].to<JsonObject>();
    if (!usb_response_write_json(response)) {
        writer.log_write_failure("payload_transfer_abort", id);
    }
}

}  // namespace

void handle_usb_payload_transfer_begin_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {
        "id", "version", "type", "action", "sessionId", "totalBytes", "payloadDigest",
    };
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(id, request, writer, ops, &session_id)) {
        return;
    }
    const AgentQTimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            AgentQPayloadDeliveryOperationKind::payload_transfer_begin)) {
        return;
    }
    if (write_unsupported_fields_error(id, request, writer, fields, 7)) {
        return;
    }

    const char* size_bytes_string = nullptr;
    const char* payload_digest = nullptr;
    size_t size_bytes = 0;
    if (!agent_q_json_value_c_string(request["totalBytes"], &size_bytes_string) ||
        !parse_size_string(size_bytes_string, &size_bytes) ||
        !agent_q_json_value_c_string(request["payloadDigest"], &payload_digest)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    AgentQPayloadDeliveryBeginOutput output = {};
    const AgentQPayloadDeliveryResult result = payload_delivery_begin(
        now_tick,
        AgentQPayloadDeliveryBeginInput{
            session_id,
            size_bytes,
            payload_digest,
            AgentQPayloadDeliveryLimits{
                kAgentQPayloadDeliveryDefaultChunkMaxBytes,
                kAgentQPayloadDeliveryDefaultMaxBytes,
            },
            ops.timeout_window_for_size != nullptr
                ? ops.timeout_window_for_size(size_bytes)
                : kAgentQTimeoutWindowNone,
        },
        &output);
    if (result != AgentQPayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_begin_result(id, output, writer);
}

void handle_usb_payload_transfer_chunk_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {
        "id", "version", "type", "action", "sessionId", "transferId", "offsetBytes", "chunk",
    };
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(id, request, writer, ops, &session_id)) {
        return;
    }
    const AgentQTimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            AgentQPayloadDeliveryOperationKind::payload_transfer_chunk)) {
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
    if (!agent_q_json_value_c_string(request["transferId"], &transfer_id) ||
        !agent_q_json_value_c_string(request["offsetBytes"], &offset_bytes_string) ||
        !parse_size_string(offset_bytes_string, &offset_bytes) ||
        !agent_q_json_value_c_string(request["chunk"], &chunk_base64) ||
        !validate_canonical_base64_syntax(
            chunk_base64,
            kAgentQUsbRequestLineMaxBytes,
            &decoded_size)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    if (decoded_size > kAgentQPayloadDeliveryDefaultChunkMaxBytes) {
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
    const AgentQPayloadDeliveryResult result = payload_delivery_append_chunk(
        now_tick,
        AgentQPayloadDeliveryChunkInput{
            session_id,
            transfer_id,
            offset_bytes,
            g_chunk_decode_buffer,
            decoded_size,
        },
        &received_bytes);
    wipe_sensitive_buffer(g_chunk_decode_buffer, sizeof(g_chunk_decode_buffer));
    if (result != AgentQPayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_chunk_result(id, received_bytes, writer);
}

void handle_usb_payload_transfer_finish_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {"id", "version", "type", "action", "sessionId", "transferId"};
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(id, request, writer, ops, &session_id)) {
        return;
    }
    const AgentQTimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            AgentQPayloadDeliveryOperationKind::payload_transfer_finish)) {
        return;
    }
    if (write_unsupported_fields_error(id, request, writer, fields, 6)) {
        return;
    }

    const char* transfer_id = nullptr;
    if (!agent_q_json_value_c_string(request["transferId"], &transfer_id)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    AgentQPayloadDeliveryFinishOutput output = {};
    const AgentQPayloadDeliveryResult result = payload_delivery_finish(
        now_tick,
        AgentQPayloadDeliveryFinishInput{session_id, transfer_id},
        &output);
    if (result != AgentQPayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_finish_result(id, output, writer);
}

void handle_usb_payload_transfer_abort_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadTransferHandlerOps& ops)
{
    const char* const fields[] = {"id", "version", "type", "action", "sessionId", "transferId"};
    const char* session_id = nullptr;
    if (!guard_payload_transfer_request(id, request, writer, ops, &session_id)) {
        return;
    }
    const AgentQTimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            AgentQPayloadDeliveryOperationKind::payload_transfer_abort)) {
        return;
    }
    if (write_unsupported_fields_error(id, request, writer, fields, 6)) {
        return;
    }

    const char* transfer_id = nullptr;
    if (!agent_q_json_value_c_string(request["transferId"], &transfer_id)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    const AgentQPayloadDeliveryResult result = payload_delivery_abort(
        now_tick,
        AgentQPayloadDeliveryAbortInput{
            session_id,
            transfer_id,
            nullptr,
        });
    if (result != AgentQPayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_abort_result(id, writer);
}

}  // namespace agent_q
