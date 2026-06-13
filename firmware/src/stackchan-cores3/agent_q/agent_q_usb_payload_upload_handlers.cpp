#include "agent_q_usb_payload_upload_handlers.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_base64.h"
#include "agent_q_bip39.h"
#include "agent_q_json_input.h"
#include "agent_q_payload_delivery_admission.h"
#include "agent_q_payload_delivery_store.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_sign_route.h"
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
    writer.write_error(id, "invalid_session", "Invalid sessionId.");
    return false;
}

bool guard_payload_upload_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadUploadHandlerOps& ops,
    const char** session_id)
{
    if (ops.current_tick == nullptr) {
        writer.write_error(id, "protocol_error", "Payload upload handler is unavailable.");
        return false;
    }
    if (ops.material_ready == nullptr || !ops.material_ready()) {
        writer.write_error(
            id,
            "invalid_state",
            "Payload upload is available only after provisioning is complete.");
        return false;
    }
    if (ops.write_busy_if_pending_or_local_flow_active != nullptr &&
        ops.write_busy_if_pending_or_local_flow_active(id)) {
        return false;
    }
    if (!parse_session_id_or_write_error(id, request, writer, session_id)) {
        return false;
    }
    if (ops.require_active_matching_session == nullptr ||
        !ops.require_active_matching_session(id, *session_id)) {
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
    writer.write_error(id, "invalid_params", "Payload upload request contains unsupported fields.");
    return true;
}

const char* payload_upload_error_code(AgentQPayloadDeliveryResult result)
{
    switch (result) {
        case AgentQPayloadDeliveryResult::invalid_session:
            return "invalid_session";
        case AgentQPayloadDeliveryResult::invalid_state:
            return "busy";
        case AgentQPayloadDeliveryResult::unsupported_method:
            return "unsupported_method";
        case AgentQPayloadDeliveryResult::unsupported_payload_size:
            return "unsupported_payload_size";
        case AgentQPayloadDeliveryResult::allocation_failed:
        case AgentQPayloadDeliveryResult::digest_error:
            return "protocol_error";
        case AgentQPayloadDeliveryResult::not_found:
            return "unknown_request";
        case AgentQPayloadDeliveryResult::ok:
            return "protocol_error";
        case AgentQPayloadDeliveryResult::invalid_argument:
        case AgentQPayloadDeliveryResult::unsupported_payload_kind:
        case AgentQPayloadDeliveryResult::invalid_payload_digest:
        case AgentQPayloadDeliveryResult::invalid_upload_id:
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

const char* payload_upload_error_message(AgentQPayloadDeliveryResult result)
{
    switch (result) {
        case AgentQPayloadDeliveryResult::invalid_session:
            return "Session is unknown or already ended.";
        case AgentQPayloadDeliveryResult::invalid_state:
            return "Payload upload cannot start while another payload is pending.";
        case AgentQPayloadDeliveryResult::unsupported_method:
            return "Payload upload route is not supported.";
        case AgentQPayloadDeliveryResult::unsupported_payload_size:
            return "Payload size is not supported.";
        case AgentQPayloadDeliveryResult::invalid_payload_digest:
            return "Payload digest is invalid.";
        case AgentQPayloadDeliveryResult::invalid_upload_id:
            return "Upload id is invalid.";
        case AgentQPayloadDeliveryResult::invalid_payload_ref:
            return "Payload reference is invalid.";
        case AgentQPayloadDeliveryResult::chunk_too_large:
            return "Payload upload chunk is too large.";
        case AgentQPayloadDeliveryResult::offset_mismatch:
            return "Payload upload chunk offset is invalid.";
        case AgentQPayloadDeliveryResult::payload_overflow:
            return "Payload upload exceeds the declared size.";
        case AgentQPayloadDeliveryResult::size_mismatch:
            return "Payload upload is incomplete.";
        case AgentQPayloadDeliveryResult::digest_mismatch:
            return "Payload digest does not match uploaded bytes.";
        case AgentQPayloadDeliveryResult::allocation_failed:
            return "Payload buffer allocation failed.";
        case AgentQPayloadDeliveryResult::digest_error:
            return "Could not digest uploaded payload.";
        case AgentQPayloadDeliveryResult::not_found:
            return "Payload upload request is unknown.";
        case AgentQPayloadDeliveryResult::invalid_argument:
        case AgentQPayloadDeliveryResult::unsupported_payload_kind:
        case AgentQPayloadDeliveryResult::ok:
        default:
            return "Payload upload params are invalid.";
    }
}

void write_store_error(
    const char* id,
    const AgentQUsbOperationResponseWriter& writer,
    AgentQPayloadDeliveryResult result)
{
    writer.write_error(
        id,
        payload_upload_error_code(result),
        payload_upload_error_message(result));
}

AgentQTimeoutTick handler_current_tick(const AgentQUsbPayloadUploadHandlerOps& ops)
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
                false,
                nullptr,
            });
    if (payload_delivery_admission_allowed(admission)) {
        return false;
    }
    switch (admission.result) {
        case AgentQPayloadDeliveryAdmissionResult::busy:
            writer.write_error(id, "busy", "Device has a pending signable payload.");
            return true;
        case AgentQPayloadDeliveryAdmissionResult::invalid_session:
            writer.write_error(id, "invalid_session", "Session is unknown or already ended.");
            return true;
        case AgentQPayloadDeliveryAdmissionResult::invalid_payload_ref:
            writer.write_error(id, "invalid_params", "Payload reference is invalid.");
            return true;
        case AgentQPayloadDeliveryAdmissionResult::unknown_request:
            writer.write_error(id, "unknown_request", "Payload upload request is unknown.");
            return true;
        case AgentQPayloadDeliveryAdmissionResult::ok:
            break;
    }
    writer.write_error(id, "protocol_error", "Payload delivery admission failed.");
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
    response["type"] = "payload_upload_begin_result";
    response["uploadId"] = output.upload_id;
    if (!write_size_string(response.as<JsonObject>(), "receivedBytes", output.received_bytes) ||
        !write_size_string(response.as<JsonObject>(), "chunkMaxBytes", output.chunk_max_bytes) ||
        !usb_response_write_json(response)) {
        writer.log_write_failure("payload_upload_begin_result", id);
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
    response["type"] = "payload_upload_chunk_result";
    if (!write_size_string(response.as<JsonObject>(), "receivedBytes", received_bytes) ||
        !usb_response_write_json(response)) {
        writer.log_write_failure("payload_upload_chunk_result", id);
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
    response["type"] = "payload_upload_finish_result";
    response["payloadRef"] = output.descriptor.payload_ref;
    response["chain"] = output.descriptor.chain;
    response["method"] = output.descriptor.method;
    response["payloadKind"] = output.descriptor.payload_kind;
    if (!write_size_string(response.as<JsonObject>(), "sizeBytes", output.descriptor.size_bytes)) {
        writer.log_write_failure("payload_upload_finish_result", id);
        return;
    }
    response["payloadDigest"] = output.descriptor.payload_digest;
    if (!usb_response_write_json(response)) {
        writer.log_write_failure("payload_upload_finish_result", id);
    }
}

void write_abort_result(const char* id, const AgentQUsbOperationResponseWriter& writer)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "payload_upload_abort_result";
    response["status"] = "aborted";
    if (!usb_response_write_json(response)) {
        writer.log_write_failure("payload_upload_abort_result", id);
    }
}

}  // namespace

void handle_usb_payload_upload_begin_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadUploadHandlerOps& ops)
{
    const char* const fields[] = {
        "id", "version", "type", "sessionId", "chain", "method",
        "payloadKind", "sizeBytes", "payloadDigest",
    };
    const char* session_id = nullptr;
    if (!guard_payload_upload_request(id, request, writer, ops, &session_id)) {
        return;
    }
    const AgentQTimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            AgentQPayloadDeliveryOperationKind::payload_upload_begin)) {
        return;
    }
    if (write_unsupported_fields_error(id, request, writer, fields, 9)) {
        return;
    }

    const char* chain = nullptr;
    const char* method = nullptr;
    if (!agent_q_json_value_c_string(request["chain"], &chain) ||
        !agent_q_json_value_c_string(request["method"], &method)) {
        writer.write_error(id, "invalid_params", "Payload upload route is invalid.");
        return;
    }

    const AgentQSignRouteClassification classification =
        classify_sign_route(AgentQSignOperation::sign_transaction, chain, method);
    if (classification.result == AgentQSignRouteResult::invalid_params) {
        writer.write_error(id, "invalid_params", "Payload upload route is invalid.");
        return;
    }
    if (classification.result == AgentQSignRouteResult::unsupported_chain) {
        writer.write_error(id, "unsupported_chain", "Payload upload chain is not supported.");
        return;
    }
    if (classification.result == AgentQSignRouteResult::unsupported_method) {
        writer.write_error(id, "unsupported_method", "Payload upload method is not supported.");
        return;
    }

    const char* payload_kind = nullptr;
    const char* size_bytes_string = nullptr;
    const char* payload_digest = nullptr;
    size_t size_bytes = 0;
    if (!agent_q_json_value_c_string(request["payloadKind"], &payload_kind) ||
        !agent_q_json_value_c_string(request["sizeBytes"], &size_bytes_string) ||
        !parse_size_string(size_bytes_string, &size_bytes) ||
        !agent_q_json_value_c_string(request["payloadDigest"], &payload_digest)) {
        writer.write_error(id, "invalid_params", "Payload upload begin params are invalid.");
        return;
    }

    AgentQPayloadDeliveryBeginOutput output = {};
    const AgentQPayloadDeliveryResult result = payload_delivery_begin(
        now_tick,
        AgentQPayloadDeliveryBeginInput{
            session_id,
            classification.route,
            payload_kind,
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

void handle_usb_payload_upload_chunk_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadUploadHandlerOps& ops)
{
    const char* const fields[] = {
        "id", "version", "type", "sessionId", "uploadId", "offsetBytes", "chunk",
    };
    const char* session_id = nullptr;
    if (!guard_payload_upload_request(id, request, writer, ops, &session_id)) {
        return;
    }
    const AgentQTimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            AgentQPayloadDeliveryOperationKind::payload_upload_chunk)) {
        return;
    }
    if (write_unsupported_fields_error(id, request, writer, fields, 7)) {
        return;
    }

    const char* upload_id = nullptr;
    const char* offset_bytes_string = nullptr;
    const char* chunk_base64 = nullptr;
    size_t offset_bytes = 0;
    size_t decoded_size = 0;
    if (!agent_q_json_value_c_string(request["uploadId"], &upload_id) ||
        !agent_q_json_value_c_string(request["offsetBytes"], &offset_bytes_string) ||
        !parse_size_string(offset_bytes_string, &offset_bytes) ||
        !agent_q_json_value_c_string(request["chunk"], &chunk_base64) ||
        !validate_canonical_base64_syntax(
            chunk_base64,
            kAgentQUsbRequestLineMaxBytes,
            &decoded_size)) {
        writer.write_error(id, "invalid_params", "Payload upload chunk params are invalid.");
        return;
    }
    if (decoded_size > kAgentQPayloadDeliveryDefaultChunkMaxBytes) {
        write_store_error(
            id,
            writer,
            payload_delivery_reject_chunk_too_large(now_tick, session_id, upload_id));
        return;
    }
    if (base64_to_bytes(
            chunk_base64,
            strlen(chunk_base64),
            g_chunk_decode_buffer,
            sizeof(g_chunk_decode_buffer)) != 0) {
        wipe_sensitive_buffer(g_chunk_decode_buffer, sizeof(g_chunk_decode_buffer));
        writer.write_error(id, "invalid_params", "Payload upload chunk params are invalid.");
        return;
    }

    size_t received_bytes = 0;
    const AgentQPayloadDeliveryResult result = payload_delivery_append_chunk(
        now_tick,
        AgentQPayloadDeliveryChunkInput{
            session_id,
            upload_id,
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

void handle_usb_payload_upload_finish_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadUploadHandlerOps& ops)
{
    const char* const fields[] = {"id", "version", "type", "sessionId", "uploadId"};
    const char* session_id = nullptr;
    if (!guard_payload_upload_request(id, request, writer, ops, &session_id)) {
        return;
    }
    const AgentQTimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            AgentQPayloadDeliveryOperationKind::payload_upload_finish)) {
        return;
    }
    if (write_unsupported_fields_error(id, request, writer, fields, 5)) {
        return;
    }

    const char* upload_id = nullptr;
    if (!agent_q_json_value_c_string(request["uploadId"], &upload_id)) {
        writer.write_error(id, "invalid_params", "Payload upload finish params are invalid.");
        return;
    }

    AgentQPayloadDeliveryFinishOutput output = {};
    const AgentQPayloadDeliveryResult result = payload_delivery_finish(
        now_tick,
        AgentQPayloadDeliveryFinishInput{session_id, upload_id},
        &output);
    if (result != AgentQPayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_finish_result(id, output, writer);
}

void handle_usb_payload_upload_abort_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadUploadHandlerOps& ops)
{
    const char* const fields[] = {"id", "version", "type", "sessionId", "uploadId", "payloadRef"};
    const char* session_id = nullptr;
    if (!guard_payload_upload_request(id, request, writer, ops, &session_id)) {
        return;
    }
    const AgentQTimeoutTick now_tick = handler_current_tick(ops);
    if (write_operation_admission_error(
            id,
            writer,
            now_tick,
            AgentQPayloadDeliveryOperationKind::payload_upload_abort)) {
        return;
    }
    if (write_unsupported_fields_error(id, request, writer, fields, 6)) {
        return;
    }

    const char* upload_id = nullptr;
    const char* payload_ref = nullptr;
    const bool has_upload_id = agent_q_json_optional_c_string(request["uploadId"], "", &upload_id) &&
                               upload_id != nullptr &&
                               upload_id[0] != '\0';
    const bool has_payload_ref = agent_q_json_optional_c_string(request["payloadRef"], "", &payload_ref) &&
                                 payload_ref != nullptr &&
                                 payload_ref[0] != '\0';
    if (has_upload_id == has_payload_ref) {
        writer.write_error(id, "invalid_params", "Payload upload abort params are invalid.");
        return;
    }

    const AgentQPayloadDeliveryResult result = payload_delivery_abort(
        now_tick,
        AgentQPayloadDeliveryAbortInput{
            session_id,
            has_upload_id ? upload_id : nullptr,
            has_payload_ref ? payload_ref : nullptr,
        });
    if (result != AgentQPayloadDeliveryResult::ok) {
        write_store_error(id, writer, result);
        return;
    }
    write_abort_result(id, writer);
}

}  // namespace agent_q
