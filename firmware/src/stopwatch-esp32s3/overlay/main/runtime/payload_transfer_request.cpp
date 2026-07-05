#include "payload_transfer_request.h"

#include <string.h>

#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_id.h"
#include "session_state.h"

namespace stopwatch_target {
namespace {

bool request_has_only_fields(JsonDocument& request, const char* const* fields, size_t count)
{
    return signing::json_object_fields_supported(request.as<JsonVariantConst>(), fields, count);
}

bool request_has_key(JsonDocument& request, const char* key)
{
    if (key == nullptr) {
        return false;
    }
    for (JsonPairConst pair : request.as<JsonObjectConst>()) {
        if (signing::json_string_equals(pair.key(), key)) {
            return true;
        }
    }
    return false;
}

PayloadTransferRequestAction payload_transfer_action(const char* action)
{
    if (strcmp(action, "begin") == 0) {
        return PayloadTransferRequestAction::begin;
    }
    if (strcmp(action, "chunk") == 0) {
        return PayloadTransferRequestAction::chunk;
    }
    if (strcmp(action, "finish") == 0) {
        return PayloadTransferRequestAction::finish;
    }
    return PayloadTransferRequestAction::abort;
}

}  // namespace

PayloadTransferRequestParseStatus payload_transfer_request_parse(
    JsonDocument& request,
    PayloadTransferRequestEnvelope* output)
{
    if (output == nullptr) {
        return PayloadTransferRequestParseStatus::invalid_envelope;
    }
    output->id = nullptr;
    output->session_id = nullptr;
    output->action = PayloadTransferRequestAction::begin;

    const char* id = nullptr;
    if (!signing::json_value_c_string(request["id"], &id) ||
        !signing::request_id_format_valid(id)) {
        return PayloadTransferRequestParseStatus::invalid_envelope;
    }
    output->id = id;

    if (!request["version"].is<int>()) {
        return PayloadTransferRequestParseStatus::invalid_envelope;
    }
    if (request["version"].as<int>() != signing::kProtocolVersion) {
        return PayloadTransferRequestParseStatus::unsupported_version;
    }

    const char* type = nullptr;
    if (!signing::json_value_c_string(request["type"], &type)) {
        return PayloadTransferRequestParseStatus::invalid_request;
    }
    if (strcmp(type, "payload_transfer") != 0) {
        return PayloadTransferRequestParseStatus::unsupported_method;
    }

    const char* action = nullptr;
    if (!signing::json_value_c_string(request["action"], &action)) {
        return PayloadTransferRequestParseStatus::unsupported_method;
    }

    const char* const begin_fields[] = {
        "id", "version", "type", "action", "sessionId", "totalBytes", "payloadDigest",
    };
    const char* const chunk_fields[] = {
        "id", "version", "type", "action", "sessionId", "transferId", "offsetBytes", "chunk",
    };
    const char* const finish_fields[] = {
        "id", "version", "type", "action", "sessionId", "transferId",
    };
    const char* const abort_fields[] = {
        "id", "version", "type", "action", "sessionId", "transferId",
    };
    const char* const abort_finalized_fields[] = {
        "id", "version", "type", "action", "sessionId", "payloadRef",
    };

    if (strcmp(action, "begin") == 0) {
        if (!request_has_only_fields(request, begin_fields, 7)) {
            return PayloadTransferRequestParseStatus::invalid_request;
        }
    } else if (strcmp(action, "chunk") == 0) {
        if (!request_has_only_fields(request, chunk_fields, 8)) {
            return PayloadTransferRequestParseStatus::invalid_request;
        }
    } else if (strcmp(action, "finish") == 0) {
        if (!request_has_only_fields(request, finish_fields, 6)) {
            return PayloadTransferRequestParseStatus::invalid_request;
        }
    } else if (strcmp(action, "abort") == 0) {
        const bool has_transfer_id = request_has_key(request, "transferId");
        const bool has_payload_ref = request_has_key(request, "payloadRef");
        if (has_transfer_id == has_payload_ref) {
            return PayloadTransferRequestParseStatus::invalid_request;
        }
        if (has_transfer_id) {
            if (!request_has_only_fields(request, abort_fields, 6)) {
                return PayloadTransferRequestParseStatus::invalid_request;
            }
        } else if (!request_has_only_fields(request, abort_finalized_fields, 6)) {
            return PayloadTransferRequestParseStatus::invalid_request;
        }
    } else {
        return PayloadTransferRequestParseStatus::unsupported_method;
    }

    const char* session_id = nullptr;
    if (!signing::json_value_c_string(request["sessionId"], &session_id) ||
        !session_id_format_valid(session_id)) {
        return PayloadTransferRequestParseStatus::invalid_session;
    }
    output->session_id = session_id;
    output->action = payload_transfer_action(action);
    return PayloadTransferRequestParseStatus::ok;
}

const char* payload_transfer_request_error_code(PayloadTransferRequestParseStatus status)
{
    switch (status) {
        case PayloadTransferRequestParseStatus::ok:
            return nullptr;
        case PayloadTransferRequestParseStatus::unsupported_version:
            return "unsupported_version";
        case PayloadTransferRequestParseStatus::unsupported_method:
            return "unsupported_method";
        case PayloadTransferRequestParseStatus::invalid_session:
            return "invalid_session";
        case PayloadTransferRequestParseStatus::invalid_envelope:
        case PayloadTransferRequestParseStatus::invalid_request:
        default:
            return "invalid_request";
    }
}

}  // namespace stopwatch_target
