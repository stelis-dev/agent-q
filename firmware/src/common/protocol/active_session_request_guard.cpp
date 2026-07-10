#include "protocol/active_session_request_guard.h"

#include "protocol/json_input.h"

namespace signing {
namespace {

bool parse_session_id_or_write_error(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    SessionIdMode mode,
    const char** session_id)
{
    const bool parsed =
        mode == SessionIdMode::required
            ? json_value_c_string(request["sessionId"], session_id)
            : json_optional_c_string(request["sessionId"], "", session_id);
    if (parsed) {
        return true;
    }
    writer.write_error(id, "invalid_session");
    return false;
}

bool request_fields_supported(
    JsonDocument& request,
    const char* const* allowed_request_fields,
    size_t allowed_request_field_count)
{
    if (allowed_request_fields == nullptr && allowed_request_field_count == 0) {
        return true;
    }
    if (allowed_request_fields == nullptr) {
        return false;
    }
    return json_object_fields_supported(
        request.as<JsonVariantConst>(),
        allowed_request_fields,
        allowed_request_field_count);
}

}  // namespace

bool guard_active_session_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    OperationType operation,
    const ActiveSessionRequestGuardOps& ops,
    SessionIdMode session_id_mode,
    const char* const* allowed_request_fields,
    size_t allowed_request_field_count,
    const char** session_id)
{
    if (session_id == nullptr) {
        writer.write_error(id, "internal_output_error");
        return false;
    }
    *session_id = nullptr;
    if (ops.material_ready == nullptr ||
        !ops.material_ready()) {
        writer.write_error(id, "invalid_state");
        return false;
    }
    if (ops.write_busy_if_pending_or_local_flow_active != nullptr &&
        ops.write_busy_if_pending_or_local_flow_active(id, writer)) {
        return false;
    }
    if (ops.write_admission_error != nullptr &&
        ops.write_admission_error(id, operation, writer)) {
        return false;
    }
    if (!parse_session_id_or_write_error(id, request, writer, session_id_mode, session_id)) {
        return false;
    }
    if (ops.require_active_matching_session == nullptr ||
        !ops.require_active_matching_session(id, *session_id, writer)) {
        return false;
    }
    if (!request_fields_supported(request, allowed_request_fields, allowed_request_field_count)) {
        writer.write_error(id, "invalid_request");
        return false;
    }
    return true;
}

}  // namespace signing
