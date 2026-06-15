#include "agent_q_usb_operation_dispatch.h"

#include "agent_q_usb_operation_manifest.h"

namespace agent_q {

namespace {

bool call_handler(
    AgentQUsbOperationHandler handler,
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& response_writer)
{
    if (handler == nullptr) {
        if (response_writer.write_error != nullptr) {
            response_writer.write_error(
                id,
                "protocol_error",
                "USB operation handler is unavailable.");
        }
        return false;
    }
    handler(id, request, response_writer);
    return true;
}

}  // namespace

bool dispatch_usb_operation(
    const char* id,
    AgentQUsbOperationType operation_type,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& response_writer,
    const AgentQUsbOperationHandlers& handlers)
{
    const AgentQUsbOperationManifestEntry* entry =
        usb_operation_manifest_entry(operation_type);
    if (entry == nullptr) {
        if (response_writer.write_error != nullptr) {
            response_writer.write_error(id, "unsupported_type", "Unsupported request type.");
        }
        return false;
    }

    switch (entry->handler_slot) {
        case AgentQUsbOperationHandlerSlot::get_status:
            return call_handler(handlers.get_status, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::identify_device:
            return call_handler(handlers.identify_device, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::connect:
            return call_handler(handlers.connect, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::sign_transaction:
            return call_handler(handlers.sign_transaction, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::sign_personal_message:
            return call_handler(handlers.sign_personal_message, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::get_result:
            return call_handler(handlers.get_result, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::ack_result:
            return call_handler(handlers.ack_result, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::disconnect:
            return call_handler(handlers.disconnect, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::get_capabilities:
            return call_handler(handlers.get_capabilities, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::get_accounts:
            return call_handler(handlers.get_accounts, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::policy_get:
            return call_handler(handlers.policy_get, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::get_approval_history:
            return call_handler(handlers.get_approval_history, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::policy_propose:
            return call_handler(handlers.policy_propose, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::payload_upload_begin:
            return call_handler(handlers.payload_upload_begin, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::payload_upload_chunk:
            return call_handler(handlers.payload_upload_chunk, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::payload_upload_finish:
            return call_handler(handlers.payload_upload_finish, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::payload_upload_abort:
            return call_handler(handlers.payload_upload_abort, id, request, response_writer);
        case AgentQUsbOperationHandlerSlot::none:
            break;
    }
    return false;
}

}  // namespace agent_q
