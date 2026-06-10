#include "agent_q_usb_operation_dispatch.h"

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
    switch (operation_type) {
        case AgentQUsbOperationType::get_status:
            return call_handler(handlers.get_status, id, request, response_writer);
        case AgentQUsbOperationType::identify_device:
            return call_handler(handlers.identify_device, id, request, response_writer);
        case AgentQUsbOperationType::connect:
            return call_handler(handlers.connect, id, request, response_writer);
        case AgentQUsbOperationType::sign_transaction:
            return call_handler(handlers.sign_transaction, id, request, response_writer);
        case AgentQUsbOperationType::sign_personal_message:
            return call_handler(handlers.sign_personal_message, id, request, response_writer);
        case AgentQUsbOperationType::get_result:
            return call_handler(handlers.get_result, id, request, response_writer);
        case AgentQUsbOperationType::ack_result:
            return call_handler(handlers.ack_result, id, request, response_writer);
        case AgentQUsbOperationType::disconnect:
            return call_handler(handlers.disconnect, id, request, response_writer);
        case AgentQUsbOperationType::get_capabilities:
            return call_handler(handlers.get_capabilities, id, request, response_writer);
        case AgentQUsbOperationType::get_accounts:
            return call_handler(handlers.get_accounts, id, request, response_writer);
        case AgentQUsbOperationType::policy_get:
            return call_handler(handlers.policy_get, id, request, response_writer);
        case AgentQUsbOperationType::get_approval_history:
            return call_handler(handlers.get_approval_history, id, request, response_writer);
        case AgentQUsbOperationType::policy_propose:
            return call_handler(handlers.policy_propose, id, request, response_writer);
        case AgentQUsbOperationType::unsupported:
            if (response_writer.write_error != nullptr) {
                response_writer.write_error(id, "unsupported_type", "Unsupported request type.");
            }
            return false;
    }
    return false;
}

}  // namespace agent_q
