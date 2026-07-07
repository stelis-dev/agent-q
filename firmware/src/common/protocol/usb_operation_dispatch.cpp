#include "protocol/usb_operation_dispatch.h"

#include "protocol/usb_operation_manifest.h"

namespace signing {

namespace {

bool call_handler(
    UsbOperationHandler handler,
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& response_writer)
{
    if (handler == nullptr) {
        if (response_writer.can_write_error()) {
            response_writer.write_error(
                id,
                "internal_output_error");
        }
        return false;
    }
    handler(id, request, response_writer);
    return true;
}

}  // namespace

bool dispatch_usb_operation(
    const char* id,
    UsbOperationType operation_type,
    JsonDocument& request,
    const UsbOperationResponseWriter& response_writer,
    const UsbOperationHandlers& handlers)
{
    const UsbOperationManifestEntry* entry =
        usb_operation_manifest_entry(operation_type);
    if (entry == nullptr) {
        if (response_writer.can_write_error()) {
            response_writer.write_error(id, "unsupported_method");
        }
        return false;
    }

    switch (entry->handler_slot) {
        case UsbOperationHandlerSlot::get_status:
            return call_handler(handlers.get_status, id, request, response_writer);
        case UsbOperationHandlerSlot::identify_device:
            return call_handler(handlers.identify_device, id, request, response_writer);
        case UsbOperationHandlerSlot::connect:
            return call_handler(handlers.connect, id, request, response_writer);
        case UsbOperationHandlerSlot::sign_transaction:
            return call_handler(handlers.sign_transaction, id, request, response_writer);
        case UsbOperationHandlerSlot::sign_personal_message:
            return call_handler(handlers.sign_personal_message, id, request, response_writer);
        case UsbOperationHandlerSlot::get_result:
            return call_handler(handlers.get_result, id, request, response_writer);
        case UsbOperationHandlerSlot::ack_result:
            return call_handler(handlers.ack_result, id, request, response_writer);
        case UsbOperationHandlerSlot::disconnect:
            return call_handler(handlers.disconnect, id, request, response_writer);
        case UsbOperationHandlerSlot::get_capabilities:
            return call_handler(handlers.get_capabilities, id, request, response_writer);
        case UsbOperationHandlerSlot::get_accounts:
            return call_handler(handlers.get_accounts, id, request, response_writer);
        case UsbOperationHandlerSlot::policy_get:
            return call_handler(handlers.policy_get, id, request, response_writer);
        case UsbOperationHandlerSlot::get_approval_history:
            return call_handler(handlers.get_approval_history, id, request, response_writer);
        case UsbOperationHandlerSlot::policy_propose:
            return call_handler(handlers.policy_propose, id, request, response_writer);
        case UsbOperationHandlerSlot::credential_prepare:
            return call_handler(handlers.credential_prepare, id, request, response_writer);
        case UsbOperationHandlerSlot::credential_propose:
            return call_handler(handlers.credential_propose, id, request, response_writer);
        case UsbOperationHandlerSlot::payload_transfer_begin:
            return call_handler(handlers.payload_transfer_begin, id, request, response_writer);
        case UsbOperationHandlerSlot::payload_transfer_chunk:
            return call_handler(handlers.payload_transfer_chunk, id, request, response_writer);
        case UsbOperationHandlerSlot::payload_transfer_finish:
            return call_handler(handlers.payload_transfer_finish, id, request, response_writer);
        case UsbOperationHandlerSlot::payload_transfer_abort:
            return call_handler(handlers.payload_transfer_abort, id, request, response_writer);
        case UsbOperationHandlerSlot::none:
            break;
    }
    return false;
}

}  // namespace signing
