#pragma once

#include "protocol/usb_request_line.h"

namespace signing {

using UsbRequestLineHandler = void (*)(const char* line);
using UsbRequestLineErrorHandler = void (*)(const char* code);

void usb_line_receiver_reset();
void usb_line_receiver_poll(
    UsbRequestLineHandler handle_line,
    UsbRequestLineErrorHandler write_error);

}  // namespace signing
