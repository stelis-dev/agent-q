#pragma once

#include <stddef.h>

namespace signing {

constexpr size_t kUsbRequestLineMaxBytes = 16 * 1024;

using UsbRequestLineHandler = void (*)(const char* line);
using UsbRequestLineErrorHandler = void (*)(const char* code);

void usb_line_receiver_reset();
void usb_line_receiver_poll(
    UsbRequestLineHandler handle_line,
    UsbRequestLineErrorHandler write_error);

}  // namespace signing
