#pragma once

#include <stddef.h>

#include "local_pin_auth.h"
#include "transport/timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class RequestBackedLocalPinOwner {
    none,
    protocol_pin_approval,
    user_signing,
};

RequestBackedLocalPinOwner request_backed_local_pin_owner_for_purpose(
    LocalPinAuthPurpose purpose);
bool request_backed_local_pin_purpose(LocalPinAuthPurpose purpose);
bool request_backed_local_pin_request_id(
    LocalPinAuthPurpose purpose,
    char* output,
    size_t output_size);
TimeoutWindow request_backed_local_pin_cap_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now,
    TimeoutWindow input_window);
bool request_backed_local_pin_resume_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now);
bool request_backed_local_pin_pause_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now);
bool request_backed_local_pin_deadline_reached(
    LocalPinAuthPurpose purpose,
    TickType_t now);

}  // namespace signing
