#pragma once

#include <stdint.h>

#include "local_auth_worker.h"
#include "timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class LocalPinAuthSignatureVerifyResult {
    not_ready,
    verified,
    wrong_pin,
    locked,
    auth_unavailable,
};

struct LocalPinAuthSignatureBinding {
    uint32_t token;
};

bool local_pin_auth_begin_user_signing(
    const LocalPinAuthSignatureBinding& binding,
    TickType_t now,
    TimeoutWindow input_window);
bool local_pin_auth_user_signing_matches(
    const LocalPinAuthSignatureBinding& binding);
LocalPinAuthSignatureVerifyResult local_pin_auth_complete_user_signing_verify_job(
    const LocalAuthWorkerResult& result,
    TickType_t lockout_until);

}  // namespace signing
