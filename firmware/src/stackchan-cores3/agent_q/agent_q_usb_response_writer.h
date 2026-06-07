#pragma once

#include <ArduinoJson.h>
#include <stddef.h>

namespace agent_q {

constexpr size_t kAgentQUsbResponseLineMaxBytes = 64 * 1024;

bool usb_response_write_json(JsonDocument& response);

}  // namespace agent_q
