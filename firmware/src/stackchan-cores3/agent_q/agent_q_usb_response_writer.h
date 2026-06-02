#pragma once

#include <ArduinoJson.h>

namespace agent_q {

bool usb_response_write_json(JsonDocument& response);

}  // namespace agent_q
