#pragma once

#include <ArduinoJson.h>

#include "transport/payload_delivery_primitives.h"

namespace signing {

bool payload_delivery_payload_ref_wrapper(JsonDocument& request, const char** payload_ref);
const char* payload_delivery_resolve_error_code(PayloadDeliveryResult result);

}  // namespace signing
