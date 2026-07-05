#pragma once

#include <ArduinoJson.h>

namespace signing {

bool sui_zklogin_credential_prepare_payload_shape_valid(JsonVariantConst payload);
bool sui_zklogin_credential_propose_payload_shape_valid(JsonVariantConst payload);

}  // namespace signing
