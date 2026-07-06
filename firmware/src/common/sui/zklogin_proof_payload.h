#pragma once

#include <ArduinoJson.h>

#include "sui/zklogin_proof_record.h"

namespace signing {

enum class SuiZkLoginProofPayloadParseResult {
    ok,
    invalid_argument,
    invalid_proof,
    encode_error,
};

SuiZkLoginProofPayloadParseResult parse_sui_zklogin_proof_payload(
    JsonVariantConst payload,
    SuiZkLoginProofRecord* record);

}  // namespace signing
