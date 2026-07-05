#include "sui/zklogin_credential_payload.h"

#include <stddef.h>
#include <string.h>

#include "protocol/json_input.h"

namespace signing {
namespace {

bool object_has_key(JsonObjectConst object, const char* key)
{
    if (key == nullptr) {
        return false;
    }
    for (JsonPairConst pair : object) {
        if (json_string_equals(pair.key(), key)) {
            return true;
        }
    }
    return false;
}

bool object_has_exact_keys(
    JsonVariantConst value,
    const char* const* keys,
    size_t key_count)
{
    JsonObjectConst object = value.as<JsonObjectConst>();
    if (object.isNull() || !json_object_fields_supported(value, keys, key_count)) {
        return false;
    }
    for (size_t index = 0; index < key_count; ++index) {
        if (!object_has_key(object, keys[index])) {
            return false;
        }
    }
    return true;
}

bool has_sui_zklogin_selector(JsonObjectConst object)
{
    const char* chain = nullptr;
    const char* credential = nullptr;
    return json_value_c_string(object["chain"], &chain) &&
           json_value_c_string(object["credential"], &credential) &&
           strcmp(chain, "sui") == 0 &&
           strcmp(credential, "zklogin") == 0;
}

}  // namespace

bool sui_zklogin_credential_prepare_payload_shape_valid(JsonVariantConst payload)
{
    const char* const keys[] = {"chain", "credential"};
    if (!object_has_exact_keys(payload, keys, 2)) {
        return false;
    }
    return has_sui_zklogin_selector(payload.as<JsonObjectConst>());
}

bool sui_zklogin_credential_propose_payload_shape_valid(JsonVariantConst payload)
{
    const char* const keys[] = {
        "chain",
        "credential",
        "network",
        "address",
        "publicKey",
        "maxEpoch",
        "inputs",
    };
    if (!object_has_exact_keys(payload, keys, 7)) {
        return false;
    }
    return has_sui_zklogin_selector(payload.as<JsonObjectConst>());
}

}  // namespace signing
