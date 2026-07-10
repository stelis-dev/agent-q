#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_session_read_handlers.sh

Compiles extracted USB session-scoped read handlers and verifies
get_capabilities and get_accounts validation/response behavior. It does not
require hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_PROTOCOL_DIR="${COMMON_ROOT}/protocol"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_ROOT}/protocol/sign_route.h" \
  "${COMMON_ROOT}/protocol/active_session_request_guard.cpp" \
  "${COMMON_ROOT}/protocol/active_session_request_guard.h" \
  "${COMMON_PROTOCOL_DIR}/session_read_handlers.cpp" \
  "${COMMON_PROTOCOL_DIR}/session_read_handlers.h" \
  "${COMMON_ROOT}/protocol/response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-session-read-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/stubs"
mkdir -p "${TMP_DIR}/firmware_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

cat >"${TMP_DIR}/stubs/byte_conversions.h" <<'H'
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

inline int bytes_to_base64(
    const uint8_t* input,
    size_t input_size,
    char* output,
    size_t output_size)
{
    if (input == nullptr || output == nullptr || output_size < 45) {
        return -1;
    }
    if (input_size == 33 && input[0] == 0x00) {
        snprintf(output, output_size, "AAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH");
        return 0;
    }
    if (input_size == 60 && input[0] == 0x05) {
        snprintf(
            output,
            output_size,
            "BQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB");
        return 0;
    }
    return 0;
}
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/session_read_handlers.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_payload_admission_calls = 0;
int g_require_session_calls = 0;
int g_read_mode_calls = 0;
int g_read_sui_account_settings_calls = 0;
int g_sui_zklogin_credential_available_calls = 0;
int g_resolve_active_identity_calls = 0;
int g_record_root_material_unreadable_calls = 0;
int g_write_json_calls = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_payload_admission_error = false;
bool g_session_valid = true;
bool g_read_mode_ok = true;
bool g_read_sui_account_settings_ok = true;
bool g_accept_gas_sponsor = false;
bool g_sui_zklogin_credential_available = true;
signing::SuiActiveIdentityKind g_active_identity_kind =
    signing::SuiActiveIdentityKind::native;
signing::SuiActiveIdentityError g_active_identity_error =
    signing::SuiActiveIdentityError::none;
bool g_write_json_ok = true;
constexpr size_t kTestEd25519PublicKeyBytes = 32;
constexpr size_t kTestSchemePrefixedEd25519PublicKeyBytes = 1 + kTestEd25519PublicKeyBytes;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
char g_last_json_type[32] = {};
char g_last_json_auth[16] = {};
char g_last_json_account_address[80] = {};
char g_last_json_account_public_key[128] = {};
char g_last_json_account_key_scheme[16] = {};
char g_last_json_account_derivation_path[32] = {};
bool g_last_json_sponsored_transactions_present = false;
bool g_last_json_accept_gas_sponsor = false;
char g_last_json_capability_key_scheme[16] = {};
char g_last_json_capability_derivation_path[32] = {};
char g_last_json_policy_id[80] = {};
char g_last_json_condition_where_type[256] = {};
char g_last_payload_kind[24] = {};
char g_last_payload_inline_max[24] = {};
char g_last_payload_chunk_max[24] = {};
char g_last_payload_max[24] = {};
size_t g_last_json_signing_method_count = 0;
bool g_last_json_credentials_array_present = false;
size_t g_last_json_credential_count = 0;
size_t g_last_json_credential_operation_count = 0;

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_payload_admission_calls = 0;
    g_require_session_calls = 0;
    g_read_mode_calls = 0;
    g_read_sui_account_settings_calls = 0;
    g_sui_zklogin_credential_available_calls = 0;
    g_resolve_active_identity_calls = 0;
    g_record_root_material_unreadable_calls = 0;
    g_write_json_calls = 0;
    g_material_ready = true;
    g_busy = false;
    g_payload_admission_error = false;
    g_session_valid = true;
    g_read_mode_ok = true;
    g_read_sui_account_settings_ok = true;
    g_accept_gas_sponsor = false;
    g_sui_zklogin_credential_available = true;
    g_active_identity_kind = signing::SuiActiveIdentityKind::native;
    g_active_identity_error = signing::SuiActiveIdentityError::none;
    g_write_json_ok = true;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_json_type[0] = '\0';
    g_last_json_auth[0] = '\0';
    g_last_json_account_address[0] = '\0';
    g_last_json_account_public_key[0] = '\0';
    g_last_json_account_key_scheme[0] = '\0';
    g_last_json_account_derivation_path[0] = '\0';
    g_last_json_sponsored_transactions_present = false;
    g_last_json_accept_gas_sponsor = false;
    g_last_json_capability_key_scheme[0] = '\0';
    g_last_json_capability_derivation_path[0] = '\0';
    g_last_json_policy_id[0] = '\0';
    g_last_json_condition_where_type[0] = '\0';
    g_last_payload_kind[0] = '\0';
    g_last_payload_inline_max[0] = '\0';
    g_last_payload_chunk_max[0] = '\0';
    g_last_payload_max[0] = '\0';
    g_last_json_signing_method_count = 0;
    g_last_json_credentials_array_present = false;
    g_last_json_credential_count = 0;
    g_last_json_credential_operation_count = 0;
}

}  // namespace

namespace signing {

const char* authorization_mode_name(AuthorizationMode mode)
{
    return mode == AuthorizationMode::policy ? "policy" : "user";
}

bool usb_response_write_json(JsonDocument& response)
{
    g_write_json_calls += 1;
    JsonObjectConst result = response["result"].as<JsonObjectConst>();
    const char* type = response["method"] | "";
    snprintf(g_last_json_type, sizeof(g_last_json_type), "%s", type);
    const char* authorization = result["signing"]["authorization"] | "";
    snprintf(g_last_json_auth, sizeof(g_last_json_auth), "%s", authorization);
    JsonArrayConst methods = result["signing"]["methods"].as<JsonArrayConst>();
    g_last_json_signing_method_count = methods.size();
    JsonObjectConst payload = methods[0]["payload"].as<JsonObjectConst>();
    snprintf(g_last_payload_kind, sizeof(g_last_payload_kind), "%s", payload["kind"] | "");
    snprintf(g_last_payload_inline_max, sizeof(g_last_payload_inline_max), "%s", payload["inlineMaxBytes"] | "");
    snprintf(g_last_payload_chunk_max, sizeof(g_last_payload_chunk_max), "%s", payload["chunkMaxBytes"] | "");
    snprintf(g_last_payload_max, sizeof(g_last_payload_max), "%s", payload["payloadMaxBytes"] | "");
    JsonArrayConst credentials = result["credentials"].as<JsonArrayConst>();
    g_last_json_credentials_array_present = !credentials.isNull();
    g_last_json_credential_count = credentials.size();
    if (g_last_json_credential_count > 0) {
        JsonArrayConst operations = credentials[0]["operations"].as<JsonArrayConst>();
        g_last_json_credential_operation_count = operations.size();
    }
    const char* account_address = result["accounts"][0]["address"] | "";
    snprintf(g_last_json_account_address, sizeof(g_last_json_account_address), "%s", account_address);
    const char* account_public_key = result["accounts"][0]["publicKey"] | "";
    snprintf(g_last_json_account_public_key, sizeof(g_last_json_account_public_key), "%s", account_public_key);
    const char* account_key_scheme = result["accounts"][0]["keyScheme"] | "";
    snprintf(g_last_json_account_key_scheme, sizeof(g_last_json_account_key_scheme), "%s", account_key_scheme);
    const char* account_derivation_path = result["accounts"][0]["derivationPath"] | "";
    snprintf(
        g_last_json_account_derivation_path,
        sizeof(g_last_json_account_derivation_path),
        "%s",
        account_derivation_path);
    JsonVariantConst sponsored_transactions = result["accounts"][0]["sponsoredTransactions"];
    g_last_json_sponsored_transactions_present = !sponsored_transactions.isNull();
    g_last_json_accept_gas_sponsor =
        sponsored_transactions["acceptGasSponsor"] | false;
    const char* capability_key_scheme = result["chains"][0]["accounts"][0]["keyScheme"] | "";
    snprintf(
        g_last_json_capability_key_scheme,
        sizeof(g_last_json_capability_key_scheme),
        "%s",
        capability_key_scheme);
    const char* capability_derivation_path =
        result["chains"][0]["accounts"][0]["derivationPath"] | "";
    snprintf(
        g_last_json_capability_derivation_path,
        sizeof(g_last_json_capability_derivation_path),
        "%s",
        capability_derivation_path);
    return g_write_json_ok;
}

bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = 1;
    response["success"] = true;
    response["method"] = method;
    response["result"].set(result);
    return usb_response_write_json(response);
}

}  // namespace signing

namespace {

bool write_error(const char* id, const char* code)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
    return true;
}

void log_write_failure(const char* response_type, const char* id)
{
    (void)response_type;
    g_log_write_failure_calls += 1;
    g_last_id = id;
}

bool material_ready()
{
    g_material_calls += 1;
    return g_material_ready;
}

bool write_busy(const char* id, const signing::ResponseWriter& writer)
{
    g_busy_calls += 1;
    g_last_id = id;
    if (g_busy) {
        writer.write_error(id, "busy");
    }
    return g_busy;
}

bool write_payload_admission_error(
    const char* id,
    signing::OperationType operation,
    const signing::ResponseWriter& writer)
{
    assert(operation == signing::OperationType::get_capabilities ||
           operation == signing::OperationType::get_accounts);
    g_payload_admission_calls += 1;
    g_last_id = id;
    if (g_payload_admission_error) {
        writer.write_error(id, "busy");
        return true;
    }
    return false;
}

bool require_session(
    const char* id,
    const char* session_id,
    const signing::ResponseWriter& writer)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    if (!g_session_valid) {
        writer.write_error(id, "invalid_session");
    }
    return g_session_valid;
}

bool read_signing_mode(signing::AuthorizationMode* mode)
{
    g_read_mode_calls += 1;
    *mode = signing::AuthorizationMode::policy;
    return g_read_mode_ok;
}

bool read_sui_account_settings(signing::SuiAccountSettings* settings)
{
    g_read_sui_account_settings_calls += 1;
    if (settings != nullptr) {
        settings->accept_gas_sponsor = g_accept_gas_sponsor;
    }
    return g_read_sui_account_settings_ok;
}

bool sui_zklogin_credential_available()
{
    g_sui_zklogin_credential_available_calls += 1;
    return g_sui_zklogin_credential_available;
}

signing::SuiActiveIdentity resolve_active_identity()
{
    g_resolve_active_identity_calls += 1;
    signing::SuiActiveIdentity identity = {};
    identity.kind = g_active_identity_kind;
    identity.error = g_active_identity_error;
    if (identity.kind == signing::SuiActiveIdentityKind::native) {
        snprintf(
            identity.address,
            sizeof(identity.address),
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        identity.public_key[0] = signing::kSuiSignatureSchemeFlagEd25519;
        memset(identity.public_key + 1, 7, kTestEd25519PublicKeyBytes);
        identity.public_key_size = kTestSchemePrefixedEd25519PublicKeyBytes;
    } else if (identity.kind == signing::SuiActiveIdentityKind::zklogin) {
        snprintf(
            identity.address,
            sizeof(identity.address),
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        identity.public_key[0] = signing::kSuiSignatureSchemeFlagZkLogin;
        memset(identity.public_key + 1, 1, 59);
        identity.public_key_size = 60;
    }
    return identity;
}

void record_root_material_unreadable()
{
    g_record_root_material_unreadable_calls += 1;
}

signing::ResponseWriter make_writer()
{
    return signing::ResponseWriter{
        write_error,
        signing::usb_response_write_success_result,
        log_write_failure,
    };
}

signing::SessionReadHandlerOps make_ops()
{
    return signing::SessionReadHandlerOps{
        material_ready,
        write_busy,
        write_payload_admission_error,
        require_session,
        read_signing_mode,
        read_sui_account_settings,
        sui_zklogin_credential_available,
        resolve_active_identity,
        record_root_material_unreadable,
    };
}

JsonDocument parse_request(const char* json)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, json);
    assert(!error);
    return request;
}

}  // namespace

int main()
{
    {
        reset_state();
        g_material_ready = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_payload_admission_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_mode_calls == 0);
        assert(g_sui_zklogin_credential_available_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_material_calls == 1);
        assert(g_busy_calls == 1);
        assert(g_payload_admission_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        g_payload_admission_error = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_material_calls == 1);
        assert(g_busy_calls == 1);
        assert(g_payload_admission_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":7}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_require_session_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_payload_admission_calls == 1);
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\",\"extra\":1}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        g_read_mode_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_read_mode_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_write_json_calls == 0);
        assert(g_sui_zklogin_credential_available_calls == 0);
        assert(g_resolve_active_identity_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_read_mode_calls == 1);
        assert(g_resolve_active_identity_calls == 1);
        assert(g_sui_zklogin_credential_available_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "get_capabilities") == 0);
        assert(strcmp(g_last_json_auth, "policy") == 0);
        assert(strcmp(g_last_json_capability_key_scheme, "ed25519") == 0);
        assert(strcmp(g_last_json_capability_derivation_path, "m/44'/784'/0'/0'/0'") == 0);
        assert(g_last_json_signing_method_count == 1);
        assert(strcmp(g_last_payload_kind, "") == 0);
        assert(strcmp(g_last_payload_inline_max, "") == 0);
        assert(strcmp(g_last_payload_chunk_max, "") == 0);
        assert(strcmp(g_last_payload_max, "") == 0);
        assert(g_last_json_credentials_array_present);
        assert(g_last_json_credential_count == 1);
        assert(g_last_json_credential_operation_count == 2);
    }

    {
        reset_state();
        g_active_identity_kind = signing::SuiActiveIdentityKind::zklogin;
        g_sui_zklogin_credential_available = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_resolve_active_identity_calls == 1);
        assert(g_sui_zklogin_credential_available_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_capability_key_scheme, "zklogin") == 0);
        assert(strcmp(g_last_json_capability_derivation_path, "") == 0);
        assert(g_last_json_credentials_array_present);
        assert(g_last_json_credential_count == 0);
    }

    {
        reset_state();
        g_active_identity_kind = signing::SuiActiveIdentityKind::none;
        g_sui_zklogin_credential_available = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_resolve_active_identity_calls == 1);
        assert(g_sui_zklogin_credential_available_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_capability_key_scheme, "") == 0);
        assert(strcmp(g_last_json_auth, "") == 0);
        assert(g_last_json_signing_method_count == 0);
        assert(g_last_json_credentials_array_present);
        assert(g_last_json_credential_count == 1);
        assert(g_last_json_credential_operation_count == 2);
    }

    {
        reset_state();
        g_active_identity_kind = signing::SuiActiveIdentityKind::error;
        g_active_identity_error = signing::SuiActiveIdentityError::proof_storage_error;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_resolve_active_identity_calls == 1);
        assert(g_sui_zklogin_credential_available_calls == 0);
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_unavailable") == 0);
        assert(g_record_root_material_unreadable_calls == 0);
    }

    {
        reset_state();
        g_write_json_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_json_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_write_error_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "get_accounts") == 0);
        assert(strcmp(g_last_json_account_address, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef") == 0);
        assert(strcmp(g_last_json_account_public_key, "AAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH") == 0);
        assert(strcmp(g_last_json_account_key_scheme, "ed25519") == 0);
        assert(strcmp(g_last_json_account_derivation_path, "m/44'/784'/0'/0'/0'") == 0);
        assert(g_last_json_sponsored_transactions_present);
        assert(!g_last_json_accept_gas_sponsor);
    }

    {
        reset_state();
        g_active_identity_kind = signing::SuiActiveIdentityKind::zklogin;
        g_accept_gas_sponsor = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_account_address, "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890") == 0);
        assert(strcmp(
            g_last_json_account_public_key,
            "BQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB") == 0);
        assert(strcmp(g_last_json_account_key_scheme, "zklogin") == 0);
        assert(strcmp(g_last_json_account_derivation_path, "") == 0);
        assert(g_last_json_sponsored_transactions_present);
        assert(g_last_json_accept_gas_sponsor);
    }

    {
        reset_state();
        g_active_identity_kind = signing::SuiActiveIdentityKind::none;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 0);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_account_address, "") == 0);
        assert(strcmp(g_last_json_account_public_key, "") == 0);
        assert(strcmp(g_last_json_account_key_scheme, "") == 0);
    }

    {
        reset_state();
        g_active_identity_kind = signing::SuiActiveIdentityKind::error;
        g_active_identity_error = signing::SuiActiveIdentityError::proof_storage_error;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 0);
        assert(g_record_root_material_unreadable_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_unavailable") == 0);
    }

    {
        reset_state();
        g_active_identity_kind = signing::SuiActiveIdentityKind::error;
        g_active_identity_error = signing::SuiActiveIdentityError::native_account_unavailable;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 0);
        assert(g_record_root_material_unreadable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_unavailable") == 0);
    }

    {
        reset_state();
        g_read_sui_account_settings_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session\"}");
        signing::handle_protocol_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 1);
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_unavailable") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session\",\"extra\":1}");
        signing::handle_protocol_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
        assert(g_resolve_active_identity_calls == 0);
    }

    printf("USB session-read handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/protocol/active_session_request_guard.cpp" \
  "${COMMON_PROTOCOL_DIR}/session_read_handlers.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
