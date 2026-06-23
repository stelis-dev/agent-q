#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_session_read_handlers.sh

Compiles extracted USB session-scoped read handlers and verifies
get_capabilities, get_accounts, and policy_get validation/response behavior. It
does not require hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_AGENT_Q_DIR="${REPO_ROOT}/firmware/src/common/agent_q"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_AGENT_Q_DIR}/agent_q_sign_route.h" \
  "${COMMON_AGENT_Q_DIR}/policy/agent_q_policy_document.cpp" \
  "${COMMON_AGENT_Q_DIR}/policy/agent_q_policy_document.h" \
  "${AGENT_Q_DIR}/agent_q_usb_session_read_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_session_read_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-session-read-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/stubs"
mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_AGENT_Q_DIR}/policy" "${TMP_DIR}/agent_q_common/policy"

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

#include "agent_q_usb_session_read_handlers.h"

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
int g_read_policy_calls = 0;
int g_record_policy_unavailable_calls = 0;
int g_write_json_calls = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_payload_admission_error = false;
bool g_session_valid = true;
bool g_read_mode_ok = true;
bool g_read_sui_account_settings_ok = true;
bool g_accept_gas_sponsor = false;
bool g_sui_zklogin_credential_available = true;
agent_q::AgentQSuiActiveIdentityKind g_active_identity_kind =
    agent_q::AgentQSuiActiveIdentityKind::native;
agent_q::AgentQSuiActiveIdentityError g_active_identity_error =
    agent_q::AgentQSuiActiveIdentityError::none;
bool g_read_policy_ok = true;
bool g_policy_has_document = true;
bool g_write_json_ok = true;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;
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
size_t g_last_json_credential_count = 0;
size_t g_last_json_credential_operation_count = 0;
size_t g_last_json_policy_count = 0;
size_t g_last_json_policy_condition_count = 0;

agent_q::AgentQCurrentPolicyDocument g_policy_document = {};

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
    g_read_policy_calls = 0;
    g_record_policy_unavailable_calls = 0;
    g_write_json_calls = 0;
    g_material_ready = true;
    g_busy = false;
    g_payload_admission_error = false;
    g_session_valid = true;
    g_read_mode_ok = true;
    g_read_sui_account_settings_ok = true;
    g_accept_gas_sponsor = false;
    g_sui_zklogin_credential_available = true;
    g_active_identity_kind = agent_q::AgentQSuiActiveIdentityKind::native;
    g_active_identity_error = agent_q::AgentQSuiActiveIdentityError::none;
    g_read_policy_ok = true;
    g_policy_has_document = true;
    g_write_json_ok = true;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_error_message = nullptr;
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
    g_last_json_credential_count = 0;
    g_last_json_credential_operation_count = 0;
    g_last_json_policy_count = 0;
    g_last_json_policy_condition_count = 0;
    g_policy_document = agent_q::AgentQCurrentPolicyDocument{
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        nullptr,
        0,
    };
}

void count_policy_document(
    const agent_q::AgentQCurrentPolicyDocument& document,
    size_t* network_count,
    size_t* policy_count,
    size_t* condition_count)
{
    *network_count = 0;
    *policy_count = 0;
    *condition_count = 0;
    for (size_t blockchain_index = 0; blockchain_index < document.blockchain_count; ++blockchain_index) {
        const agent_q::AgentQCurrentPolicyBlockchainScope& blockchain =
            document.blockchains[blockchain_index];
        *network_count += blockchain.network_count;
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const agent_q::AgentQCurrentPolicyNetworkScope& network = blockchain.networks[network_index];
            *policy_count += network.policy_count;
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                *condition_count += network.policies[policy_index].condition_count;
            }
        }
    }
}

}  // namespace

namespace agent_q {

const char* signing_authorization_mode_name(AgentQSigningAuthorizationMode mode)
{
    return mode == AgentQSigningAuthorizationMode::policy ? "policy" : "user";
}

bool usb_response_write_json(JsonDocument& response)
{
    g_write_json_calls += 1;
    const char* type = response["type"] | "";
    snprintf(g_last_json_type, sizeof(g_last_json_type), "%s", type);
    const char* authorization = response["signing"]["authorization"] | "";
    snprintf(g_last_json_auth, sizeof(g_last_json_auth), "%s", authorization);
    JsonArray methods = response["signing"]["methods"].as<JsonArray>();
    g_last_json_signing_method_count = methods.size();
    JsonObject payload = methods[0]["payload"].as<JsonObject>();
    snprintf(g_last_payload_kind, sizeof(g_last_payload_kind), "%s", payload["kind"] | "");
    snprintf(g_last_payload_inline_max, sizeof(g_last_payload_inline_max), "%s", payload["inlineMaxBytes"] | "");
    snprintf(g_last_payload_chunk_max, sizeof(g_last_payload_chunk_max), "%s", payload["chunkMaxBytes"] | "");
    snprintf(g_last_payload_max, sizeof(g_last_payload_max), "%s", payload["payloadMaxBytes"] | "");
    JsonArray credentials = response["credentials"].as<JsonArray>();
    g_last_json_credential_count = credentials.size();
    if (g_last_json_credential_count > 0) {
        JsonArray operations = credentials[0]["operations"].as<JsonArray>();
        g_last_json_credential_operation_count = operations.size();
    }
    const char* account_address = response["accounts"][0]["address"] | "";
    snprintf(g_last_json_account_address, sizeof(g_last_json_account_address), "%s", account_address);
    const char* account_public_key = response["accounts"][0]["publicKey"] | "";
    snprintf(g_last_json_account_public_key, sizeof(g_last_json_account_public_key), "%s", account_public_key);
    const char* account_key_scheme = response["accounts"][0]["keyScheme"] | "";
    snprintf(g_last_json_account_key_scheme, sizeof(g_last_json_account_key_scheme), "%s", account_key_scheme);
    const char* account_derivation_path = response["accounts"][0]["derivationPath"] | "";
    snprintf(
        g_last_json_account_derivation_path,
        sizeof(g_last_json_account_derivation_path),
        "%s",
        account_derivation_path);
    JsonVariant sponsored_transactions = response["accounts"][0]["sponsoredTransactions"];
    g_last_json_sponsored_transactions_present = !sponsored_transactions.isNull();
    g_last_json_accept_gas_sponsor =
        sponsored_transactions["acceptGasSponsor"] | false;
    const char* capability_key_scheme = response["chains"][0]["accounts"][0]["keyScheme"] | "";
    snprintf(
        g_last_json_capability_key_scheme,
        sizeof(g_last_json_capability_key_scheme),
        "%s",
        capability_key_scheme);
    const char* capability_derivation_path =
        response["chains"][0]["accounts"][0]["derivationPath"] | "";
    snprintf(
        g_last_json_capability_derivation_path,
        sizeof(g_last_json_capability_derivation_path),
        "%s",
        capability_derivation_path);
    const char* policy_id = response["policy"]["policyId"] | "";
    snprintf(g_last_json_policy_id, sizeof(g_last_json_policy_id), "%s", policy_id);
    const char* where_type =
        response["policy"]["blockchains"][0]["networks"][0]["policies"][0]["conditions"][0]["where"]["type"] | "";
    snprintf(g_last_json_condition_where_type, sizeof(g_last_json_condition_where_type), "%s", where_type);
    g_last_json_policy_count = response["policy"]["policyCount"] | 0;
    g_last_json_policy_condition_count = response["policy"]["conditionCount"] | 0;
    return g_write_json_ok;
}

}  // namespace agent_q

namespace {

bool write_error(const char* id, const char* code, const char* message)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
    g_last_error_message = message;
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

bool write_busy(const char* id)
{
    g_busy_calls += 1;
    g_last_id = id;
    return g_busy;
}

bool write_payload_admission_error(
    const char* id,
    agent_q::AgentQUsbOperationType operation)
{
    assert(operation == agent_q::AgentQUsbOperationType::get_capabilities ||
           operation == agent_q::AgentQUsbOperationType::get_accounts ||
           operation == agent_q::AgentQUsbOperationType::policy_get);
    g_payload_admission_calls += 1;
    g_last_id = id;
    if (g_payload_admission_error) {
        write_error(id, "busy", "Device has a pending signable payload.");
        return true;
    }
    return false;
}

bool require_session(const char* id, const char* session_id)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    return g_session_valid;
}

bool read_signing_mode(agent_q::AgentQSigningAuthorizationMode* mode)
{
    g_read_mode_calls += 1;
    *mode = agent_q::AgentQSigningAuthorizationMode::policy;
    return g_read_mode_ok;
}

bool read_sui_account_settings(agent_q::AgentQSuiAccountSettings* settings)
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

agent_q::AgentQSuiActiveIdentity resolve_active_identity()
{
    g_resolve_active_identity_calls += 1;
    agent_q::AgentQSuiActiveIdentity identity = {};
    identity.kind = g_active_identity_kind;
    identity.error = g_active_identity_error;
    if (identity.kind == agent_q::AgentQSuiActiveIdentityKind::native) {
        snprintf(
            identity.address,
            sizeof(identity.address),
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        identity.public_key[0] = agent_q::kAgentQSuiSignatureSchemeFlagEd25519;
        memset(identity.public_key + 1, 7, agent_q::kSuiEd25519PublicKeyBytes);
        identity.public_key_size = agent_q::kAgentQSuiSchemePrefixedEd25519PublicKeyBytes;
    } else if (identity.kind == agent_q::AgentQSuiActiveIdentityKind::zklogin) {
        snprintf(
            identity.address,
            sizeof(identity.address),
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        identity.public_key[0] = agent_q::kAgentQSuiSignatureSchemeFlagZkLogin;
        memset(identity.public_key + 1, 1, 59);
        identity.public_key_size = 60;
    }
    return identity;
}

void record_root_material_unreadable()
{
    g_record_root_material_unreadable_calls += 1;
}

bool read_active_policy(
    const char** schema,
    char* policy_id_out,
    size_t policy_id_out_size,
    const char** default_action,
    size_t* blockchain_count,
    size_t* network_count,
    size_t* policy_count,
    size_t* condition_count,
    const agent_q::AgentQCurrentPolicyDocument** document)
{
    g_read_policy_calls += 1;
    if (!g_read_policy_ok) {
        return false;
    }
    *schema = agent_q::kAgentQCurrentPolicySchema;
    snprintf(policy_id_out, policy_id_out_size, "sha256:test");
    *default_action = "reject";
    size_t counted_networks = 0;
    size_t counted_policies = 0;
    size_t counted_conditions = 0;
    count_policy_document(
        g_policy_document,
        &counted_networks,
        &counted_policies,
        &counted_conditions);
    *blockchain_count = g_policy_document.blockchain_count;
    *network_count = counted_networks;
    *policy_count = counted_policies;
    *condition_count = counted_conditions;
    *document = g_policy_has_document ? &g_policy_document : nullptr;
    return true;
}

void record_policy_unavailable()
{
    g_record_policy_unavailable_calls += 1;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbSessionReadHandlerOps make_ops()
{
    return agent_q::AgentQUsbSessionReadHandlerOps{
        material_ready,
        write_busy,
        write_payload_admission_error,
        require_session,
        read_signing_mode,
        read_sui_account_settings,
        sui_zklogin_credential_available,
        resolve_active_identity,
        record_root_material_unreadable,
        read_active_policy,
        record_policy_unavailable,
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
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
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
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_material_calls == 1);
        assert(g_busy_calls == 1);
        assert(g_payload_admission_calls == 0);
        assert(g_write_error_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        g_payload_admission_error = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
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
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":7}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_require_session_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_payload_admission_calls == 1);
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "get_capabilities request contains unsupported fields.") == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        g_read_mode_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_read_mode_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_write_json_calls == 0);
        assert(g_sui_zklogin_credential_available_calls == 0);
        assert(g_resolve_active_identity_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_read_mode_calls == 1);
        assert(g_resolve_active_identity_calls == 1);
        assert(g_sui_zklogin_credential_available_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "capabilities") == 0);
        assert(strcmp(g_last_json_auth, "policy") == 0);
        assert(strcmp(g_last_json_capability_key_scheme, "ed25519") == 0);
        assert(strcmp(g_last_json_capability_derivation_path, "m/44'/784'/0'/0'/0'") == 0);
        assert(g_last_json_signing_method_count == 1);
        assert(strcmp(g_last_payload_kind, "transaction") == 0);
        assert(strcmp(g_last_payload_inline_max, "384") == 0);
        assert(strcmp(g_last_payload_chunk_max, "2700") == 0);
        assert(strcmp(g_last_payload_max, "131072") == 0);
        assert(g_last_json_credential_count == 1);
        assert(g_last_json_credential_operation_count == 2);
    }

    {
        reset_state();
        g_active_identity_kind = agent_q::AgentQSuiActiveIdentityKind::zklogin;
        g_sui_zklogin_credential_available = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_resolve_active_identity_calls == 1);
        assert(g_sui_zklogin_credential_available_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_capability_key_scheme, "zklogin") == 0);
        assert(strcmp(g_last_json_capability_derivation_path, "") == 0);
        assert(g_last_json_credential_count == 0);
    }

    {
        reset_state();
        g_active_identity_kind = agent_q::AgentQSuiActiveIdentityKind::error;
        g_active_identity_error = agent_q::AgentQSuiActiveIdentityError::proof_storage_error;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_resolve_active_identity_calls == 1);
        assert(g_sui_zklogin_credential_available_calls == 0);
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_error") == 0);
        assert(g_record_root_material_unreadable_calls == 0);
    }

    {
        reset_state();
        g_write_json_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_json_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_write_error_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "accounts") == 0);
        assert(strcmp(g_last_json_account_address, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef") == 0);
        assert(strcmp(g_last_json_account_public_key, "AAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH") == 0);
        assert(strcmp(g_last_json_account_key_scheme, "ed25519") == 0);
        assert(strcmp(g_last_json_account_derivation_path, "m/44'/784'/0'/0'/0'") == 0);
        assert(g_last_json_sponsored_transactions_present);
        assert(!g_last_json_accept_gas_sponsor);
    }

    {
        reset_state();
        g_active_identity_kind = agent_q::AgentQSuiActiveIdentityKind::zklogin;
        g_accept_gas_sponsor = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
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
        g_active_identity_kind = agent_q::AgentQSuiActiveIdentityKind::error;
        g_active_identity_error = agent_q::AgentQSuiActiveIdentityError::proof_storage_error;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 0);
        assert(g_record_root_material_unreadable_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_error") == 0);
    }

    {
        reset_state();
        g_active_identity_kind = agent_q::AgentQSuiActiveIdentityKind::error;
        g_active_identity_error = agent_q::AgentQSuiActiveIdentityError::native_account_unavailable;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 0);
        assert(g_record_root_material_unreadable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_error") == 0);
    }

    {
        reset_state();
        g_read_sui_account_settings_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_resolve_active_identity_calls == 1);
        assert(g_read_sui_account_settings_calls == 1);
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_error") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "get_accounts request contains unsupported fields.") == 0);
        assert(g_resolve_active_identity_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_read_policy_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "policy") == 0);
        assert(strcmp(g_last_json_policy_id, "sha256:test") == 0);
        assert(g_last_json_policy_count == 0);
        assert(g_last_json_policy_condition_count == 0);
        assert(g_record_policy_unavailable_calls == 0);
    }

    {
        reset_state();
        constexpr const char* kSuiTypeTag =
            "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
        const char* amount_values[] = {"1000000000"};
        const agent_q::AgentQCurrentPolicyCondition conditions[] = {
            {
                "sui.token_totals_by_type.amount_raw",
                agent_q::AgentQCurrentPolicyOperator::lte,
                amount_values,
                sizeof(amount_values) / sizeof(amount_values[0]),
                kSuiTypeTag,
            },
        };
        const agent_q::AgentQCurrentPolicy policies[] = {
            {
                "sui-testnet-max-one-sui",
                agent_q::AgentQCurrentPolicyAction::sign,
                conditions,
                sizeof(conditions) / sizeof(conditions[0]),
            },
        };
        const agent_q::AgentQCurrentPolicyNetworkScope networks[] = {
            {
                "testnet",
                policies,
                sizeof(policies) / sizeof(policies[0]),
            },
        };
        const agent_q::AgentQCurrentPolicyBlockchainScope blockchains[] = {
            {
                "sui",
                networks,
                sizeof(networks) / sizeof(networks[0]),
            },
        };
        g_policy_document = agent_q::AgentQCurrentPolicyDocument{
            agent_q::kAgentQCurrentPolicySchema,
            agent_q::AgentQCurrentPolicyAction::reject,
            blockchains,
            sizeof(blockchains) / sizeof(blockchains[0]),
        };
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_read_policy_calls == 1);
        assert(g_write_json_calls == 1);
        assert(g_last_json_policy_count == 1);
        assert(g_last_json_policy_condition_count == 1);
        assert(strcmp(g_last_json_condition_where_type, kSuiTypeTag) == 0);
    }

    {
        reset_state();
        g_read_policy_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
        assert(g_record_policy_unavailable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "policy_error") == 0);
        assert(strcmp(g_last_error_message, "Active policy is unavailable.") == 0);
    }

    {
        reset_state();
        g_policy_has_document = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
        assert(g_record_policy_unavailable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "policy_error") == 0);
    }

    {
        reset_state();
        g_write_json_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_write_error_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "policy_get request contains unsupported fields.") == 0);
        assert(g_read_policy_calls == 0);
    }

    printf("USB session-read handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_session_read_handlers.cpp" \
  "${COMMON_AGENT_Q_DIR}/policy/agent_q_policy_document.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
