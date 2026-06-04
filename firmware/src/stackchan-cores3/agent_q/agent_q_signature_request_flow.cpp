#include "agent_q_signature_request_flow.h"

#include <stdint.h>
#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_sui_account_store.h"

namespace agent_q {
namespace {

struct AgentQSignatureRequestFlowState {
    AgentQSignatureRequestStage stage = AgentQSignatureRequestStage::none;
    AgentQSignatureRequestTerminalResult terminal_result =
        AgentQSignatureRequestTerminalResult::none;
    char request_id[kAgentQSignatureRequestIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQSignatureRequestChainSize] = {};
    char method[kAgentQSignatureRequestMethodSize] = {};
    char network[kAgentQSignatureRequestNetworkSize] = {};
    char payload_digest[kAgentQApprovalHistoryDigestSize] = {};
    TickType_t deadline = 0;
    TickType_t confirmation_deadline = 0;
    uint8_t tx_bytes[kAgentQSuiSignTransactionTxBytesMaxBytes] = {};
    size_t tx_bytes_size = 0;
    bool tx_bytes_available = false;
    SuiTransferFacts sui_transfer = {};

    bool active() const
    {
        return stage != AgentQSignatureRequestStage::none;
    }

    void wipe_payload()
    {
        wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
        tx_bytes_size = 0;
        tx_bytes_available = false;
    }

    void clear()
    {
        wipe_payload();
        stage = AgentQSignatureRequestStage::none;
        terminal_result = AgentQSignatureRequestTerminalResult::none;
        request_id[0] = '\0';
        session_id[0] = '\0';
        chain[0] = '\0';
        method[0] = '\0';
        network[0] = '\0';
        payload_digest[0] = '\0';
        deadline = 0;
        confirmation_deadline = 0;
        memset(&sui_transfer, 0, sizeof(sui_transfer));
    }

    void terminalize(AgentQSignatureRequestTerminalResult result)
    {
        wipe_payload();
        terminal_result = result;
        stage = AgentQSignatureRequestStage::terminal;
        deadline = 0;
        confirmation_deadline = 0;
    }
};

AgentQSignatureRequestFlowState g_state;
constexpr const char* kSuiAsset = "0x2::sui::SUI";
constexpr size_t kSuiAddressHexLength = 64;
constexpr size_t kSuiAddressStringLength = 2 + kSuiAddressHexLength;
constexpr uint16_t kRestrictedSuiTransferCommandCount = 2;

bool copy_nonempty_c_string(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || input[0] == '\0' || output == nullptr || output_size == 0) {
        return false;
    }
    size_t index = 0;
    while (input[index] != '\0' && index + 1 < output_size) {
        output[index] = input[index];
        ++index;
    }
    if (input[index] != '\0') {
        output[0] = '\0';
        return false;
    }
    output[index] = '\0';
    return true;
}

bool supported_network(const char* network)
{
    return network != nullptr &&
           (strcmp(network, "mainnet") == 0 ||
            strcmp(network, "testnet") == 0 ||
            strcmp(network, "devnet") == 0 ||
            strcmp(network, "localnet") == 0);
}

bool bounded_string_present(const char* value, size_t value_size)
{
    return value != nullptr &&
           value_size > 0 &&
           value[0] != '\0' &&
           memchr(value, '\0', value_size) != nullptr;
}

bool decimal_string_valid(const char* value, size_t value_size)
{
    if (!bounded_string_present(value, value_size)) {
        return false;
    }
    for (size_t index = 0; value[index] != '\0'; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return true;
}

bool hex_char(char value)
{
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

bool sui_address_valid(const char* value, size_t value_size)
{
    if (!bounded_string_present(value, value_size)) {
        return false;
    }
    if (strlen(value) != kSuiAddressStringLength ||
        value[0] != '0' ||
        value[1] != 'x') {
        return false;
    }
    for (size_t index = 2; value[index] != '\0'; ++index) {
        if (!hex_char(value[index])) {
            return false;
        }
    }
    return true;
}

bool summary_valid(const SuiTransferFacts& facts)
{
    return sui_address_valid(facts.sender, sizeof(facts.sender)) &&
           sui_address_valid(facts.gas_owner, sizeof(facts.gas_owner)) &&
           sui_address_valid(facts.recipient, sizeof(facts.recipient)) &&
           bounded_string_present(facts.asset, sizeof(facts.asset)) &&
           strcmp(facts.asset, kSuiAsset) == 0 &&
           decimal_string_valid(facts.amount, sizeof(facts.amount)) &&
           decimal_string_valid(facts.gas_budget, sizeof(facts.gas_budget)) &&
           decimal_string_valid(facts.gas_price, sizeof(facts.gas_price)) &&
           facts.command_count == kRestrictedSuiTransferCommandCount;
}

AgentQSignatureRequestFlowBeginResult verify_stored_account_binding(
    const SuiTransferFacts& facts)
{
    uint8_t public_key[kSuiEd25519PublicKeyBytes] = {};
    char stored_address[kSuiAddressBufferSize] = {};
    const SuiAccountDerivationResult result =
        derive_sui_ed25519_account_from_stored_root(
            public_key,
            stored_address,
            sizeof(stored_address));
    wipe_sensitive_buffer(public_key, sizeof(public_key));
    if (result != SuiAccountDerivationResult::ok) {
        memset(stored_address, 0, sizeof(stored_address));
        return AgentQSignatureRequestFlowBeginResult::account_unavailable;
    }
    const bool matches =
        strcmp(facts.sender, stored_address) == 0 &&
        strcmp(facts.gas_owner, stored_address) == 0;
    memset(stored_address, 0, sizeof(stored_address));
    return matches ? AgentQSignatureRequestFlowBeginResult::ok
                   : AgentQSignatureRequestFlowBeginResult::invalid_account;
}

bool tick_reached(TickType_t deadline, TickType_t now)
{
    return deadline != 0 &&
           static_cast<int32_t>(now - deadline) >= 0;
}

TickType_t cap_deadline(TickType_t deadline, TickType_t cap)
{
    if (deadline == 0 || cap == 0) {
        return deadline;
    }
    return tick_reached(cap, deadline) ? cap : deadline;
}

bool any_deadline_reached(TickType_t now)
{
    return tick_reached(g_state.confirmation_deadline, now) ||
           tick_reached(g_state.deadline, now);
}

bool rejectable_stage(AgentQSignatureRequestStage stage)
{
    return stage == AgentQSignatureRequestStage::reviewing ||
           stage == AgentQSignatureRequestStage::pin_entry;
}

bool precritical_cleanup_stage(AgentQSignatureRequestStage stage)
{
    return stage == AgentQSignatureRequestStage::reviewing ||
           stage == AgentQSignatureRequestStage::pin_entry ||
           stage == AgentQSignatureRequestStage::history_write;
}

AgentQSignatureRequestTransitionResult terminalize_if_rejectable(
    AgentQSignatureRequestTerminalResult result)
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage == AgentQSignatureRequestStage::signing_critical_section) {
        return AgentQSignatureRequestTransitionResult::busy;
    }
    if (!rejectable_stage(g_state.stage)) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return AgentQSignatureRequestTransitionResult::ok;
}

AgentQSignatureRequestTransitionResult terminalize_if_precritical_cleanup(
    AgentQSignatureRequestTerminalResult result)
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage == AgentQSignatureRequestStage::signing_critical_section) {
        return AgentQSignatureRequestTransitionResult::busy;
    }
    if (!precritical_cleanup_stage(g_state.stage)) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return AgentQSignatureRequestTransitionResult::ok;
}

AgentQSignatureRequestTransitionResult terminalize_invalid_session()
{
    g_state.terminalize(AgentQSignatureRequestTerminalResult::canceled);
    return AgentQSignatureRequestTransitionResult::invalid_session;
}

AgentQSignatureRequestTransitionResult require_active_session()
{
    if (session_validate(g_state.session_id) != AgentQSessionValidationResult::ok) {
        return terminalize_invalid_session();
    }
    return AgentQSignatureRequestTransitionResult::ok;
}

AgentQSignatureRequestTransitionResult terminalize_if_deadline_expired(TickType_t now)
{
    if (any_deadline_reached(now)) {
        g_state.terminalize(AgentQSignatureRequestTerminalResult::timed_out);
        return AgentQSignatureRequestTransitionResult::deadline_expired;
    }
    return AgentQSignatureRequestTransitionResult::ok;
}

bool same_history_write_request(const AgentQSignatureRequestFlowSnapshot& snapshot)
{
    return g_state.active() &&
           snapshot.active &&
           snapshot.stage == AgentQSignatureRequestStage::history_write &&
           g_state.stage == AgentQSignatureRequestStage::history_write &&
           strcmp(g_state.request_id, snapshot.request_id) == 0 &&
           strcmp(g_state.session_id, snapshot.session_id) == 0 &&
           strcmp(g_state.chain, snapshot.chain) == 0 &&
           strcmp(g_state.method, snapshot.method) == 0 &&
           strcmp(g_state.network, snapshot.network) == 0 &&
           strcmp(g_state.payload_digest, snapshot.payload_digest) == 0 &&
           g_state.confirmation_deadline == snapshot.confirmation_deadline &&
           g_state.tx_bytes_size == snapshot.signable_payload_size &&
           g_state.tx_bytes_available == snapshot.signable_payload_available;
}

}  // namespace

AgentQSignatureRequestTransitionResult signature_request_flow_clear()
{
    if (g_state.stage == AgentQSignatureRequestStage::signing_critical_section) {
        return AgentQSignatureRequestTransitionResult::busy;
    }
    const bool was_active = g_state.active();
    g_state.clear();
    return was_active ? AgentQSignatureRequestTransitionResult::ok
                      : AgentQSignatureRequestTransitionResult::inactive;
}

bool signature_request_flow_active()
{
    return g_state.active();
}

bool signature_request_flow_in_signing_critical_section()
{
    return g_state.stage == AgentQSignatureRequestStage::signing_critical_section;
}

bool signature_request_flow_session_matches(const char* session_id)
{
    return g_state.active() &&
           session_id != nullptr &&
           g_state.session_id[0] != '\0' &&
           strcmp(g_state.session_id, session_id) == 0;
}

AgentQSessionValidationResult signature_request_flow_validate_session()
{
    if (!g_state.active() || g_state.session_id[0] == '\0') {
        return AgentQSessionValidationResult::missing;
    }
    return session_validate(g_state.session_id);
}

AgentQSignatureRequestFlowSnapshot signature_request_flow_snapshot()
{
    AgentQSignatureRequestFlowSnapshot snapshot = {};
    snapshot.active = g_state.active();
    snapshot.stage = g_state.stage;
    snapshot.terminal_result = g_state.terminal_result;
    memcpy(snapshot.request_id, g_state.request_id, sizeof(snapshot.request_id));
    memcpy(snapshot.session_id, g_state.session_id, sizeof(snapshot.session_id));
    memcpy(snapshot.chain, g_state.chain, sizeof(snapshot.chain));
    memcpy(snapshot.method, g_state.method, sizeof(snapshot.method));
    memcpy(snapshot.network, g_state.network, sizeof(snapshot.network));
    memcpy(snapshot.payload_digest, g_state.payload_digest, sizeof(snapshot.payload_digest));
    snapshot.deadline = g_state.deadline;
    snapshot.confirmation_deadline = g_state.confirmation_deadline;
    snapshot.signable_payload_size = g_state.tx_bytes_size;
    snapshot.signable_payload_available = g_state.tx_bytes_available;
    snapshot.sui_transfer = g_state.sui_transfer;
    return snapshot;
}

AgentQSignatureRequestFlowBeginResult signature_request_flow_begin(
    const AgentQSignatureRequestBeginInput& input)
{
    if (g_state.active()) {
        return AgentQSignatureRequestFlowBeginResult::active;
    }
    if (input.request_id == nullptr ||
        input.session_id == nullptr ||
        input.chain == nullptr ||
        input.method == nullptr ||
        input.network == nullptr ||
        input.tx_bytes == nullptr) {
        return AgentQSignatureRequestFlowBeginResult::invalid_argument;
    }
    if (input.deadline == 0) {
        return AgentQSignatureRequestFlowBeginResult::invalid_deadline;
    }
    char request_id[kAgentQSignatureRequestIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQSignatureRequestChainSize] = {};
    char method[kAgentQSignatureRequestMethodSize] = {};
    char network[kAgentQSignatureRequestNetworkSize] = {};
    if (!copy_nonempty_c_string(input.request_id, request_id, sizeof(request_id)) ||
        !copy_nonempty_c_string(input.session_id, session_id, sizeof(session_id)) ||
        !copy_nonempty_c_string(input.chain, chain, sizeof(chain)) ||
        !copy_nonempty_c_string(input.method, method, sizeof(method)) ||
        !copy_nonempty_c_string(input.network, network, sizeof(network))) {
        return AgentQSignatureRequestFlowBeginResult::invalid_argument;
    }
    if (session_validate(session_id) != AgentQSessionValidationResult::ok) {
        return AgentQSignatureRequestFlowBeginResult::invalid_session;
    }
    if (strcmp(chain, "sui") != 0 ||
        strcmp(method, "sign_transaction") != 0) {
        return AgentQSignatureRequestFlowBeginResult::unsupported_method;
    }
    if (!supported_network(network)) {
        return AgentQSignatureRequestFlowBeginResult::invalid_network;
    }
    if (input.tx_bytes_size == 0 ||
        input.tx_bytes_size > kAgentQSuiSignTransactionTxBytesMaxBytes) {
        return AgentQSignatureRequestFlowBeginResult::invalid_payload;
    }

    SuiTransferFacts parsed_facts = {};
    if (parse_sui_transfer_facts(
            input.tx_bytes,
            input.tx_bytes_size,
            &parsed_facts) != SuiTransactionFactsResult::ok) {
        return AgentQSignatureRequestFlowBeginResult::invalid_transaction;
    }
    if (!summary_valid(parsed_facts)) {
        return AgentQSignatureRequestFlowBeginResult::invalid_summary;
    }
    const AgentQSignatureRequestFlowBeginResult account_result =
        verify_stored_account_binding(parsed_facts);
    if (account_result != AgentQSignatureRequestFlowBeginResult::ok) {
        return account_result;
    }

    g_state.clear();
    memcpy(g_state.request_id, request_id, sizeof(g_state.request_id));
    memcpy(g_state.session_id, session_id, sizeof(g_state.session_id));
    memcpy(g_state.chain, chain, sizeof(g_state.chain));
    memcpy(g_state.method, method, sizeof(g_state.method));
    memcpy(g_state.network, network, sizeof(g_state.network));
    if (!approval_history_digest_payload(
            input.tx_bytes,
            input.tx_bytes_size,
            g_state.payload_digest,
            sizeof(g_state.payload_digest))) {
        g_state.clear();
        return AgentQSignatureRequestFlowBeginResult::digest_error;
    }
    memcpy(g_state.tx_bytes, input.tx_bytes, input.tx_bytes_size);
    g_state.tx_bytes_size = input.tx_bytes_size;
    g_state.tx_bytes_available = true;
    g_state.sui_transfer = parsed_facts;
    g_state.deadline = input.deadline;
    g_state.confirmation_deadline = input.deadline;
    g_state.stage = AgentQSignatureRequestStage::reviewing;
    return AgentQSignatureRequestFlowBeginResult::ok;
}

AgentQSignatureRequestTransitionResult signature_request_flow_accept_review(
    TickType_t now,
    TickType_t pin_deadline)
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignatureRequestStage::reviewing) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    if (pin_deadline == 0) {
        return AgentQSignatureRequestTransitionResult::invalid_deadline;
    }
    AgentQSignatureRequestTransitionResult guard = require_active_session();
    if (guard != AgentQSignatureRequestTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQSignatureRequestTransitionResult::ok) {
        return guard;
    }
    if (tick_reached(pin_deadline, now)) {
        g_state.terminalize(AgentQSignatureRequestTerminalResult::timed_out);
        return AgentQSignatureRequestTransitionResult::deadline_expired;
    }
    g_state.stage = AgentQSignatureRequestStage::pin_entry;
    g_state.deadline = cap_deadline(pin_deadline, g_state.confirmation_deadline);
    return AgentQSignatureRequestTransitionResult::ok;
}

TickType_t signature_request_flow_retry_deadline(TickType_t fallback_deadline)
{
    if (!g_state.active()) {
        return fallback_deadline;
    }
    return cap_deadline(fallback_deadline, g_state.confirmation_deadline);
}

AgentQSignatureRequestTransitionResult signature_request_flow_refresh_pin_deadline(
    TickType_t pin_deadline)
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignatureRequestStage::pin_entry) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    if (pin_deadline == 0) {
        return AgentQSignatureRequestTransitionResult::invalid_deadline;
    }
    const AgentQSignatureRequestTransitionResult guard = require_active_session();
    if (guard != AgentQSignatureRequestTransitionResult::ok) {
        return guard;
    }
    g_state.deadline = cap_deadline(pin_deadline, g_state.confirmation_deadline);
    return AgentQSignatureRequestTransitionResult::ok;
}

AgentQSignatureRequestTransitionResult signature_request_flow_pause_pin_deadline()
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignatureRequestStage::pin_entry) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    const AgentQSignatureRequestTransitionResult guard = require_active_session();
    if (guard != AgentQSignatureRequestTransitionResult::ok) {
        return guard;
    }
    g_state.deadline = 0;
    return AgentQSignatureRequestTransitionResult::ok;
}

bool signature_request_flow_deadline_reached(TickType_t now)
{
    return g_state.active() && any_deadline_reached(now);
}

AgentQSignatureRequestTransitionResult
signature_request_flow_record_pin_verified_and_write_confirmation_history(
    TickType_t now,
    AgentQSignatureRequestHistoryWriteFn write_fn,
    void* context)
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignatureRequestStage::pin_entry) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    if (write_fn == nullptr) {
        return AgentQSignatureRequestTransitionResult::invalid_argument;
    }
    AgentQSignatureRequestTransitionResult guard = require_active_session();
    if (guard != AgentQSignatureRequestTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQSignatureRequestTransitionResult::ok) {
        return guard;
    }
    g_state.stage = AgentQSignatureRequestStage::history_write;
    g_state.deadline = 0;

    guard = require_active_session();
    if (guard != AgentQSignatureRequestTransitionResult::ok) {
        return guard;
    }
    const AgentQSignatureRequestFlowSnapshot snapshot =
        signature_request_flow_snapshot();
    const bool write_ok = write_fn(snapshot, context);
    if (!same_history_write_request(snapshot)) {
        return AgentQSignatureRequestTransitionResult::stale_state;
    }
    if (!write_ok) {
        g_state.terminalize(AgentQSignatureRequestTerminalResult::history_error);
        return AgentQSignatureRequestTransitionResult::history_error;
    }
    g_state.stage = AgentQSignatureRequestStage::signing_critical_section;
    g_state.confirmation_deadline = 0;
    return AgentQSignatureRequestTransitionResult::ok;
}

AgentQSignatureRequestTransitionResult signature_request_flow_consume_signable_payload(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output != nullptr && output_capacity > 0) {
        memset(output, 0, output_capacity);
    }
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignatureRequestStage::signing_critical_section) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    if (!g_state.tx_bytes_available || g_state.tx_bytes_size == 0) {
        return AgentQSignatureRequestTransitionResult::payload_unavailable;
    }
    if (output == nullptr || output_capacity < g_state.tx_bytes_size || output_size == nullptr) {
        return AgentQSignatureRequestTransitionResult::output_too_small;
    }
    memcpy(output, g_state.tx_bytes, g_state.tx_bytes_size);
    *output_size = g_state.tx_bytes_size;
    g_state.wipe_payload();
    return AgentQSignatureRequestTransitionResult::ok;
}

AgentQSignatureRequestTransitionResult signature_request_flow_record_device_rejected()
{
    return terminalize_if_rejectable(AgentQSignatureRequestTerminalResult::rejected);
}

AgentQSignatureRequestTransitionResult signature_request_flow_record_timeout(TickType_t now)
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage == AgentQSignatureRequestStage::signing_critical_section) {
        return AgentQSignatureRequestTransitionResult::busy;
    }
    if (g_state.stage != AgentQSignatureRequestStage::reviewing &&
        g_state.stage != AgentQSignatureRequestStage::pin_entry) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    if (!any_deadline_reached(now)) {
        return AgentQSignatureRequestTransitionResult::deadline_not_reached;
    }
    g_state.terminalize(AgentQSignatureRequestTerminalResult::timed_out);
    return AgentQSignatureRequestTransitionResult::ok;
}

AgentQSignatureRequestTransitionResult signature_request_flow_record_signing_failed()
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignatureRequestStage::signing_critical_section) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    g_state.terminalize(AgentQSignatureRequestTerminalResult::signing_failed);
    return AgentQSignatureRequestTransitionResult::ok;
}

AgentQSignatureRequestTransitionResult signature_request_flow_complete_signed()
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignatureRequestStage::signing_critical_section) {
        return AgentQSignatureRequestTransitionResult::wrong_stage;
    }
    if (g_state.tx_bytes_available) {
        return AgentQSignatureRequestTransitionResult::payload_not_consumed;
    }
    g_state.terminalize(AgentQSignatureRequestTerminalResult::signed_success);
    return AgentQSignatureRequestTransitionResult::ok;
}

AgentQSignatureRequestTransitionResult signature_request_flow_cancel_for_disconnect(
    const char* session_id)
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (!signature_request_flow_session_matches(session_id)) {
        return AgentQSignatureRequestTransitionResult::invalid_session;
    }
    return terminalize_if_precritical_cleanup(AgentQSignatureRequestTerminalResult::canceled);
}

AgentQSignatureRequestTransitionResult signature_request_flow_cancel_for_session_loss()
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    if (g_state.stage == AgentQSignatureRequestStage::signing_critical_section) {
        return AgentQSignatureRequestTransitionResult::busy;
    }
    if (session_validate(g_state.session_id) == AgentQSessionValidationResult::ok) {
        return AgentQSignatureRequestTransitionResult::session_still_active;
    }
    return terminalize_if_precritical_cleanup(AgentQSignatureRequestTerminalResult::canceled);
}

AgentQSignatureRequestTransitionResult signature_request_flow_cancel_for_ui_loss()
{
    if (!g_state.active()) {
        return AgentQSignatureRequestTransitionResult::inactive;
    }
    return terminalize_if_precritical_cleanup(AgentQSignatureRequestTerminalResult::canceled);
}

AgentQSignatureRequestTransitionResult signature_request_flow_cancel_for_pin_loss()
{
    return signature_request_flow_cancel_for_ui_loss();
}

bool signature_request_flow_terminal_pending()
{
    return g_state.stage == AgentQSignatureRequestStage::terminal &&
           g_state.terminal_result != AgentQSignatureRequestTerminalResult::none;
}

bool signature_request_flow_consume_terminal_result(
    AgentQSignatureRequestTerminalResult* output)
{
    if (!signature_request_flow_terminal_pending() || output == nullptr) {
        return false;
    }
    *output = g_state.terminal_result;
    g_state.clear();
    return true;
}

const char* signature_request_flow_terminal_status(
    AgentQSignatureRequestTerminalResult result)
{
    switch (result) {
        case AgentQSignatureRequestTerminalResult::signed_success:
            return "signed";
        case AgentQSignatureRequestTerminalResult::rejected:
            return "rejected";
        case AgentQSignatureRequestTerminalResult::timed_out:
            return "timed_out";
        case AgentQSignatureRequestTerminalResult::signing_failed:
            return "failed";
        case AgentQSignatureRequestTerminalResult::canceled:
        case AgentQSignatureRequestTerminalResult::history_error:
            return "";
        case AgentQSignatureRequestTerminalResult::none:
        default:
            return "";
    }
}

const char* signature_request_flow_terminal_reason(
    AgentQSignatureRequestTerminalResult result)
{
    switch (result) {
        case AgentQSignatureRequestTerminalResult::signed_success:
            return "device_confirmed";
        case AgentQSignatureRequestTerminalResult::rejected:
            return "device_rejected";
        case AgentQSignatureRequestTerminalResult::timed_out:
            return "device_timed_out";
        case AgentQSignatureRequestTerminalResult::signing_failed:
            return "signing_failed";
        case AgentQSignatureRequestTerminalResult::canceled:
        case AgentQSignatureRequestTerminalResult::history_error:
            return "";
        case AgentQSignatureRequestTerminalResult::none:
        default:
            return "";
    }
}

}  // namespace agent_q
