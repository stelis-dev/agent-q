#include "agent_q_sign_transaction_user_flow.h"

#include <stdint.h>
#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_sui_signing_authority.h"

namespace agent_q {
namespace {

struct AgentQSignTransactionUserFlowState {
    AgentQSignTransactionUserStage stage = AgentQSignTransactionUserStage::none;
    AgentQSignTransactionUserTerminalResult terminal_result =
        AgentQSignTransactionUserTerminalResult::none;
    char request_id[kAgentQSignTransactionUserIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQSignTransactionUserChainSize] = {};
    char method[kAgentQSignTransactionUserMethodSize] = {};
    char network[kAgentQSignTransactionUserNetworkSize] = {};
    char payload_digest[kAgentQApprovalHistoryDigestSize] = {};
    TickType_t request_deadline = 0;
    TickType_t pin_input_deadline = 0;
    uint8_t tx_bytes[kAgentQSuiSignTransactionTxBytesMaxBytes] = {};
    size_t tx_bytes_size = 0;
    bool tx_bytes_available = false;
    SuiTransferFacts sui_transfer = {};

    bool active() const
    {
        return stage != AgentQSignTransactionUserStage::none;
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
        stage = AgentQSignTransactionUserStage::none;
        terminal_result = AgentQSignTransactionUserTerminalResult::none;
        request_id[0] = '\0';
        session_id[0] = '\0';
        chain[0] = '\0';
        method[0] = '\0';
        network[0] = '\0';
        payload_digest[0] = '\0';
        request_deadline = 0;
        pin_input_deadline = 0;
        memset(&sui_transfer, 0, sizeof(sui_transfer));
    }

    void terminalize(AgentQSignTransactionUserTerminalResult result)
    {
        wipe_payload();
        terminal_result = result;
        stage = AgentQSignTransactionUserStage::terminal;
        request_deadline = 0;
        pin_input_deadline = 0;
    }
};

AgentQSignTransactionUserFlowState g_state;
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

bool tick_reached(TickType_t deadline, TickType_t now)
{
    return deadline != 0 &&
           static_cast<int32_t>(now - deadline) >= 0;
}

TickType_t cap_to_request_deadline(TickType_t deadline)
{
    if (g_state.request_deadline == 0) {
        return deadline;
    }
    return tick_reached(g_state.request_deadline, deadline)
               ? g_state.request_deadline
               : deadline;
}

bool any_deadline_reached(TickType_t now)
{
    return tick_reached(g_state.request_deadline, now) ||
           tick_reached(g_state.pin_input_deadline, now);
}

bool rejectable_stage(AgentQSignTransactionUserStage stage)
{
    return stage == AgentQSignTransactionUserStage::reviewing ||
           stage == AgentQSignTransactionUserStage::pin_entry;
}

bool precritical_cleanup_stage(AgentQSignTransactionUserStage stage)
{
    return stage == AgentQSignTransactionUserStage::reviewing ||
           stage == AgentQSignTransactionUserStage::pin_entry ||
           stage == AgentQSignTransactionUserStage::history_write;
}

AgentQSignTransactionUserTransitionResult terminalize_if_rejectable(
    AgentQSignTransactionUserTerminalResult result)
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage == AgentQSignTransactionUserStage::signing_critical_section) {
        return AgentQSignTransactionUserTransitionResult::busy;
    }
    if (!rejectable_stage(g_state.stage)) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult terminalize_if_precritical_cleanup(
    AgentQSignTransactionUserTerminalResult result)
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage == AgentQSignTransactionUserStage::signing_critical_section) {
        return AgentQSignTransactionUserTransitionResult::busy;
    }
    if (!precritical_cleanup_stage(g_state.stage)) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult terminalize_invalid_session()
{
    g_state.terminalize(AgentQSignTransactionUserTerminalResult::canceled);
    return AgentQSignTransactionUserTransitionResult::invalid_session;
}

AgentQSignTransactionUserTransitionResult require_active_session()
{
    if (session_validate(g_state.session_id) != AgentQSessionValidationResult::ok) {
        return terminalize_invalid_session();
    }
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult terminalize_if_deadline_expired(TickType_t now)
{
    if (any_deadline_reached(now)) {
        g_state.terminalize(AgentQSignTransactionUserTerminalResult::timed_out);
        return AgentQSignTransactionUserTransitionResult::deadline_expired;
    }
    return AgentQSignTransactionUserTransitionResult::ok;
}

bool same_history_write_request(const AgentQSignTransactionUserFlowSnapshot& snapshot)
{
    return g_state.active() &&
           snapshot.active &&
           snapshot.stage == AgentQSignTransactionUserStage::history_write &&
           g_state.stage == AgentQSignTransactionUserStage::history_write &&
           strcmp(g_state.request_id, snapshot.request_id) == 0 &&
           strcmp(g_state.session_id, snapshot.session_id) == 0 &&
           strcmp(g_state.chain, snapshot.chain) == 0 &&
           strcmp(g_state.method, snapshot.method) == 0 &&
           strcmp(g_state.network, snapshot.network) == 0 &&
           strcmp(g_state.payload_digest, snapshot.payload_digest) == 0 &&
           g_state.tx_bytes_size == snapshot.signable_payload_size &&
           g_state.tx_bytes_available == snapshot.signable_payload_available;
}

}  // namespace

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_clear()
{
    if (g_state.stage == AgentQSignTransactionUserStage::signing_critical_section) {
        return AgentQSignTransactionUserTransitionResult::busy;
    }
    const bool was_active = g_state.active();
    g_state.clear();
    return was_active ? AgentQSignTransactionUserTransitionResult::ok
                      : AgentQSignTransactionUserTransitionResult::inactive;
}

bool sign_transaction_user_flow_active()
{
    return g_state.active();
}

bool sign_transaction_user_flow_in_signing_critical_section()
{
    return g_state.stage == AgentQSignTransactionUserStage::signing_critical_section;
}

bool sign_transaction_user_flow_session_matches(const char* session_id)
{
    return g_state.active() &&
           session_id != nullptr &&
           g_state.session_id[0] != '\0' &&
           strcmp(g_state.session_id, session_id) == 0;
}

AgentQSessionValidationResult sign_transaction_user_flow_validate_session()
{
    if (!g_state.active() || g_state.session_id[0] == '\0') {
        return AgentQSessionValidationResult::missing;
    }
    return session_validate(g_state.session_id);
}

AgentQSignTransactionUserFlowSnapshot sign_transaction_user_flow_snapshot()
{
    AgentQSignTransactionUserFlowSnapshot snapshot = {};
    snapshot.active = g_state.active();
    snapshot.stage = g_state.stage;
    snapshot.terminal_result = g_state.terminal_result;
    memcpy(snapshot.request_id, g_state.request_id, sizeof(snapshot.request_id));
    memcpy(snapshot.session_id, g_state.session_id, sizeof(snapshot.session_id));
    memcpy(snapshot.chain, g_state.chain, sizeof(snapshot.chain));
    memcpy(snapshot.method, g_state.method, sizeof(snapshot.method));
    memcpy(snapshot.network, g_state.network, sizeof(snapshot.network));
    memcpy(snapshot.payload_digest, g_state.payload_digest, sizeof(snapshot.payload_digest));
    snapshot.request_deadline = g_state.request_deadline;
    snapshot.pin_input_deadline = g_state.pin_input_deadline;
    snapshot.signable_payload_size = g_state.tx_bytes_size;
    snapshot.signable_payload_available = g_state.tx_bytes_available;
    snapshot.sui_transfer = g_state.sui_transfer;
    return snapshot;
}

AgentQSignTransactionUserFlowBeginResult sign_transaction_user_flow_begin(
    const AgentQSignTransactionUserBeginInput& input)
{
    if (g_state.active()) {
        return AgentQSignTransactionUserFlowBeginResult::active;
    }
    if (input.request_id == nullptr ||
        input.session_id == nullptr ||
        input.chain == nullptr ||
        input.method == nullptr ||
        input.network == nullptr ||
        input.tx_bytes == nullptr) {
        return AgentQSignTransactionUserFlowBeginResult::invalid_argument;
    }
    if (input.request_deadline == 0) {
        return AgentQSignTransactionUserFlowBeginResult::invalid_deadline;
    }
    char request_id[kAgentQSignTransactionUserIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQSignTransactionUserChainSize] = {};
    char method[kAgentQSignTransactionUserMethodSize] = {};
    char network[kAgentQSignTransactionUserNetworkSize] = {};
    if (!copy_nonempty_c_string(input.request_id, request_id, sizeof(request_id)) ||
        !copy_nonempty_c_string(input.session_id, session_id, sizeof(session_id)) ||
        !copy_nonempty_c_string(input.chain, chain, sizeof(chain)) ||
        !copy_nonempty_c_string(input.method, method, sizeof(method)) ||
        !copy_nonempty_c_string(input.network, network, sizeof(network))) {
        return AgentQSignTransactionUserFlowBeginResult::invalid_argument;
    }
    if (session_validate(session_id) != AgentQSessionValidationResult::ok) {
        return AgentQSignTransactionUserFlowBeginResult::invalid_session;
    }
    if (strcmp(chain, "sui") != 0 ||
        strcmp(method, "sign_transaction") != 0) {
        return AgentQSignTransactionUserFlowBeginResult::unsupported_method;
    }
    if (!supported_network(network)) {
        return AgentQSignTransactionUserFlowBeginResult::invalid_network;
    }
    if (input.tx_bytes_size == 0 ||
        input.tx_bytes_size > kAgentQSuiSignTransactionTxBytesMaxBytes) {
        return AgentQSignTransactionUserFlowBeginResult::invalid_payload;
    }

    SuiTransferFacts parsed_facts = {};
    if (parse_sui_transfer_facts(
            input.tx_bytes,
            input.tx_bytes_size,
            &parsed_facts) != SuiTransactionFactsResult::ok) {
        return AgentQSignTransactionUserFlowBeginResult::invalid_transaction;
    }
    if (!summary_valid(parsed_facts)) {
        return AgentQSignTransactionUserFlowBeginResult::invalid_summary;
    }
    const AgentQSuiSigningAccountBindingResult account_result =
        verify_sui_signing_stored_account_binding(parsed_facts);
    if (account_result != AgentQSuiSigningAccountBindingResult::ok) {
        return account_result == AgentQSuiSigningAccountBindingResult::account_unavailable
                   ? AgentQSignTransactionUserFlowBeginResult::account_unavailable
                   : AgentQSignTransactionUserFlowBeginResult::invalid_account;
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
        return AgentQSignTransactionUserFlowBeginResult::digest_error;
    }
    memcpy(g_state.tx_bytes, input.tx_bytes, input.tx_bytes_size);
    g_state.tx_bytes_size = input.tx_bytes_size;
    g_state.tx_bytes_available = true;
    g_state.sui_transfer = parsed_facts;
    g_state.request_deadline = input.request_deadline;
    g_state.pin_input_deadline = 0;
    g_state.stage = AgentQSignTransactionUserStage::reviewing;
    return AgentQSignTransactionUserFlowBeginResult::ok;
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_accept_review(
    TickType_t now,
    TickType_t pin_deadline)
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignTransactionUserStage::reviewing) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    if (pin_deadline == 0) {
        return AgentQSignTransactionUserTransitionResult::invalid_deadline;
    }
    AgentQSignTransactionUserTransitionResult guard = require_active_session();
    if (guard != AgentQSignTransactionUserTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQSignTransactionUserTransitionResult::ok) {
        return guard;
    }
    const TickType_t capped_pin_deadline = cap_to_request_deadline(pin_deadline);
    if (tick_reached(capped_pin_deadline, now)) {
        g_state.terminalize(AgentQSignTransactionUserTerminalResult::timed_out);
        return AgentQSignTransactionUserTransitionResult::deadline_expired;
    }
    g_state.stage = AgentQSignTransactionUserStage::pin_entry;
    g_state.pin_input_deadline = capped_pin_deadline;
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_refresh_pin_deadline(
    TickType_t pin_deadline)
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignTransactionUserStage::pin_entry) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    if (pin_deadline == 0) {
        return AgentQSignTransactionUserTransitionResult::invalid_deadline;
    }
    const AgentQSignTransactionUserTransitionResult guard = require_active_session();
    if (guard != AgentQSignTransactionUserTransitionResult::ok) {
        return guard;
    }
    g_state.pin_input_deadline = cap_to_request_deadline(pin_deadline);
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_pause_pin_deadline()
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignTransactionUserStage::pin_entry) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    const AgentQSignTransactionUserTransitionResult guard = require_active_session();
    if (guard != AgentQSignTransactionUserTransitionResult::ok) {
        return guard;
    }
    g_state.pin_input_deadline = 0;
    return AgentQSignTransactionUserTransitionResult::ok;
}

bool sign_transaction_user_flow_deadline_reached(TickType_t now)
{
    return g_state.active() && any_deadline_reached(now);
}

AgentQSignTransactionUserTransitionResult
sign_transaction_user_flow_record_pin_verified_and_write_confirmation_history(
    TickType_t now,
    AgentQSignTransactionUserHistoryWriteFn write_fn,
    void* context)
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignTransactionUserStage::pin_entry) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    if (write_fn == nullptr) {
        return AgentQSignTransactionUserTransitionResult::invalid_argument;
    }
    if (g_state.pin_input_deadline != 0) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    AgentQSignTransactionUserTransitionResult guard = require_active_session();
    if (guard != AgentQSignTransactionUserTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQSignTransactionUserTransitionResult::ok) {
        return guard;
    }
    g_state.stage = AgentQSignTransactionUserStage::history_write;
    g_state.pin_input_deadline = 0;

    guard = require_active_session();
    if (guard != AgentQSignTransactionUserTransitionResult::ok) {
        return guard;
    }
    const AgentQSignTransactionUserFlowSnapshot snapshot =
        sign_transaction_user_flow_snapshot();
    const bool write_ok = write_fn(snapshot, context);
    if (!same_history_write_request(snapshot)) {
        return AgentQSignTransactionUserTransitionResult::stale_state;
    }
    if (!write_ok) {
        g_state.terminalize(AgentQSignTransactionUserTerminalResult::history_error);
        return AgentQSignTransactionUserTransitionResult::history_error;
    }
    g_state.stage = AgentQSignTransactionUserStage::signing_critical_section;
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_consume_signable_payload(
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
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignTransactionUserStage::signing_critical_section) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    if (!g_state.tx_bytes_available || g_state.tx_bytes_size == 0) {
        return AgentQSignTransactionUserTransitionResult::payload_unavailable;
    }
    if (output == nullptr || output_capacity < g_state.tx_bytes_size || output_size == nullptr) {
        return AgentQSignTransactionUserTransitionResult::output_too_small;
    }
    memcpy(output, g_state.tx_bytes, g_state.tx_bytes_size);
    *output_size = g_state.tx_bytes_size;
    g_state.wipe_payload();
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_record_device_rejected()
{
    return terminalize_if_rejectable(AgentQSignTransactionUserTerminalResult::rejected);
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_record_timeout(TickType_t now)
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage == AgentQSignTransactionUserStage::signing_critical_section) {
        return AgentQSignTransactionUserTransitionResult::busy;
    }
    if (g_state.stage != AgentQSignTransactionUserStage::reviewing &&
        g_state.stage != AgentQSignTransactionUserStage::pin_entry) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    if (!any_deadline_reached(now)) {
        return AgentQSignTransactionUserTransitionResult::deadline_not_reached;
    }
    g_state.terminalize(AgentQSignTransactionUserTerminalResult::timed_out);
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_record_signing_failed()
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignTransactionUserStage::signing_critical_section) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    g_state.terminalize(AgentQSignTransactionUserTerminalResult::signing_failed);
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_complete_signed()
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage != AgentQSignTransactionUserStage::signing_critical_section) {
        return AgentQSignTransactionUserTransitionResult::wrong_stage;
    }
    if (g_state.tx_bytes_available) {
        return AgentQSignTransactionUserTransitionResult::payload_not_consumed;
    }
    g_state.terminalize(AgentQSignTransactionUserTerminalResult::signed_success);
    return AgentQSignTransactionUserTransitionResult::ok;
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_cancel_for_disconnect(
    const char* session_id)
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (!sign_transaction_user_flow_session_matches(session_id)) {
        return AgentQSignTransactionUserTransitionResult::invalid_session;
    }
    return terminalize_if_precritical_cleanup(AgentQSignTransactionUserTerminalResult::canceled);
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_cancel_for_session_loss()
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    if (g_state.stage == AgentQSignTransactionUserStage::signing_critical_section) {
        return AgentQSignTransactionUserTransitionResult::busy;
    }
    if (session_validate(g_state.session_id) == AgentQSessionValidationResult::ok) {
        return AgentQSignTransactionUserTransitionResult::session_still_active;
    }
    return terminalize_if_precritical_cleanup(AgentQSignTransactionUserTerminalResult::canceled);
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_cancel_for_ui_loss()
{
    if (!g_state.active()) {
        return AgentQSignTransactionUserTransitionResult::inactive;
    }
    return terminalize_if_precritical_cleanup(AgentQSignTransactionUserTerminalResult::canceled);
}

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_cancel_for_pin_loss()
{
    return sign_transaction_user_flow_cancel_for_ui_loss();
}

bool sign_transaction_user_flow_terminal_pending()
{
    return g_state.stage == AgentQSignTransactionUserStage::terminal &&
           g_state.terminal_result != AgentQSignTransactionUserTerminalResult::none;
}

bool sign_transaction_user_flow_consume_terminal_result(
    AgentQSignTransactionUserTerminalResult* output)
{
    if (!sign_transaction_user_flow_terminal_pending() || output == nullptr) {
        return false;
    }
    *output = g_state.terminal_result;
    g_state.clear();
    return true;
}

const char* sign_transaction_user_flow_terminal_status(
    AgentQSignTransactionUserTerminalResult result)
{
    switch (result) {
        case AgentQSignTransactionUserTerminalResult::signed_success:
            return "signed";
        case AgentQSignTransactionUserTerminalResult::rejected:
            return "user_rejected";
        case AgentQSignTransactionUserTerminalResult::timed_out:
            return "user_timed_out";
        case AgentQSignTransactionUserTerminalResult::signing_failed:
            return "signing_failed";
        case AgentQSignTransactionUserTerminalResult::canceled:
        case AgentQSignTransactionUserTerminalResult::history_error:
            return "";
        case AgentQSignTransactionUserTerminalResult::none:
        default:
            return "";
    }
}

const char* sign_transaction_user_flow_terminal_reason(
    AgentQSignTransactionUserTerminalResult result)
{
    switch (result) {
        case AgentQSignTransactionUserTerminalResult::signed_success:
            return "device_confirmed";
        case AgentQSignTransactionUserTerminalResult::rejected:
            return "user_rejected";
        case AgentQSignTransactionUserTerminalResult::timed_out:
            return "user_timed_out";
        case AgentQSignTransactionUserTerminalResult::signing_failed:
            return "signing_failed";
        case AgentQSignTransactionUserTerminalResult::canceled:
        case AgentQSignTransactionUserTerminalResult::history_error:
            return "";
        case AgentQSignTransactionUserTerminalResult::none:
        default:
            return "";
    }
}

}  // namespace agent_q
