#include "agent_q_user_signing_flow.h"

#include <stdint.h>
#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_sui_signing_authority.h"

namespace agent_q {
namespace {

struct AgentQUserSigningFlowState {
    AgentQUserSigningStage stage = AgentQUserSigningStage::none;
    AgentQUserSigningTerminalResult terminal_result =
        AgentQUserSigningTerminalResult::none;
    AgentQSigningMethod signing_method = AgentQSigningMethod::unsupported;
    char request_id[kAgentQUserSigningIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQUserSigningChainSize] = {};
    char method[kAgentQUserSigningMethodSize] = {};
    char network[kAgentQUserSigningNetworkSize] = {};
    char payload_digest[kAgentQApprovalHistoryDigestSize] = {};
    AgentQTimeoutWindow request_window = kAgentQTimeoutWindowNone;
    AgentQTimeoutWindow pin_input_window = kAgentQTimeoutWindowNone;
    uint8_t signable_payload[kAgentQUserSigningPayloadMaxBytes] = {};
    size_t signable_payload_size = 0;
    bool signable_payload_available = false;
    SuiTransferFacts sui_transfer = {};
    char account_address[kSuiAddressBufferSize] = {};
    char message_preview[kAgentQSignPersonalMessagePreviewSize] = {};

    bool active() const
    {
        return stage != AgentQUserSigningStage::none;
    }

    void wipe_payload()
    {
        wipe_sensitive_buffer(signable_payload, sizeof(signable_payload));
        signable_payload_size = 0;
        signable_payload_available = false;
    }

    void clear()
    {
        wipe_payload();
        stage = AgentQUserSigningStage::none;
        terminal_result = AgentQUserSigningTerminalResult::none;
        signing_method = AgentQSigningMethod::unsupported;
        request_id[0] = '\0';
        session_id[0] = '\0';
        chain[0] = '\0';
        method[0] = '\0';
        network[0] = '\0';
        payload_digest[0] = '\0';
        request_window = kAgentQTimeoutWindowNone;
        pin_input_window = kAgentQTimeoutWindowNone;
        memset(&sui_transfer, 0, sizeof(sui_transfer));
        account_address[0] = '\0';
        message_preview[0] = '\0';
    }

    void terminalize(AgentQUserSigningTerminalResult result)
    {
        wipe_payload();
        terminal_result = result;
        stage = AgentQUserSigningStage::terminal;
        request_window = kAgentQTimeoutWindowNone;
        pin_input_window = kAgentQTimeoutWindowNone;
    }
};

AgentQUserSigningFlowState g_state;
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

bool printable_ascii(uint8_t value)
{
    return value >= 0x20 && value <= 0x7e;
}

void make_message_preview(const uint8_t* message, size_t message_size, char* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (message == nullptr || message_size == 0) {
        return;
    }
    const size_t max_payload = output_size > 4 ? output_size - 4 : output_size - 1;
    size_t written = 0;
    for (; written < message_size && written < max_payload; ++written) {
        output[written] = printable_ascii(message[written])
                              ? static_cast<char>(message[written])
                              : '.';
    }
    if (written < message_size && written + 3 < output_size) {
        output[written++] = '.';
        output[written++] = '.';
        output[written++] = '.';
    }
    output[written < output_size ? written : output_size - 1] = '\0';
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

bool any_deadline_reached(TickType_t now)
{
    return timeout_window_reached(g_state.request_window, now) ||
           timeout_window_reached(g_state.pin_input_window, now);
}

bool rejectable_stage(AgentQUserSigningStage stage)
{
    return stage == AgentQUserSigningStage::reviewing ||
           stage == AgentQUserSigningStage::pin_entry;
}

bool precritical_cleanup_stage(AgentQUserSigningStage stage)
{
    return stage == AgentQUserSigningStage::reviewing ||
           stage == AgentQUserSigningStage::pin_entry ||
           stage == AgentQUserSigningStage::history_write;
}

AgentQUserSigningTransitionResult terminalize_if_rejectable(
    AgentQUserSigningTerminalResult result)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    if (!rejectable_stage(g_state.stage)) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult terminalize_if_precritical_cleanup(
    AgentQUserSigningTerminalResult result)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    if (!precritical_cleanup_stage(g_state.stage)) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult terminalize_invalid_session()
{
    g_state.terminalize(AgentQUserSigningTerminalResult::canceled);
    return AgentQUserSigningTransitionResult::invalid_session;
}

AgentQUserSigningTransitionResult require_active_session()
{
    if (session_validate(g_state.session_id) != AgentQSessionValidationResult::ok) {
        return terminalize_invalid_session();
    }
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult terminalize_if_deadline_expired(TickType_t now)
{
    if (any_deadline_reached(now)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    return AgentQUserSigningTransitionResult::ok;
}

bool same_history_write_request(const AgentQUserSigningFlowSnapshot& snapshot)
{
    return g_state.active() &&
           snapshot.active &&
           snapshot.stage == AgentQUserSigningStage::history_write &&
           g_state.stage == AgentQUserSigningStage::history_write &&
           strcmp(g_state.request_id, snapshot.request_id) == 0 &&
           strcmp(g_state.session_id, snapshot.session_id) == 0 &&
           strcmp(g_state.chain, snapshot.chain) == 0 &&
           strcmp(g_state.method, snapshot.method) == 0 &&
           g_state.signing_method == snapshot.signing_method &&
           strcmp(g_state.network, snapshot.network) == 0 &&
           strcmp(g_state.payload_digest, snapshot.payload_digest) == 0 &&
           g_state.signable_payload_size == snapshot.signable_payload_size &&
           g_state.signable_payload_available == snapshot.signable_payload_available;
}

}  // namespace

AgentQUserSigningTransitionResult user_signing_flow_clear()
{
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    const bool was_active = g_state.active();
    g_state.clear();
    return was_active ? AgentQUserSigningTransitionResult::ok
                      : AgentQUserSigningTransitionResult::inactive;
}

bool user_signing_flow_active()
{
    return g_state.active();
}

bool user_signing_flow_in_signing_critical_section()
{
    return g_state.stage == AgentQUserSigningStage::signing_critical_section;
}

bool user_signing_flow_session_matches(const char* session_id)
{
    return g_state.active() &&
           session_id != nullptr &&
           g_state.session_id[0] != '\0' &&
           strcmp(g_state.session_id, session_id) == 0;
}

AgentQSessionValidationResult user_signing_flow_validate_session()
{
    if (!g_state.active() || g_state.session_id[0] == '\0') {
        return AgentQSessionValidationResult::missing;
    }
    return session_validate(g_state.session_id);
}

AgentQUserSigningFlowSnapshot user_signing_flow_snapshot()
{
    AgentQUserSigningFlowSnapshot snapshot = {};
    snapshot.active = g_state.active();
    snapshot.stage = g_state.stage;
    snapshot.terminal_result = g_state.terminal_result;
    snapshot.signing_method = g_state.signing_method;
    memcpy(snapshot.request_id, g_state.request_id, sizeof(snapshot.request_id));
    memcpy(snapshot.session_id, g_state.session_id, sizeof(snapshot.session_id));
    memcpy(snapshot.chain, g_state.chain, sizeof(snapshot.chain));
    memcpy(snapshot.method, g_state.method, sizeof(snapshot.method));
    memcpy(snapshot.network, g_state.network, sizeof(snapshot.network));
    memcpy(snapshot.payload_digest, g_state.payload_digest, sizeof(snapshot.payload_digest));
    snapshot.request_window = g_state.request_window;
    snapshot.pin_input_window = g_state.pin_input_window;
    snapshot.signable_payload_size = g_state.signable_payload_size;
    snapshot.signable_payload_available = g_state.signable_payload_available;
    snapshot.sui_transfer = g_state.sui_transfer;
    memcpy(snapshot.account_address, g_state.account_address, sizeof(snapshot.account_address));
    memcpy(snapshot.message_preview, g_state.message_preview, sizeof(snapshot.message_preview));
    return snapshot;
}

AgentQUserSigningFlowBeginResult user_signing_flow_begin(
    const AgentQUserSigningTransactionBeginInput& input)
{
    if (g_state.active()) {
        return AgentQUserSigningFlowBeginResult::active;
    }
    if (input.request_id == nullptr ||
        input.session_id == nullptr ||
        input.chain == nullptr ||
        input.method == nullptr ||
        input.network == nullptr ||
        input.signable_payload == nullptr) {
        return AgentQUserSigningFlowBeginResult::invalid_argument;
    }
    if (!timeout_window_valid(input.request_window)) {
        return AgentQUserSigningFlowBeginResult::invalid_deadline;
    }
    char request_id[kAgentQUserSigningIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQUserSigningChainSize] = {};
    char method[kAgentQUserSigningMethodSize] = {};
    char network[kAgentQUserSigningNetworkSize] = {};
    if (!copy_nonempty_c_string(input.request_id, request_id, sizeof(request_id)) ||
        !copy_nonempty_c_string(input.session_id, session_id, sizeof(session_id)) ||
        !copy_nonempty_c_string(input.chain, chain, sizeof(chain)) ||
        !copy_nonempty_c_string(input.method, method, sizeof(method)) ||
        !copy_nonempty_c_string(input.network, network, sizeof(network))) {
        return AgentQUserSigningFlowBeginResult::invalid_argument;
    }
    if (session_validate(session_id) != AgentQSessionValidationResult::ok) {
        return AgentQUserSigningFlowBeginResult::invalid_session;
    }
    if (strcmp(chain, "sui") != 0 ||
        strcmp(method, "sign_transaction") != 0) {
        return AgentQUserSigningFlowBeginResult::unsupported_method;
    }
    if (!supported_network(network)) {
        return AgentQUserSigningFlowBeginResult::invalid_network;
    }
    if (input.signable_payload_size == 0 ||
        input.signable_payload_size > kAgentQSuiSignTransactionTxBytesMaxBytes) {
        return AgentQUserSigningFlowBeginResult::invalid_payload;
    }

    SuiTransferFacts parsed_facts = {};
    if (parse_sui_transfer_facts(
            input.signable_payload,
            input.signable_payload_size,
            &parsed_facts) != SuiTransactionFactsResult::ok) {
        return AgentQUserSigningFlowBeginResult::invalid_transaction;
    }
    if (!summary_valid(parsed_facts)) {
        return AgentQUserSigningFlowBeginResult::invalid_summary;
    }
    const AgentQSuiSigningAccountBindingResult account_result =
        verify_sui_signing_stored_account_binding(parsed_facts);
    if (account_result != AgentQSuiSigningAccountBindingResult::ok) {
        return account_result == AgentQSuiSigningAccountBindingResult::account_unavailable
                   ? AgentQUserSigningFlowBeginResult::account_unavailable
                   : AgentQUserSigningFlowBeginResult::invalid_account;
    }

    g_state.clear();
    g_state.signing_method = AgentQSigningMethod::sui_sign_transaction;
    memcpy(g_state.request_id, request_id, sizeof(g_state.request_id));
    memcpy(g_state.session_id, session_id, sizeof(g_state.session_id));
    memcpy(g_state.chain, chain, sizeof(g_state.chain));
    memcpy(g_state.method, method, sizeof(g_state.method));
    memcpy(g_state.network, network, sizeof(g_state.network));
    if (!approval_history_digest_payload(
            input.signable_payload,
            input.signable_payload_size,
            g_state.payload_digest,
            sizeof(g_state.payload_digest))) {
        g_state.clear();
        return AgentQUserSigningFlowBeginResult::digest_error;
    }
    memcpy(g_state.signable_payload, input.signable_payload, input.signable_payload_size);
    g_state.signable_payload_size = input.signable_payload_size;
    g_state.signable_payload_available = true;
    g_state.sui_transfer = parsed_facts;
    g_state.request_window = input.request_window;
    g_state.pin_input_window = kAgentQTimeoutWindowNone;
    g_state.stage = AgentQUserSigningStage::reviewing;
    return AgentQUserSigningFlowBeginResult::ok;
}

AgentQUserSigningFlowBeginResult user_signing_flow_begin_personal_message(
    const AgentQUserSigningPersonalMessageBeginInput& input)
{
    if (g_state.active()) {
        return AgentQUserSigningFlowBeginResult::active;
    }
    if (input.request_id == nullptr ||
        input.session_id == nullptr ||
        input.chain == nullptr ||
        input.method == nullptr ||
        input.network == nullptr ||
        input.message == nullptr) {
        return AgentQUserSigningFlowBeginResult::invalid_argument;
    }
    if (!timeout_window_valid(input.request_window)) {
        return AgentQUserSigningFlowBeginResult::invalid_deadline;
    }
    char request_id[kAgentQUserSigningIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQUserSigningChainSize] = {};
    char method[kAgentQUserSigningMethodSize] = {};
    char network[kAgentQUserSigningNetworkSize] = {};
    if (!copy_nonempty_c_string(input.request_id, request_id, sizeof(request_id)) ||
        !copy_nonempty_c_string(input.session_id, session_id, sizeof(session_id)) ||
        !copy_nonempty_c_string(input.chain, chain, sizeof(chain)) ||
        !copy_nonempty_c_string(input.method, method, sizeof(method)) ||
        !copy_nonempty_c_string(input.network, network, sizeof(network))) {
        return AgentQUserSigningFlowBeginResult::invalid_argument;
    }
    if (session_validate(session_id) != AgentQSessionValidationResult::ok) {
        return AgentQUserSigningFlowBeginResult::invalid_session;
    }
    if (strcmp(chain, "sui") != 0 ||
        strcmp(method, "sign_personal_message") != 0) {
        return AgentQUserSigningFlowBeginResult::unsupported_method;
    }
    if (!supported_network(network)) {
        return AgentQUserSigningFlowBeginResult::invalid_network;
    }
    if (input.message_size == 0 ||
        input.message_size > kAgentQSuiSignPersonalMessageMaxBytes) {
        return AgentQUserSigningFlowBeginResult::invalid_payload;
    }

    uint8_t public_key[kSuiEd25519PublicKeyBytes] = {};
    char account_address[kSuiAddressBufferSize] = {};
    const SuiAccountDerivationResult account_result =
        derive_sui_ed25519_account_from_stored_root(
            public_key,
            account_address,
            sizeof(account_address));
    wipe_sensitive_buffer(public_key, sizeof(public_key));
    if (account_result != SuiAccountDerivationResult::ok) {
        memset(account_address, 0, sizeof(account_address));
        return AgentQUserSigningFlowBeginResult::account_unavailable;
    }

    g_state.clear();
    g_state.signing_method = AgentQSigningMethod::sui_sign_personal_message;
    memcpy(g_state.request_id, request_id, sizeof(g_state.request_id));
    memcpy(g_state.session_id, session_id, sizeof(g_state.session_id));
    memcpy(g_state.chain, chain, sizeof(g_state.chain));
    memcpy(g_state.method, method, sizeof(g_state.method));
    memcpy(g_state.network, network, sizeof(g_state.network));
    memcpy(g_state.account_address, account_address, sizeof(g_state.account_address));
    make_message_preview(
        input.message,
        input.message_size,
        g_state.message_preview,
        sizeof(g_state.message_preview));
    memset(account_address, 0, sizeof(account_address));
    if (!approval_history_digest_payload(
            input.message,
            input.message_size,
            g_state.payload_digest,
            sizeof(g_state.payload_digest))) {
        g_state.clear();
        return AgentQUserSigningFlowBeginResult::digest_error;
    }
    memcpy(g_state.signable_payload, input.message, input.message_size);
    g_state.signable_payload_size = input.message_size;
    g_state.signable_payload_available = true;
    g_state.request_window = input.request_window;
    g_state.pin_input_window = kAgentQTimeoutWindowNone;
    g_state.stage = AgentQUserSigningStage::reviewing;
    return AgentQUserSigningFlowBeginResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_accept_review(
    TickType_t now,
    AgentQTimeoutWindow pin_input_window)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::reviewing) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid(pin_input_window)) {
        return AgentQUserSigningTransitionResult::invalid_deadline;
    }
    AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    const TickType_t capped_pin_deadline =
        timeout_window_cap_deadline(g_state.request_window, pin_input_window.deadline);
    if (timeout_window_tick_reached(now, capped_pin_deadline)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    g_state.stage = AgentQUserSigningStage::pin_entry;
    g_state.pin_input_window =
        timeout_window_from_deadline(pin_input_window.started_at, capped_pin_deadline);
    if (!timeout_window_valid(g_state.pin_input_window)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_refresh_pin_deadline(
    TickType_t now,
    AgentQTimeoutWindow pin_input_window)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::pin_entry) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid(pin_input_window)) {
        return AgentQUserSigningTransitionResult::invalid_deadline;
    }
    const AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    const AgentQUserSigningTransitionResult deadline_guard = terminalize_if_deadline_expired(now);
    if (deadline_guard != AgentQUserSigningTransitionResult::ok) {
        return deadline_guard;
    }
    const TickType_t capped_pin_deadline =
        timeout_window_cap_deadline(g_state.request_window, pin_input_window.deadline);
    if (timeout_window_tick_reached(now, capped_pin_deadline)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    g_state.pin_input_window =
        timeout_window_from_deadline(pin_input_window.started_at, capped_pin_deadline);
    if (!timeout_window_valid(g_state.pin_input_window)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_pause_pin_deadline()
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::pin_entry) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    const AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    g_state.pin_input_window = kAgentQTimeoutWindowNone;
    return AgentQUserSigningTransitionResult::ok;
}

bool user_signing_flow_deadline_reached(TickType_t now)
{
    return g_state.active() && any_deadline_reached(now);
}

AgentQUserSigningTransitionResult
user_signing_flow_record_pin_verified_and_write_confirmation_history(
    TickType_t now,
    AgentQUserSigningHistoryWriteFn write_fn,
    void* context)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::pin_entry) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (write_fn == nullptr) {
        return AgentQUserSigningTransitionResult::invalid_argument;
    }
    if (timeout_window_active(g_state.pin_input_window)) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    g_state.stage = AgentQUserSigningStage::history_write;
    g_state.pin_input_window = kAgentQTimeoutWindowNone;

    guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    const AgentQUserSigningFlowSnapshot snapshot =
        user_signing_flow_snapshot();
    const bool write_ok = write_fn(snapshot, context);
    if (!same_history_write_request(snapshot)) {
        return AgentQUserSigningTransitionResult::stale_state;
    }
    if (!write_ok) {
        g_state.terminalize(AgentQUserSigningTerminalResult::history_error);
        return AgentQUserSigningTransitionResult::history_error;
    }
    g_state.stage = AgentQUserSigningStage::signing_critical_section;
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_consume_signable_payload(
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
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (!g_state.signable_payload_available || g_state.signable_payload_size == 0) {
        return AgentQUserSigningTransitionResult::payload_unavailable;
    }
    if (output == nullptr || output_capacity < g_state.signable_payload_size || output_size == nullptr) {
        return AgentQUserSigningTransitionResult::output_too_small;
    }
    memcpy(output, g_state.signable_payload, g_state.signable_payload_size);
    *output_size = g_state.signable_payload_size;
    g_state.wipe_payload();
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_record_device_rejected()
{
    return terminalize_if_rejectable(AgentQUserSigningTerminalResult::rejected);
}

AgentQUserSigningTransitionResult user_signing_flow_record_timeout(TickType_t now)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    if (g_state.stage != AgentQUserSigningStage::reviewing &&
        g_state.stage != AgentQUserSigningStage::pin_entry) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (!any_deadline_reached(now)) {
        return AgentQUserSigningTransitionResult::deadline_not_reached;
    }
    g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_record_signing_failed()
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    g_state.terminalize(AgentQUserSigningTerminalResult::signing_failed);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_complete_signed()
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (g_state.signable_payload_available) {
        return AgentQUserSigningTransitionResult::payload_not_consumed;
    }
    g_state.terminalize(AgentQUserSigningTerminalResult::signed_success);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_cancel_for_disconnect(
    const char* session_id)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (!user_signing_flow_session_matches(session_id)) {
        return AgentQUserSigningTransitionResult::invalid_session;
    }
    return terminalize_if_precritical_cleanup(AgentQUserSigningTerminalResult::canceled);
}

AgentQUserSigningTransitionResult user_signing_flow_cancel_for_session_loss()
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    if (session_validate(g_state.session_id) == AgentQSessionValidationResult::ok) {
        return AgentQUserSigningTransitionResult::session_still_active;
    }
    return terminalize_if_precritical_cleanup(AgentQUserSigningTerminalResult::canceled);
}

AgentQUserSigningTransitionResult user_signing_flow_cancel_for_ui_loss()
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    return terminalize_if_precritical_cleanup(AgentQUserSigningTerminalResult::canceled);
}

AgentQUserSigningTransitionResult user_signing_flow_cancel_for_pin_loss()
{
    return user_signing_flow_cancel_for_ui_loss();
}

bool user_signing_flow_terminal_pending()
{
    return g_state.stage == AgentQUserSigningStage::terminal &&
           g_state.terminal_result != AgentQUserSigningTerminalResult::none;
}

bool user_signing_flow_consume_terminal_result(
    AgentQUserSigningTerminalResult* output)
{
    if (!user_signing_flow_terminal_pending() || output == nullptr) {
        return false;
    }
    *output = g_state.terminal_result;
    g_state.clear();
    return true;
}

const char* user_signing_flow_terminal_status(
    AgentQUserSigningTerminalResult result)
{
    switch (result) {
        case AgentQUserSigningTerminalResult::signed_success:
            return "signed";
        case AgentQUserSigningTerminalResult::rejected:
            return "user_rejected";
        case AgentQUserSigningTerminalResult::timed_out:
            return "user_timed_out";
        case AgentQUserSigningTerminalResult::signing_failed:
            return "signing_failed";
        case AgentQUserSigningTerminalResult::canceled:
        case AgentQUserSigningTerminalResult::history_error:
            return "";
        case AgentQUserSigningTerminalResult::none:
        default:
            return "";
    }
}

const char* user_signing_flow_terminal_reason(
    AgentQUserSigningTerminalResult result)
{
    switch (result) {
        case AgentQUserSigningTerminalResult::signed_success:
            return "device_confirmed";
        case AgentQUserSigningTerminalResult::rejected:
            return "user_rejected";
        case AgentQUserSigningTerminalResult::timed_out:
            return "user_timed_out";
        case AgentQUserSigningTerminalResult::signing_failed:
            return "signing_failed";
        case AgentQUserSigningTerminalResult::canceled:
        case AgentQUserSigningTerminalResult::history_error:
            return "";
        case AgentQUserSigningTerminalResult::none:
        default:
            return "";
    }
}

}  // namespace agent_q
