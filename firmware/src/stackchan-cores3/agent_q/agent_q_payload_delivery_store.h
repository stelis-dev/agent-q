#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_approval_history.h"
#include "agent_q_payload_delivery_primitives.h"
#include "agent_q_session.h"
#include "agent_q_sign_route.h"
#include "agent_q_timeout_window.h"
#include "agent_q_user_signing_limits.h"

namespace agent_q {

constexpr size_t kAgentQPayloadDeliveryDefaultMaxBytes = 128 * 1024;
// Worst-case payload_upload_chunk JSON frame under the 4096-byte USB request
// line cap with maximum request/session/upload id lengths, uint64 offset, and
// base64 expansion. Keep this in sync with host request framing tests.
constexpr size_t kAgentQPayloadDeliveryDefaultChunkMaxBytes = 2700;

enum class AgentQPayloadDeliveryState {
    idle,
    receiving,
    finalized,
};

enum class AgentQPayloadDeliveryResult {
    ok,
    invalid_argument,
    invalid_state,
    invalid_session,
    unsupported_method,
    unsupported_payload_kind,
    unsupported_payload_size,
    invalid_payload_digest,
    invalid_upload_id,
    invalid_payload_ref,
    allocation_failed,
    chunk_too_large,
    offset_mismatch,
    payload_overflow,
    size_mismatch,
    digest_mismatch,
    digest_error,
    not_found,
};

struct AgentQPayloadDeliveryLimits {
    size_t chunk_max_bytes;
    size_t payload_max_bytes;
};

struct AgentQPayloadDeliveryBeginInput {
    const char* session_id;
    AgentQSupportedSignRoute route;
    const char* payload_kind;
    size_t size_bytes;
    const char* payload_digest;
    AgentQPayloadDeliveryLimits limits;
    AgentQTimeoutWindow timeout_window;
};

struct AgentQPayloadDeliveryBeginOutput {
    char upload_id[kAgentQPayloadDeliveryUploadIdSize];
    size_t received_bytes;
    size_t chunk_max_bytes;
};

struct AgentQPayloadDeliveryChunkInput {
    const char* session_id;
    const char* upload_id;
    size_t offset_bytes;
    const uint8_t* chunk;
    size_t chunk_size;
};

struct AgentQPayloadDeliveryFinishInput {
    const char* session_id;
    const char* upload_id;
};

struct AgentQPayloadDeliveryAbortInput {
    const char* session_id;
    const char* upload_id;
    const char* payload_ref;
};

struct AgentQPayloadDeliveryDescriptor {
    char session_id[kAgentQSessionIdSize];
    char payload_ref[kAgentQPayloadDeliveryPayloadRefSize];
    AgentQSupportedSignRoute route;
    char chain[kAgentQUserSigningChainSize];
    char method[kAgentQUserSigningMethodSize];
    char payload_kind[kAgentQPayloadDeliveryPayloadKindSize];
    size_t size_bytes;
    char payload_digest[kAgentQApprovalHistoryDigestSize];
};

struct AgentQPayloadDeliveryFinishOutput {
    AgentQPayloadDeliveryDescriptor descriptor;
};

struct AgentQPayloadDeliveryView {
    AgentQPayloadDeliveryDescriptor descriptor;
    const uint8_t* bytes;
    size_t size_bytes;
};

struct AgentQPayloadDeliveryOwnedPayload {
    AgentQPayloadDeliveryDescriptor descriptor;
    uint8_t* bytes;
    size_t size_bytes;
};

struct AgentQPayloadDeliverySnapshot {
    AgentQPayloadDeliveryState state;
    char session_id[kAgentQSessionIdSize];
    char upload_id[kAgentQPayloadDeliveryUploadIdSize];
    char payload_ref[kAgentQPayloadDeliveryPayloadRefSize];
    AgentQSupportedSignRoute route;
    size_t declared_size_bytes;
    size_t received_bytes;
    size_t chunk_max_bytes;
    size_t payload_max_bytes;
    AgentQTimeoutWindow timeout_window;
};

void payload_delivery_store_reset();
// Advances volatile payload delivery state to now_tick before returning a
// snapshot. Expired scratch is wiped by this call.
AgentQPayloadDeliverySnapshot payload_delivery_advance_and_snapshot(AgentQTimeoutTick now_tick);

AgentQPayloadDeliveryResult payload_delivery_begin(
    AgentQTimeoutTick now_tick,
    const AgentQPayloadDeliveryBeginInput& input,
    AgentQPayloadDeliveryBeginOutput* output);
AgentQPayloadDeliveryResult payload_delivery_append_chunk(
    AgentQTimeoutTick now_tick,
    const AgentQPayloadDeliveryChunkInput& input,
    size_t* received_bytes_out);
AgentQPayloadDeliveryResult payload_delivery_reject_chunk_too_large(
    AgentQTimeoutTick now_tick,
    const char* session_id,
    const char* upload_id);
AgentQPayloadDeliveryResult payload_delivery_finish(
    AgentQTimeoutTick now_tick,
    const AgentQPayloadDeliveryFinishInput& input,
    AgentQPayloadDeliveryFinishOutput* output);
AgentQPayloadDeliveryResult payload_delivery_abort(
    AgentQTimeoutTick now_tick,
    const AgentQPayloadDeliveryAbortInput& input);
AgentQPayloadDeliveryResult payload_delivery_resolve_finalized(
    AgentQTimeoutTick now_tick,
    const char* session_id,
    const char* payload_ref,
    AgentQPayloadDeliveryView* output);
AgentQPayloadDeliveryResult payload_delivery_take_finalized(
    AgentQTimeoutTick now_tick,
    const char* session_id,
    const char* payload_ref,
    AgentQPayloadDeliveryOwnedPayload* output);

bool payload_delivery_clear_for_session(const char* session_id);
bool payload_delivery_clear_expired(uint64_t now_tick);
void payload_delivery_clear_all();

const char* payload_delivery_result_name(AgentQPayloadDeliveryResult result);

}  // namespace agent_q
