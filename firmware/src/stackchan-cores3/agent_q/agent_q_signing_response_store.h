#pragma once

#include <stddef.h>

#include "agent_q_request_id.h"
#include "agent_q_sign_request_identity.h"
#include "agent_q_session.h"

namespace agent_q {

// Bounded RAM store of completed signing responses, keyed by (session_id, request_id).
// A generated signature is buffered here until the host acknowledges it, so a link
// blip or reconnect between "signed" and "delivered" does not lose the response:
// the host re-requests the same request_id and the device returns the stored response
// (idempotent, never re-signs) or fetches it with a get_result request.
//
// The store is RAM-only by design: a device reset clears it, after which a re-request
// re-runs the normal signing gates (the host is told `unknown_request` and re-issues).
// This eliminates *silent* loss (a reset surfaces as an explicit re-authorization,
// not a vanished signature). All entries clear on disconnect/session end and on wipe.

constexpr size_t kSigningResponseStoreCapacity = 4;
// Bounds one serialized signing response line. Native Ed25519 signature envelopes are small, while
// zkLogin transaction envelopes can carry a base64 signature of up to ~2732 chars.
constexpr size_t kSigningResponseMaxSize = 4096;

enum class SigningResponseStoreOutcome {
    stored,     // newly stored
    duplicate,  // (session_id, request_id) already present — idempotent, left as-is
    conflict,   // (session_id, request_id) exists with a different request identity
    too_large,  // serialized response exceeds kSigningResponseMaxSize
    storage_error,  // response buffer allocation failed
    invalid,    // null/empty session_id or request_id, or null response
};

// Store a completed serialized response for (session_id, request_id). Idempotent: if the
// pair is already stored, returns `duplicate` and leaves the existing entry untouched.
// Evicts the least-recently-stored entry when the store is full.
SigningResponseStoreOutcome signing_response_store(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size,
    const char* serialized_response,
    size_t serialized_size);

enum class SigningResponseRetryLookup {
    not_found,
    match,
    conflict,
    invalid,
};

SigningResponseRetryLookup signing_response_find_for_retry(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size,
    char* out,
    size_t out_size,
    size_t* out_len);

// Copy a stored response for (session_id, request_id) into `out` (bounded by out_size,
// NUL-terminated). Writes the length to out_len when non-null. Returns false if not
// found or if out is too small.
bool signing_response_find(
    const char* session_id,
    const char* request_id,
    char* out,
    size_t out_size,
    size_t* out_len);

// Release a stored response (the host acknowledged delivery). Returns true if it existed.
bool signing_response_ack(const char* session_id, const char* request_id);

// Drop every response belonging to a session (disconnect or session end).
void signing_response_clear_session(const char* session_id);

// Drop every stored response (wipe / reset).
void signing_response_clear_all();

}  // namespace agent_q
