#include "agent_q_signing_result_store.h"

#include <stdint.h>
#include <string.h>

#include "agent_q_protocol_input_copy.h"

namespace agent_q {
namespace {

struct SigningResultEntry {
    bool active = false;
    char session_id[kAgentQSessionIdSize] = {};
    char request_id[kAgentQRequestIdSize] = {};
    char result[kSigningResultMaxSize] = {};
    size_t result_len = 0;
    uint32_t stored_seq = 0;
};

SigningResultEntry g_entries[kSigningResultStoreCapacity];
uint32_t g_store_seq = 0;

bool entry_matches(const SigningResultEntry& entry, const char* session_id, const char* request_id)
{
    return entry.active &&
           strcmp(entry.session_id, session_id) == 0 &&
           strcmp(entry.request_id, request_id) == 0;
}

}  // namespace

SigningResultStoreOutcome signing_result_store(
    const char* session_id,
    const char* request_id,
    const char* serialized_result,
    size_t serialized_size)
{
    if (session_id == nullptr || session_id[0] == '\0' ||
        request_id == nullptr || request_id[0] == '\0' ||
        serialized_result == nullptr) {
        return SigningResultStoreOutcome::invalid;
    }
    if (serialized_size == 0 || serialized_size >= kSigningResultMaxSize) {
        return SigningResultStoreOutcome::too_large;
    }

    for (SigningResultEntry& entry : g_entries) {
        if (entry_matches(entry, session_id, request_id)) {
            return SigningResultStoreOutcome::duplicate;
        }
    }

    SigningResultEntry* slot = nullptr;
    for (SigningResultEntry& entry : g_entries) {
        if (!entry.active) {
            slot = &entry;
            break;
        }
    }
    if (slot == nullptr) {
        uint32_t oldest = UINT32_MAX;
        for (SigningResultEntry& entry : g_entries) {
            if (entry.stored_seq < oldest) {
                oldest = entry.stored_seq;
                slot = &entry;
            }
        }
    }

    SigningResultEntry next = {};
    if (!copy_nonempty_c_string(session_id, next.session_id, sizeof(next.session_id)) ||
        !copy_nonempty_c_string(request_id, next.request_id, sizeof(next.request_id))) {
        return SigningResultStoreOutcome::invalid;
    }
    memcpy(next.result, serialized_result, serialized_size);
    next.result[serialized_size] = '\0';
    next.result_len = serialized_size;
    next.active = true;
    next.stored_seq = ++g_store_seq;
    *slot = next;
    return SigningResultStoreOutcome::stored;
}

bool signing_result_find(
    const char* session_id,
    const char* request_id,
    char* out,
    size_t out_size,
    size_t* out_len)
{
    if (session_id == nullptr || request_id == nullptr || out == nullptr || out_size == 0) {
        return false;
    }
    for (const SigningResultEntry& entry : g_entries) {
        if (entry_matches(entry, session_id, request_id)) {
            if (entry.result_len >= out_size) {
                return false;
            }
            memcpy(out, entry.result, entry.result_len);
            out[entry.result_len] = '\0';
            if (out_len != nullptr) {
                *out_len = entry.result_len;
            }
            return true;
        }
    }
    return false;
}

bool signing_result_ack(const char* session_id, const char* request_id)
{
    if (session_id == nullptr || request_id == nullptr) {
        return false;
    }
    for (SigningResultEntry& entry : g_entries) {
        if (entry_matches(entry, session_id, request_id)) {
            entry = SigningResultEntry{};
            return true;
        }
    }
    return false;
}

void signing_result_clear_session(const char* session_id)
{
    if (session_id == nullptr) {
        return;
    }
    for (SigningResultEntry& entry : g_entries) {
        if (entry.active && strcmp(entry.session_id, session_id) == 0) {
            entry = SigningResultEntry{};
        }
    }
}

void signing_result_clear_all()
{
    for (SigningResultEntry& entry : g_entries) {
        entry = SigningResultEntry{};
    }
}

}  // namespace agent_q
