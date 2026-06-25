#include "agent_q_signing_response_store.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "agent_q_protocol_input_copy.h"

namespace agent_q {
namespace {

struct SigningResponseEntry {
    bool active = false;
    char session_id[kAgentQSessionIdSize] = {};
    char request_id[kAgentQRequestIdSize] = {};
    uint8_t request_identity[kAgentQSignRequestIdentitySize] = {};
    char* response = nullptr;
    size_t response_len = 0;
    size_t response_capacity = 0;
    uint32_t stored_seq = 0;
};

SigningResponseEntry g_entries[kSigningResponseStoreCapacity];
uint32_t g_store_seq = 0;

void clear_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

void clear_entry(SigningResponseEntry& entry)
{
    clear_buffer(entry.session_id, sizeof(entry.session_id));
    clear_buffer(entry.request_id, sizeof(entry.request_id));
    clear_buffer(entry.request_identity, sizeof(entry.request_identity));
    if (entry.response != nullptr) {
        clear_buffer(entry.response, entry.response_capacity);
        free(entry.response);
        entry.response = nullptr;
    }
    entry.response_len = 0;
    entry.response_capacity = 0;
    entry.stored_seq = 0;
    entry.active = false;
}

bool entry_matches(const SigningResponseEntry& entry, const char* session_id, const char* request_id)
{
    return entry.active &&
           strcmp(entry.session_id, session_id) == 0 &&
           strcmp(entry.request_id, request_id) == 0;
}

}  // namespace

SigningResponseStoreOutcome signing_response_store(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size,
    const char* serialized_response,
    size_t serialized_size)
{
    if (session_id == nullptr || session_id[0] == '\0' ||
        request_id == nullptr || request_id[0] == '\0' ||
        request_identity == nullptr ||
        request_identity_size != kAgentQSignRequestIdentitySize ||
        serialized_response == nullptr) {
        return SigningResponseStoreOutcome::invalid;
    }
    if (serialized_size == 0 || serialized_size >= kSigningResponseMaxSize) {
        return SigningResponseStoreOutcome::too_large;
    }

    for (SigningResponseEntry& entry : g_entries) {
        if (entry_matches(entry, session_id, request_id)) {
            return memcmp(
                       entry.request_identity,
                       request_identity,
                       kAgentQSignRequestIdentitySize) == 0
                       ? SigningResponseStoreOutcome::duplicate
                       : SigningResponseStoreOutcome::conflict;
        }
    }

    char* response_copy = static_cast<char*>(malloc(serialized_size + 1));
    if (response_copy == nullptr) {
        return SigningResponseStoreOutcome::storage_error;
    }
    memcpy(response_copy, serialized_response, serialized_size);
    response_copy[serialized_size] = '\0';

    SigningResponseEntry* slot = nullptr;
    for (SigningResponseEntry& entry : g_entries) {
        if (!entry.active) {
            slot = &entry;
            break;
        }
    }
    if (slot == nullptr) {
        uint32_t oldest = UINT32_MAX;
        for (SigningResponseEntry& entry : g_entries) {
            if (entry.stored_seq < oldest) {
                oldest = entry.stored_seq;
                slot = &entry;
            }
        }
    }

    if (slot != nullptr) {
        clear_entry(*slot);
    } else {
        clear_buffer(response_copy, serialized_size + 1);
        free(response_copy);
        return SigningResponseStoreOutcome::storage_error;
    }

    SigningResponseEntry next = {};
    if (!copy_nonempty_c_string(session_id, next.session_id, sizeof(next.session_id)) ||
        !copy_nonempty_c_string(request_id, next.request_id, sizeof(next.request_id))) {
        clear_buffer(response_copy, serialized_size + 1);
        free(response_copy);
        return SigningResponseStoreOutcome::invalid;
    }
    memcpy(
        next.request_identity,
        request_identity,
        kAgentQSignRequestIdentitySize);
    next.response = response_copy;
    next.response_len = serialized_size;
    next.response_capacity = serialized_size + 1;
    next.active = true;
    next.stored_seq = ++g_store_seq;
    *slot = next;
    return SigningResponseStoreOutcome::stored;
}

SigningResponseRetryLookup signing_response_find_for_retry(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size,
    char* out,
    size_t out_size,
    size_t* out_len)
{
    if (session_id == nullptr ||
        request_id == nullptr ||
        request_identity == nullptr ||
        request_identity_size != kAgentQSignRequestIdentitySize ||
        out == nullptr ||
        out_size == 0) {
        return SigningResponseRetryLookup::invalid;
    }
    for (const SigningResponseEntry& entry : g_entries) {
        if (!entry_matches(entry, session_id, request_id)) {
            continue;
        }
        if (memcmp(
                entry.request_identity,
                request_identity,
                kAgentQSignRequestIdentitySize) != 0) {
            return SigningResponseRetryLookup::conflict;
        }
        if (entry.response == nullptr || entry.response_len >= out_size) {
            return SigningResponseRetryLookup::invalid;
        }
        memcpy(out, entry.response, entry.response_len);
        out[entry.response_len] = '\0';
        if (out_len != nullptr) {
            *out_len = entry.response_len;
        }
        return SigningResponseRetryLookup::match;
    }
    return SigningResponseRetryLookup::not_found;
}

bool signing_response_find(
    const char* session_id,
    const char* request_id,
    char* out,
    size_t out_size,
    size_t* out_len)
{
    if (session_id == nullptr || request_id == nullptr || out == nullptr || out_size == 0) {
        return false;
    }
    for (const SigningResponseEntry& entry : g_entries) {
        if (entry_matches(entry, session_id, request_id)) {
            if (entry.response == nullptr || entry.response_len >= out_size) {
                return false;
            }
            memcpy(out, entry.response, entry.response_len);
            out[entry.response_len] = '\0';
            if (out_len != nullptr) {
                *out_len = entry.response_len;
            }
            return true;
        }
    }
    return false;
}

bool signing_response_ack(const char* session_id, const char* request_id)
{
    if (session_id == nullptr || request_id == nullptr) {
        return false;
    }
    for (SigningResponseEntry& entry : g_entries) {
        if (entry_matches(entry, session_id, request_id)) {
            clear_entry(entry);
            return true;
        }
    }
    return false;
}

void signing_response_clear_session(const char* session_id)
{
    if (session_id == nullptr) {
        return;
    }
    for (SigningResponseEntry& entry : g_entries) {
        if (entry.active && strcmp(entry.session_id, session_id) == 0) {
            clear_entry(entry);
        }
    }
}

void signing_response_clear_all()
{
    for (SigningResponseEntry& entry : g_entries) {
        clear_entry(entry);
    }
}

}  // namespace agent_q
