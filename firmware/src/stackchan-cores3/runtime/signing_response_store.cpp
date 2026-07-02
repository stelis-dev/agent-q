#include "signing_response_store.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "protocol_input_copy.h"

namespace signing {
namespace {

struct ResponseEntry {
    bool active = false;
    char session_id[kSessionIdSize] = {};
    char request_id[kRequestIdSize] = {};
    uint8_t request_identity[kSignRequestIdentitySize] = {};
    char* response = nullptr;
    size_t response_len = 0;
    size_t response_capacity = 0;
    uint32_t stored_seq = 0;
};

ResponseEntry g_entries[kResponseStoreCapacity];
uint32_t g_store_seq = 0;

void clear_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

void clear_entry(ResponseEntry& entry)
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

bool entry_matches(const ResponseEntry& entry, const char* session_id, const char* request_id)
{
    return entry.active &&
           strcmp(entry.session_id, session_id) == 0 &&
           strcmp(entry.request_id, request_id) == 0;
}

}  // namespace

ResponseStoreOutcome signing_response_store(
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
        request_identity_size != kSignRequestIdentitySize ||
        serialized_response == nullptr) {
        return ResponseStoreOutcome::invalid;
    }
    if (serialized_size == 0 || serialized_size >= kResponseMaxSize) {
        return ResponseStoreOutcome::too_large;
    }

    for (ResponseEntry& entry : g_entries) {
        if (entry_matches(entry, session_id, request_id)) {
            return memcmp(
                       entry.request_identity,
                       request_identity,
                       kSignRequestIdentitySize) == 0
                       ? ResponseStoreOutcome::duplicate
                       : ResponseStoreOutcome::conflict;
        }
    }

    char* response_copy = static_cast<char*>(malloc(serialized_size + 1));
    if (response_copy == nullptr) {
        return ResponseStoreOutcome::storage_error;
    }
    memcpy(response_copy, serialized_response, serialized_size);
    response_copy[serialized_size] = '\0';

    ResponseEntry* slot = nullptr;
    for (ResponseEntry& entry : g_entries) {
        if (!entry.active) {
            slot = &entry;
            break;
        }
    }
    if (slot == nullptr) {
        uint32_t oldest = UINT32_MAX;
        for (ResponseEntry& entry : g_entries) {
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
        return ResponseStoreOutcome::storage_error;
    }

    ResponseEntry next = {};
    if (!copy_nonempty_c_string(session_id, next.session_id, sizeof(next.session_id)) ||
        !copy_nonempty_c_string(request_id, next.request_id, sizeof(next.request_id))) {
        clear_buffer(response_copy, serialized_size + 1);
        free(response_copy);
        return ResponseStoreOutcome::invalid;
    }
    memcpy(
        next.request_identity,
        request_identity,
        kSignRequestIdentitySize);
    next.response = response_copy;
    next.response_len = serialized_size;
    next.response_capacity = serialized_size + 1;
    next.active = true;
    next.stored_seq = ++g_store_seq;
    *slot = next;
    return ResponseStoreOutcome::stored;
}

ResponseRetryLookup signing_response_find_for_retry(
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
        request_identity_size != kSignRequestIdentitySize ||
        out == nullptr ||
        out_size == 0) {
        return ResponseRetryLookup::invalid;
    }
    for (const ResponseEntry& entry : g_entries) {
        if (!entry_matches(entry, session_id, request_id)) {
            continue;
        }
        if (memcmp(
                entry.request_identity,
                request_identity,
                kSignRequestIdentitySize) != 0) {
            return ResponseRetryLookup::conflict;
        }
        if (entry.response == nullptr || entry.response_len >= out_size) {
            return ResponseRetryLookup::invalid;
        }
        memcpy(out, entry.response, entry.response_len);
        out[entry.response_len] = '\0';
        if (out_len != nullptr) {
            *out_len = entry.response_len;
        }
        return ResponseRetryLookup::match;
    }
    return ResponseRetryLookup::not_found;
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
    for (const ResponseEntry& entry : g_entries) {
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
    for (ResponseEntry& entry : g_entries) {
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
    for (ResponseEntry& entry : g_entries) {
        if (entry.active && strcmp(entry.session_id, session_id) == 0) {
            clear_entry(entry);
        }
    }
}

void signing_response_clear_all()
{
    for (ResponseEntry& entry : g_entries) {
        clear_entry(entry);
    }
}

}  // namespace signing
