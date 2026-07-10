#pragma once

#include <stddef.h>

#include <ArduinoJson.h>

#include "transport/timeout_window.h"
#include "protocol/response_writer.h"

namespace signing {

constexpr size_t kConnectClientNameMaxBytes = 64;

struct ConnectHandlerOps {
    bool (*material_ready)();
    bool (*write_connect_admission_error)(
        const char* id,
        const ResponseWriter& writer);
    bool (*write_existing_session_connect_response)(
        const char* id,
        const ResponseWriter& writer);
    TimeoutTick (*current_tick)();
    TimeoutWindow (*make_approval_window)(TimeoutTick now);
    bool (*begin_connect_approval)(
        const char* request_id,
        const char* client_name,
        TimeoutTick now,
        TimeoutWindow approval_window);
    void (*show_connect_unavailable)();
    void (*reset_review_choice_queue)();
    void (*show_connect_review)();
    void (*record_review_waiting)(const char* id, const char* client_name);
};

void handle_protocol_connect_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const ConnectHandlerOps& ops);

}  // namespace signing
