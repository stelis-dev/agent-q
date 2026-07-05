#pragma once

#include <stddef.h>

#include "protocol/request_id.h"
#include "transport/timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

constexpr size_t kConnectApprovalRequestIdSize = kRequestIdSize;
constexpr size_t kConnectApprovalClientNameSize = 65;

enum class ConnectApprovalChoice {
    none,
    approved,
    rejected,
};

struct ConnectApprovalSnapshot {
    bool active;
    const char* request_id;
    const char* client_name;
    TimeoutWindow approval_window;
    ConnectApprovalChoice choice;
};

void connect_approval_clear();
bool connect_approval_active();
bool connect_approval_awaiting_choice();
ConnectApprovalSnapshot connect_approval_snapshot();

bool connect_approval_begin(
    const char* request_id,
    const char* client_name,
    TickType_t now,
    TimeoutWindow approval_window);
bool connect_approval_review_action_available(TickType_t now);
bool connect_approval_choose(ConnectApprovalChoice choice, TickType_t now);
bool connect_approval_return_to_review(TickType_t now, TimeoutWindow approval_window);
bool connect_approval_deadline_reached(TickType_t now);
bool connect_approval_request_id(char* output, size_t output_size);

}  // namespace signing
