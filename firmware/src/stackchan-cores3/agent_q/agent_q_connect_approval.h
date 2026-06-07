#pragma once

#include <stddef.h>

#include "agent_q_request_id.h"
#include "agent_q_timeout_window.h"

namespace agent_q {

constexpr size_t kAgentQConnectApprovalRequestIdSize = kAgentQRequestIdSize;
constexpr size_t kAgentQConnectApprovalGatewayNameSize = 65;

enum class AgentQConnectApprovalChoice {
    none,
    approved,
    rejected,
};

struct AgentQConnectApprovalSnapshot {
    bool active;
    const char* request_id;
    const char* gateway_name;
    AgentQTimeoutWindow approval_window;
    AgentQConnectApprovalChoice choice;
};

void connect_approval_clear();
bool connect_approval_active();
bool connect_approval_awaiting_choice();
AgentQConnectApprovalSnapshot connect_approval_snapshot();

bool connect_approval_begin(
    const char* request_id,
    const char* gateway_name,
    AgentQTimeoutWindow approval_window);
bool connect_approval_review_action_available(TickType_t now);
bool connect_approval_choose(AgentQConnectApprovalChoice choice, TickType_t now);
bool connect_approval_return_to_review(AgentQTimeoutWindow approval_window);
bool connect_approval_deadline_reached(TickType_t now);
bool connect_approval_request_id(char* output, size_t output_size);

}  // namespace agent_q
