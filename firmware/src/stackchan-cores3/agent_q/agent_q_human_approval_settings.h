#pragma once

namespace agent_q {

enum class AgentQHumanApprovalInputMode {
    pin,
    confirm,
};

bool read_human_approval_input_mode(AgentQHumanApprovalInputMode* mode);
AgentQHumanApprovalInputMode human_approval_input_mode_or_default();
bool human_approval_requires_pin();
bool store_human_approval_input_mode(AgentQHumanApprovalInputMode mode);
bool wipe_human_approval_input_mode();
const char* human_approval_input_mode_label(AgentQHumanApprovalInputMode mode);

}  // namespace agent_q
