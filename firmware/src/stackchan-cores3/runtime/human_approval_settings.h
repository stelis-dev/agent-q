#pragma once

namespace signing {

enum class HumanApprovalInputMode {
    pin,
    confirm,
};

bool read_human_approval_input_mode(HumanApprovalInputMode* mode);
HumanApprovalInputMode human_approval_input_mode_or_default();
bool human_approval_requires_pin();
bool store_human_approval_input_mode(HumanApprovalInputMode mode);
bool wipe_human_approval_input_mode();
const char* human_approval_input_mode_label(HumanApprovalInputMode mode);

}  // namespace signing
