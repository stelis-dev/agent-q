#pragma once

namespace agent_q {

struct AgentQSuiAccountSettings {
    bool accept_gas_sponsor;
};

constexpr AgentQSuiAccountSettings kDefaultSuiAccountSettings = {
    false,
};

enum class AgentQSuiAccountSettingsStatus {
    missing,
    active,
    invalid,
    unreadable,
};

bool read_sui_account_settings(AgentQSuiAccountSettings* settings);
bool store_sui_account_settings(const AgentQSuiAccountSettings& settings);
bool wipe_sui_account_settings();
AgentQSuiAccountSettingsStatus sui_account_settings_status();

}  // namespace agent_q
