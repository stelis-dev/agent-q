#pragma once

#include "sui/account_settings_types.h"

namespace signing {

enum class SuiAccountSettingsStatus {
    missing,
    active,
    invalid,
    unreadable,
};

bool read_sui_account_settings(SuiAccountSettings* settings);
bool store_sui_account_settings(const SuiAccountSettings& settings);
bool wipe_sui_account_settings();
SuiAccountSettingsStatus sui_account_settings_status();

}  // namespace signing
