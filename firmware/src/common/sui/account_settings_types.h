#pragma once

namespace signing {

struct SuiAccountSettings {
    bool accept_gas_sponsor;
};

constexpr SuiAccountSettings kDefaultSuiAccountSettings = {
    false,
};

}  // namespace signing
