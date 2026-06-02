#pragma once

namespace agent_q {

bool read_require_pin_on_connect(bool* required);
bool connect_requires_pin();
bool store_require_pin_on_connect(bool required);
bool wipe_require_pin_on_connect();

}  // namespace agent_q
