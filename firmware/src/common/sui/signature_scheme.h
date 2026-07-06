#pragma once

#include <stdint.h>

namespace signing {

constexpr uint8_t kSuiSignatureSchemeFlagEd25519 = 0x00;
constexpr uint8_t kSuiSignatureSchemeFlagZkLogin = 0x05;

}  // namespace signing
