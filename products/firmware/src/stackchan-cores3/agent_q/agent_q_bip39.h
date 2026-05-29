#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr size_t kBip39EntropyBytes = 16;
constexpr size_t kBip39MnemonicWordCount = 12;
constexpr size_t kBip39MnemonicMaxChars = 128;

bool make_bip39_mnemonic_12_words(
    const uint8_t entropy[kBip39EntropyBytes], char* output, size_t output_size);

void wipe_sensitive_buffer(void* data, size_t size);

}  // namespace agent_q
