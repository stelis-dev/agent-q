#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kBip39EntropyBytes = 16;
constexpr size_t kBip39MnemonicWordCount = 12;
constexpr size_t kBip39MnemonicMaxChars = 128;
constexpr size_t kBip39WordCount = 2048;

enum class Bip39EntropyDecodeResult {
    ok,
    invalid_output,
    invalid_word_count,
    invalid_word_index,
    checksum_mismatch,
};

bool make_bip39_mnemonic_12_words(
    const uint8_t entropy[kBip39EntropyBytes], char* output, size_t output_size);

bool bip39_english_word_index(const char* word, uint16_t* index_out);
Bip39EntropyDecodeResult decode_bip39_entropy_12_words(
    const uint16_t word_indices[kBip39MnemonicWordCount],
    size_t word_count,
    uint8_t* entropy_out,
    size_t entropy_size);

void wipe_sensitive_buffer(void* data, size_t size);

}  // namespace signing
