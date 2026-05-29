#include "agent_q_bip39.h"

#include <string.h>

#include <mbedtls/sha256.h>

#include "agent_q_bip39_wordlist.h"

namespace agent_q {

namespace {

constexpr size_t kBip39EntropyBits = kBip39EntropyBytes * 8;
constexpr size_t kBip39ChecksumBits = kBip39EntropyBits / 32;
constexpr size_t kBip39TotalBits = kBip39EntropyBits + kBip39ChecksumBits;
constexpr size_t kBip39WordIndexBits = 11;
constexpr size_t kSha256Bytes = 32;

uint8_t bit_at(const uint8_t* bytes, size_t bit_index)
{
    return (bytes[bit_index / 8] >> (7 - (bit_index % 8))) & 0x01;
}

bool append_text(char* output, size_t output_size, const char* text)
{
    if (output == nullptr || text == nullptr || output_size == 0) {
        return false;
    }

    const size_t current_length = strlen(output);
    const size_t text_length = strlen(text);
    if (current_length >= output_size || text_length >= output_size - current_length) {
        return false;
    }

    memcpy(output + current_length, text, text_length + 1);
    return true;
}

}  // namespace

bool make_bip39_mnemonic_12_words(
    const uint8_t entropy[kBip39EntropyBytes], char* output, size_t output_size)
{
    if (entropy == nullptr || output == nullptr || output_size == 0) {
        return false;
    }

    output[0] = '\0';

    uint8_t checksum[kSha256Bytes] = {};
    if (mbedtls_sha256(entropy, kBip39EntropyBytes, checksum, 0) != 0) {
        wipe_sensitive_buffer(checksum, sizeof(checksum));
        return false;
    }

    for (size_t word_position = 0; word_position < kBip39MnemonicWordCount; ++word_position) {
        uint16_t word_index = 0;
        for (size_t bit_position = 0; bit_position < kBip39WordIndexBits; ++bit_position) {
            const size_t source_bit = word_position * kBip39WordIndexBits + bit_position;
            uint8_t bit = 0;
            if (source_bit < kBip39EntropyBits) {
                bit = bit_at(entropy, source_bit);
            } else if (source_bit < kBip39TotalBits) {
                bit = bit_at(checksum, source_bit - kBip39EntropyBits);
            } else {
                wipe_sensitive_buffer(checksum, sizeof(checksum));
                return false;
            }
            word_index = static_cast<uint16_t>((word_index << 1) | bit);
        }

        const char* word = bip39_english_word(word_index);
        if (word == nullptr) {
            wipe_sensitive_buffer(checksum, sizeof(checksum));
            return false;
        }
        if (word_position > 0 && !append_text(output, output_size, " ")) {
            wipe_sensitive_buffer(checksum, sizeof(checksum));
            wipe_sensitive_buffer(output, output_size);
            return false;
        }
        if (!append_text(output, output_size, word)) {
            wipe_sensitive_buffer(checksum, sizeof(checksum));
            wipe_sensitive_buffer(output, output_size);
            return false;
        }
    }

    wipe_sensitive_buffer(checksum, sizeof(checksum));
    return true;
}

void wipe_sensitive_buffer(void* data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    volatile uint8_t* cursor = reinterpret_cast<volatile uint8_t*>(data);
    while (size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace agent_q
