#include "bip39.h"

#include <string.h>

#include <mbedtls/sha256.h>

#include "bip39_wordlist.h"

namespace signing {

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

void set_bit(uint8_t* bytes, size_t bit_index, uint8_t bit)
{
    const uint8_t mask = static_cast<uint8_t>(1U << (7 - (bit_index % 8)));
    if (bit != 0) {
        bytes[bit_index / 8] = static_cast<uint8_t>(bytes[bit_index / 8] | mask);
    } else {
        bytes[bit_index / 8] = static_cast<uint8_t>(bytes[bit_index / 8] & ~mask);
    }
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

bool is_lowercase_bip39_word(const char* word)
{
    if (word == nullptr || word[0] == '\0') {
        return false;
    }
    for (const char* cursor = word; *cursor != '\0'; ++cursor) {
        if (*cursor < 'a' || *cursor > 'z') {
            return false;
        }
    }
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

bool bip39_english_word_index(const char* word, uint16_t* index_out)
{
    if (!is_lowercase_bip39_word(word) || index_out == nullptr) {
        return false;
    }

    for (uint16_t index = 0; index < kBip39WordCount; ++index) {
        const char* candidate = bip39_english_word(index);
        if (candidate != nullptr && strcmp(candidate, word) == 0) {
            *index_out = index;
            return true;
        }
    }
    return false;
}

Bip39EntropyDecodeResult decode_bip39_entropy_12_words(
    const uint16_t word_indices[kBip39MnemonicWordCount],
    size_t word_count,
    uint8_t* entropy_out,
    size_t entropy_size)
{
    if (entropy_out != nullptr && entropy_size > 0) {
        wipe_sensitive_buffer(entropy_out, entropy_size);
    }
    if (word_indices == nullptr || entropy_out == nullptr || entropy_size != kBip39EntropyBytes) {
        return Bip39EntropyDecodeResult::invalid_output;
    }
    if (word_count != kBip39MnemonicWordCount) {
        return Bip39EntropyDecodeResult::invalid_word_count;
    }

    for (size_t word_position = 0; word_position < kBip39MnemonicWordCount; ++word_position) {
        const uint16_t word_index = word_indices[word_position];
        if (word_index >= kBip39WordCount || bip39_english_word(word_index) == nullptr) {
            wipe_sensitive_buffer(entropy_out, entropy_size);
            return Bip39EntropyDecodeResult::invalid_word_index;
        }

        for (size_t bit_position = 0; bit_position < kBip39WordIndexBits; ++bit_position) {
            const size_t target_bit = word_position * kBip39WordIndexBits + bit_position;
            if (target_bit >= kBip39EntropyBits) {
                break;
            }
            const uint8_t bit = static_cast<uint8_t>(
                (word_index >> (kBip39WordIndexBits - 1 - bit_position)) & 0x01);
            set_bit(entropy_out, target_bit, bit);
        }
    }

    uint8_t checksum[kSha256Bytes] = {};
    if (mbedtls_sha256(entropy_out, kBip39EntropyBytes, checksum, 0) != 0) {
        wipe_sensitive_buffer(entropy_out, entropy_size);
        wipe_sensitive_buffer(checksum, sizeof(checksum));
        return Bip39EntropyDecodeResult::invalid_output;
    }

    for (size_t checksum_bit = 0; checksum_bit < kBip39ChecksumBits; ++checksum_bit) {
        const size_t source_bit = kBip39EntropyBits + checksum_bit;
        const size_t word_position = source_bit / kBip39WordIndexBits;
        const size_t bit_position = source_bit % kBip39WordIndexBits;
        const uint16_t word_index = word_indices[word_position];
        const uint8_t supplied_bit = static_cast<uint8_t>(
            (word_index >> (kBip39WordIndexBits - 1 - bit_position)) & 0x01);
        if (supplied_bit != bit_at(checksum, checksum_bit)) {
            wipe_sensitive_buffer(entropy_out, entropy_size);
            wipe_sensitive_buffer(checksum, sizeof(checksum));
            return Bip39EntropyDecodeResult::checksum_mismatch;
        }
    }

    wipe_sensitive_buffer(checksum, sizeof(checksum));
    return Bip39EntropyDecodeResult::ok;
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

}  // namespace signing
