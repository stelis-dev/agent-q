#include "sui/personal_message_intent.h"

#include <string.h>

extern "C" {
#include "lib/monocypher/monocypher.h"
}

namespace signing {
namespace {

size_t encode_uleb128_size(size_t value, uint8_t* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return 0;
    }
    size_t written = 0;
    do {
        if (written >= output_size) {
            return 0;
        }
        uint8_t byte = static_cast<uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0) {
            byte |= 0x80U;
        }
        output[written++] = byte;
    } while (value != 0);
    return written;
}

void wipe_local(void* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (size-- > 0) {
        *cursor++ = 0;
    }
}

}  // namespace

bool build_sui_personal_message_intent_digest(
    const uint8_t* message,
    size_t message_size,
    uint8_t digest_out[kSuiPersonalMessageIntentDigestBytes])
{
    if (digest_out != nullptr) {
        memset(digest_out, 0, kSuiPersonalMessageIntentDigestBytes);
    }
    if (message == nullptr ||
        message_size == 0 ||
        message_size > kSuiSignPersonalMessageMaxBytes ||
        digest_out == nullptr) {
        return false;
    }

    uint8_t length_prefix[4] = {};
    const size_t length_prefix_size =
        encode_uleb128_size(message_size, length_prefix, sizeof(length_prefix));
    if (length_prefix_size == 0) {
        return false;
    }

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, kSuiPersonalMessageIntentDigestBytes);
    const uint8_t personal_message_intent[3] = {0x03, 0x00, 0x00};
    crypto_blake2b_update(&ctx, personal_message_intent, sizeof(personal_message_intent));
    crypto_blake2b_update(&ctx, length_prefix, length_prefix_size);
    crypto_blake2b_update(&ctx, message, message_size);
    crypto_blake2b_final(&ctx, digest_out);
    wipe_local(length_prefix, sizeof(length_prefix));
    wipe_local(&ctx, sizeof(ctx));
    return true;
}

}  // namespace signing
