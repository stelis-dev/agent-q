#include "agent_q_signing_self_test.h"

#include <stddef.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_random.h"

extern "C" {
#include "sign.h"
}

namespace {

constexpr const char* kTag = "SignerSelfTest";
constexpr uint8_t kSelfTestMessage[] = {
    's', 'i', 'g', 'n', 'i', 'n', 'g', '-', 's', 'e', 'l', 'f', '-', 't', 'e', 's', 't',
};

void wipe_bytes(uint8_t* data, size_t size)
{
    volatile uint8_t* cursor = data;
    while (size-- > 0) {
        *cursor++ = 0;
    }
}

}  // namespace

namespace agent_q {

void run_signing_self_test()
{
    uint8_t seed[32];
    uint8_t sui_signature[97];

    esp_fill_random(seed, sizeof(seed));

    const int sign_result =
        sui_signing_sign_ed25519(sui_signature, kSelfTestMessage, sizeof(kSelfTestMessage), seed);
    wipe_bytes(seed, sizeof(seed));

    if (sign_result != 0) {
        ESP_LOGE(kTag, "Ed25519 signing self-test failed: %d", sign_result);
        wipe_bytes(sui_signature, sizeof(sui_signature));
        return;
    }

    const int verify_result =
        sui_signing_verify_signature_ed25519(sui_signature, kSelfTestMessage,
                                             sizeof(kSelfTestMessage));
    if (verify_result != 0) {
        ESP_LOGE(kTag, "Ed25519 verification self-test failed: %d", verify_result);
        wipe_bytes(sui_signature, sizeof(sui_signature));
        return;
    }

    ESP_LOGI(kTag, "Ed25519 signing self-test ok: scheme=%u, signature_len=%u",
             sui_signature[0], static_cast<unsigned>(sizeof(sui_signature)));
    wipe_bytes(sui_signature, sizeof(sui_signature));
}

}  // namespace agent_q
