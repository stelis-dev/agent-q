#include "agent_q_signing_self_test.h"

#include <stddef.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_random.h"
#include "hal/hal.h"
#include "lvgl.h"

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

void show_self_test_result(bool ok, int result_code)
{
    {
        LvglLockGuard lock;

        lv_obj_t* panel = lv_obj_create(lv_screen_active());
        lv_obj_set_size(panel, 276, 92);
        lv_obj_align(panel, LV_ALIGN_CENTER, 0, 18);
        lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_style_radius(panel, 12, 0);
        lv_obj_set_style_border_width(panel, 2, 0);
        lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
        lv_obj_set_style_bg_color(panel, lv_color_hex(ok ? 0x123D25 : 0x4A1825), 0);
        lv_obj_set_style_border_color(panel, lv_color_hex(ok ? 0x34C279 : 0xFF6B93), 0);

        lv_obj_t* title = lv_label_create(panel);
        lv_label_set_text(title, ok ? "Signer self-test OK" : "Signer self-test FAIL");
        lv_obj_set_width(title, 244);
        lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(title, lv_color_hex(0xFFFFFF), 0);
        lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 12);

        lv_obj_t* subtitle = lv_label_create(panel);
        lv_label_set_text_fmt(subtitle, ok ? "Ed25519 sign + verify" : "result code: %d",
                              result_code);
        lv_obj_set_width(subtitle, 244);
        lv_obj_set_style_text_align(subtitle, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(subtitle, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(subtitle, lv_color_hex(0xD7DEE6), 0);
        lv_obj_align(subtitle, LV_ALIGN_TOP_MID, 0, 48);

        lv_obj_move_foreground(panel);
    }

    ESP_LOGI(kTag, "Signing self-test screen shown: %s", ok ? "ok" : "failed");
    GetHAL().delay(1600);
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
        show_self_test_result(false, sign_result);
        return;
    }

    const int verify_result =
        sui_signing_verify_signature_ed25519(sui_signature, kSelfTestMessage,
                                             sizeof(kSelfTestMessage));
    if (verify_result != 0) {
        ESP_LOGE(kTag, "Ed25519 verification self-test failed: %d", verify_result);
        wipe_bytes(sui_signature, sizeof(sui_signature));
        show_self_test_result(false, verify_result);
        return;
    }

    ESP_LOGI(kTag, "Ed25519 signing self-test ok: scheme=%u, signature_len=%u",
             sui_signature[0], static_cast<unsigned>(sizeof(sui_signature)));
    show_self_test_result(true, 0);
    wipe_bytes(sui_signature, sizeof(sui_signature));
}

}  // namespace agent_q
