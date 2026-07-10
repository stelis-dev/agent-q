#include "local_transport_pairing_scene.h"

#include <stdio.h>
#include <string.h>

#include "display_geometry.h"

namespace stopwatch_target {
namespace {

constexpr int kQrCodeSizePx = 286;

void set_label(lv_obj_t* label, const char* text)
{
    if (label != nullptr) {
        lv_label_set_text(label, text != nullptr ? text : "");
    }
}

}  // namespace

void LocalTransportPairingScene::create(lv_obj_t* parent)
{
    destroy();
    if (parent == nullptr) {
        return;
    }

    scene_root_ = lv_obj_create(parent);
    lv_obj_set_size(scene_root_, kDisplaySizePx, kDisplaySizePx);
    lv_obj_align(scene_root_, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(scene_root_, lv_color_hex(0x050607), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(scene_root_, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_border_width(scene_root_, 0, LV_PART_MAIN);
    lv_obj_set_style_radius(scene_root_, kDisplayCenterPx, LV_PART_MAIN);
    lv_obj_set_style_pad_all(scene_root_, 0, LV_PART_MAIN);
    lv_obj_remove_flag(scene_root_, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_clear_flag(scene_root_, LV_OBJ_FLAG_SCROLLABLE);

    title_label_ = lv_label_create(scene_root_);
    lv_obj_set_style_text_font(title_label_, &lv_font_montserrat_20, LV_PART_MAIN);
    lv_obj_set_style_text_color(title_label_, lv_color_hex(0xF4F7F8), LV_PART_MAIN);
    lv_obj_set_width(title_label_, 240);
    lv_obj_set_style_text_align(title_label_, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_obj_align(title_label_, LV_ALIGN_TOP_MID, 0, 28);

    qr_code_ = lv_qrcode_create(scene_root_);
    lv_qrcode_set_size(qr_code_, kQrCodeSizePx);
    lv_qrcode_set_dark_color(qr_code_, lv_color_hex(0x050607));
    lv_qrcode_set_light_color(qr_code_, lv_color_hex(0xF4F7F8));
    lv_qrcode_set_quiet_zone(qr_code_, true);
    lv_obj_align(qr_code_, LV_ALIGN_CENTER, 0, 0);

    detail_label_ = lv_label_create(scene_root_);
    lv_obj_set_style_text_font(detail_label_, &lv_font_montserrat_16, LV_PART_MAIN);
    lv_obj_set_style_text_color(detail_label_, lv_color_hex(0xC9D2D8), LV_PART_MAIN);
    lv_obj_set_width(detail_label_, 300);
    lv_obj_set_style_text_align(detail_label_, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_obj_align(detail_label_, LV_ALIGN_BOTTOM_MID, 0, -30);

    set_visible(false);
}

void LocalTransportPairingScene::destroy()
{
    if (scene_root_ != nullptr) {
        lv_obj_delete(scene_root_);
    }
    scene_root_ = nullptr;
    title_label_ = nullptr;
    qr_code_ = nullptr;
    detail_label_ = nullptr;
    deadline_ = 0;
    rendered_seconds_ = UINT32_MAX;
    visible_ = false;
}

bool LocalTransportPairingScene::show_pairing(const char* payload, TickType_t deadline)
{
    if (scene_root_ == nullptr || qr_code_ == nullptr ||
        payload == nullptr || payload[0] == '\0' || deadline == 0 ||
        lv_qrcode_update(qr_code_, payload, strlen(payload)) != LV_RESULT_OK) {
        return false;
    }
    deadline_ = deadline;
    rendered_seconds_ = UINT32_MAX;
    lv_obj_set_style_text_color(title_label_, lv_color_hex(0xF4F7F8), LV_PART_MAIN);
    set_label(title_label_, "PAIR");
    lv_obj_remove_flag(qr_code_, LV_OBJ_FLAG_HIDDEN);
    set_visible(true);
    update(xTaskGetTickCount());
    return true;
}

void LocalTransportPairingScene::show_result(const char* message, bool error)
{
    deadline_ = 0;
    rendered_seconds_ = UINT32_MAX;
    lv_obj_add_flag(qr_code_, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_style_text_color(
        title_label_,
        error ? lv_color_hex(0xFF8A8A) : lv_color_hex(0x8EE0A1),
        LV_PART_MAIN);
    set_label(title_label_, message);
    set_label(detail_label_, "");
    set_visible(true);
}

void LocalTransportPairingScene::set_visible(bool visible)
{
    visible_ = visible;
    if (scene_root_ == nullptr) {
        return;
    }
    if (visible) {
        lv_obj_remove_flag(scene_root_, LV_OBJ_FLAG_HIDDEN);
        lv_obj_move_foreground(scene_root_);
    } else {
        lv_obj_add_flag(scene_root_, LV_OBJ_FLAG_HIDDEN);
    }
}

void LocalTransportPairingScene::update(TickType_t now)
{
    if (!visible_ || deadline_ == 0 || detail_label_ == nullptr) {
        return;
    }
    const TickType_t remaining_ticks =
        static_cast<int32_t>(deadline_ - now) > 0 ? deadline_ - now : 0;
    const uint32_t remaining_ms = pdTICKS_TO_MS(remaining_ticks);
    const uint32_t seconds = (remaining_ms + 999U) / 1000U;
    if (seconds == rendered_seconds_) {
        return;
    }
    rendered_seconds_ = seconds;
    char detail[48] = {};
    snprintf(detail, sizeof(detail), "%lus  A CANCEL", static_cast<unsigned long>(seconds));
    set_label(detail_label_, detail);
}

}  // namespace stopwatch_target
