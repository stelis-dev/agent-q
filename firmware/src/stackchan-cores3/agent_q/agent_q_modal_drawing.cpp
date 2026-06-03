#include "agent_q_modal_drawing.h"

#include <stdio.h>
#include <string.h>

#include "agent_q_avatar_overlay_drawing.h"
#include "agent_q_bip39_wordlist.h"
#include "agent_q_connect_settings.h"
#include "agent_q_display_power.h"
#include "agent_q_local_auth.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_local_reset.h"
#include "agent_q_method_signing_request_flow.h"
#include "agent_q_policy_update_flow.h"
#include "agent_q_provisioning_flow.h"
#include "hal/hal.h"

namespace agent_q {

namespace {


constexpr size_t kRecoveryPhrasePrefixCellCount = kProvisioningFlowPhrasePrefixCellCount;
constexpr size_t kRecoverWordsPerPage = kProvisioningFlowRecoverWordsPerPage;
constexpr size_t kRecoverPageCount = kProvisioningFlowRecoverPageCount;
constexpr int kScreenHeight = 240;
constexpr int kScreenWidth = 320;
constexpr int kDecisionStripHeight = 34;
constexpr int kDecisionPanelHeight = kDecisionStripHeight;
constexpr int kDecisionButtonWidth = kScreenWidth / 2;
constexpr int kDecisionCornerRadius = 10;
constexpr int kRecoveryPhraseButtonHeight = 28;
constexpr int kRecoveryPhraseButtonRadius = 7;
constexpr int kRecoveryPhraseButtonWidth = 142;
constexpr int kRecoveryPhraseButtonLeftX = 8;
constexpr int kRecoveryPhraseButtonRightX = 154;
constexpr int kRecoveryPhraseButtonBottomMargin = 8;
constexpr int kRecoveryPhraseTopMargin = kRecoveryPhraseButtonBottomMargin;
constexpr int kSetupActionButtonY =
    kScreenHeight - 16 - kRecoveryPhraseButtonHeight - kRecoveryPhraseButtonBottomMargin;
constexpr int kPinPanelButtonRadius = 6;
constexpr int kPinPanelButtonHeight = 22;
constexpr int kPinKeypadButtonWidth = 90;
constexpr int kPinKeypadGridLeft = 17;
constexpr int kPinKeypadGridTop = 78;
constexpr int kPinKeypadRowHeight = 25;
constexpr int kSettingsMenuButtonCenterX = (kScreenWidth - 16 - kRecoveryPhraseButtonWidth) / 2;
constexpr int kSettingsMenuRowLabelX = 24;
constexpr int kSettingsMenuRowControlX = 218;
constexpr int kSettingsMenuRowOneY = 62;
constexpr int kSettingsMenuRowTwoY = 100;
constexpr int kSettingsMenuRowThreeY = 138;
constexpr int kSettingsMenuActionButtonWidth = 72;
constexpr int kSettingsMenuActionButtonHeight = 26;
constexpr int kSetupMenuGenerateButtonY = 78;
constexpr int kSetupMenuRecoverButtonY = 114;
constexpr int kMnemonicWordCellWidth = 90;
constexpr int kMnemonicWordCellHeight = 22;
constexpr int kMnemonicWordCellLeft = 17;
constexpr int kMnemonicWordIndexWidth = 22;
constexpr int kMnemonicWordPrefixLeft = 30;
constexpr int kMnemonicWordPrefixWidth = 54;
constexpr int kRecoverWordCellTop = 42;
constexpr int kRecoverAlphabetButtonWidth = 22;
constexpr int kRecoverAlphabetButtonHeight = 18;
constexpr int kRecoverAlphabetLeft = 9;
constexpr int kRecoverAlphabetTop = 82;
constexpr int kRecoverCandidateLeft = 17;
constexpr int kRecoverCandidateTop = 124;
constexpr int kRecoverCandidateWidth = 270;
constexpr int kRecoverCandidateHeight = 58;
constexpr int kRecoverCandidateButtonWidth = 84;
constexpr int kRecoverCandidateButtonHeight = 22;
constexpr int kRecoverNavigationButtonWidth = 68;
constexpr int kPinProcessingOverlaySize = 50;
constexpr int kPinProcessingOverlayX =
    (kScreenWidth - 16 - kPinProcessingOverlaySize) / 2;
constexpr int kPinProcessingOverlayY =
    (kScreenHeight - 16 - kPinProcessingOverlaySize) / 2;
constexpr int kPinProcessingSpinnerSize = 34;
constexpr int kPinProcessingArcDegrees = 112;
constexpr int kPinProcessingSpinMs = 650;
constexpr uint32_t kSetupCellBorderColor = 0xB7E4C7;
constexpr uint32_t kSetupInputPressedColor = 0x1D4ED8;
constexpr uint32_t kDisabledControlTextColor = 0x98A2B3;
constexpr uint32_t kDisabledActionTextColor = 0xEAECF0;

enum class SetupButtonKind {
    solid_action,
    outlined_keypad,
};

AgentQModalDrawingCallbacks g_callbacks;
lv_obj_t* g_pin_processing_overlay = nullptr;

void on_pin_processing_overlay_deleted(lv_event_t* event)
{
    lv_obj_t* target = static_cast<lv_obj_t*>(lv_event_get_target(event));
    if (target == g_pin_processing_overlay) {
        g_pin_processing_overlay = nullptr;
    }
}

void clear_pin_processing_overlay_locked()
{
    if (g_pin_processing_overlay == nullptr) {
        return;
    }
    if (lv_obj_is_valid(g_pin_processing_overlay)) {
        lv_obj_delete(g_pin_processing_overlay);
    }
    g_pin_processing_overlay = nullptr;
}
uint16_t g_recover_candidate_event_indices[kBip39WordCount] = {};

}  // namespace

void modal_drawing_set_callbacks(const AgentQModalDrawingCallbacks& callbacks)
{
    g_callbacks = callbacks;
}

static bool make_button_label_with_font(
    lv_obj_t* button,
    const char* text,
    const lv_font_t* font,
    lv_event_cb_t callback,
    void* user_data = nullptr)
{
    lv_obj_t* label = lv_label_create(button);
    if (label == nullptr) {
        return false;
    }
    lv_obj_remove_style_all(label);
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_remove_flag(label, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(label, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_text_font(label, font, 0);
    lv_obj_set_style_text_color(label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
    lv_obj_center(label);
    lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(label, callback, LV_EVENT_CLICKED, user_data);
    return true;
}

static void make_decision_button_corner_fill(lv_obj_t* button, lv_align_t align, lv_color_t color, lv_event_cb_t callback)
{
    lv_obj_t* fill = lv_obj_create(button);
    lv_obj_remove_style_all(fill);
    lv_obj_set_size(fill, kDecisionCornerRadius, kDecisionCornerRadius);
    lv_obj_align(fill, align, 0, 0);
    lv_obj_set_style_bg_color(fill, color, 0);
    lv_obj_set_style_bg_opa(fill, LV_OPA_COVER, 0);
    lv_obj_add_flag(fill, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(fill, callback, LV_EVENT_CLICKED, nullptr);
}

static void make_decision_button(lv_obj_t* parent, const char* text, int x, lv_color_t color, lv_event_cb_t callback)
{
    // A plain clickable object avoids themed button shadows/scrollbars that can
    // show up as stray vertical lines over the avatar.
    lv_obj_t* button = lv_obj_create(parent);
    lv_obj_remove_style_all(button);
    lv_obj_set_size(button, kDecisionButtonWidth, kDecisionStripHeight);
    lv_obj_align(button, LV_ALIGN_TOP_LEFT, x, 0);
    lv_obj_add_flag(button, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_remove_flag(button, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(button, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(button, kDecisionCornerRadius, 0);
    lv_obj_set_style_border_width(button, 0, 0);
    lv_obj_set_style_outline_width(button, 0, 0);
    lv_obj_set_style_shadow_width(button, 0, 0);
    lv_obj_set_style_pad_all(button, 0, 0);
    lv_obj_set_style_bg_color(button, color, 0);
    lv_obj_set_style_bg_opa(button, LV_OPA_COVER, 0);
    lv_obj_add_event_cb(button, callback, LV_EVENT_CLICKED, nullptr);
    if (x == 0) {
        make_decision_button_corner_fill(button, LV_ALIGN_TOP_RIGHT, color, callback);
        make_decision_button_corner_fill(button, LV_ALIGN_BOTTOM_LEFT, color, callback);
        make_decision_button_corner_fill(button, LV_ALIGN_BOTTOM_RIGHT, color, callback);
    } else {
        make_decision_button_corner_fill(button, LV_ALIGN_TOP_LEFT, color, callback);
        make_decision_button_corner_fill(button, LV_ALIGN_BOTTOM_LEFT, color, callback);
        make_decision_button_corner_fill(button, LV_ALIGN_BOTTOM_RIGHT, color, callback);
    }
    make_button_label_with_font(button, text, &lv_font_montserrat_14, callback);
}

static bool make_setup_button(
    lv_obj_t* parent,
    const char* text,
    int x,
    int y,
    int width,
    int height,
    SetupButtonKind kind,
    lv_color_t color,
    lv_event_cb_t callback,
    const void* user_data = nullptr,
    bool enabled = true)
{
    lv_obj_t* button = lv_obj_create(parent);
    if (button == nullptr) {
        return false;
    }

    lv_obj_remove_style_all(button);
    lv_obj_set_size(button, width, height);
    lv_obj_align(button, LV_ALIGN_TOP_LEFT, x, y);
    lv_obj_remove_flag(button, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(button, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_outline_width(button, 0, 0);
    lv_obj_set_style_shadow_width(button, 0, 0);
    lv_obj_set_style_pad_all(button, 0, 0);
    lv_obj_set_style_bg_color(button, color, 0);

    lv_color_t label_color = color;
    if (kind == SetupButtonKind::solid_action) {
        lv_obj_set_style_radius(button, kRecoveryPhraseButtonRadius, 0);
        lv_obj_set_style_border_width(button, 0, 0);
        lv_obj_set_style_bg_opa(button, enabled ? LV_OPA_COVER : LV_OPA_40, 0);
        label_color = lv_color_hex(enabled ? 0xFFFFFF : kDisabledActionTextColor);
        if (enabled) {
            lv_obj_set_style_bg_opa(button, LV_OPA_80, LV_STATE_PRESSED);
        }
    } else {
        lv_obj_set_style_radius(button, kPinPanelButtonRadius, 0);
        lv_obj_set_style_border_width(button, 1, 0);
        lv_obj_set_style_border_color(button, lv_color_hex(kSetupCellBorderColor), 0);
        lv_obj_set_style_bg_opa(button, LV_OPA_TRANSP, 0);
        label_color = enabled ? color : lv_color_hex(kDisabledControlTextColor);
        if (enabled) {
            lv_obj_set_style_bg_color(button, color, LV_STATE_PRESSED);
            lv_obj_set_style_bg_opa(button, LV_OPA_30, LV_STATE_PRESSED);
        }
    }

    void* callback_data = const_cast<void*>(user_data);
    if (enabled) {
        lv_obj_add_flag(button, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(button, callback, LV_EVENT_CLICKED, callback_data);
    }

    lv_obj_t* label = lv_label_create(button);
    if (label == nullptr) {
        return false;
    }
    lv_obj_remove_style_all(label);
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_remove_flag(label, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(label, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_width(label, width);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(label, label_color, 0);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
    if (enabled && kind == SetupButtonKind::outlined_keypad) {
        lv_obj_set_style_radius(label, kPinPanelButtonRadius, LV_STATE_PRESSED);
        lv_obj_set_style_bg_color(label, color, LV_STATE_PRESSED);
        lv_obj_set_style_bg_opa(label, LV_OPA_30, LV_STATE_PRESSED);
    }
    lv_obj_center(label);
    if (enabled) {
        lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(label, callback, LV_EVENT_CLICKED, callback_data);
    }
    return true;
}

static bool make_pin_keypad_buttons(lv_obj_t* parent, bool buttons_enabled)
{
    static const char* const kDigits[10] = {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    };

    for (int digit = 1; digit <= 9; ++digit) {
        const int index = digit - 1;
        const int column = index % 3;
        const int row = index / 3;
        if (!make_setup_button(
                parent,
                kDigits[digit],
                kPinKeypadGridLeft + column * kPinKeypadButtonWidth,
                kPinKeypadGridTop + row * kPinKeypadRowHeight,
                kPinKeypadButtonWidth,
                kPinPanelButtonHeight,
                SetupButtonKind::outlined_keypad,
                lv_color_hex(kSetupInputPressedColor),
                g_callbacks.on_pin_digit_clicked,
                kDigits[digit],
                buttons_enabled)) {
            return false;
        }
    }

    return make_setup_button(
               parent,
               "Clear",
               kPinKeypadGridLeft,
               kPinKeypadGridTop + 3 * kPinKeypadRowHeight,
               kPinKeypadButtonWidth,
               kPinPanelButtonHeight,
               SetupButtonKind::outlined_keypad,
               lv_color_hex(0x667085),
               g_callbacks.on_pin_clear_clicked,
               nullptr,
               buttons_enabled) &&
           make_setup_button(
               parent,
               kDigits[0],
               kPinKeypadGridLeft + kPinKeypadButtonWidth,
               kPinKeypadGridTop + 3 * kPinKeypadRowHeight,
               kPinKeypadButtonWidth,
               kPinPanelButtonHeight,
               SetupButtonKind::outlined_keypad,
               lv_color_hex(kSetupInputPressedColor),
               g_callbacks.on_pin_digit_clicked,
               kDigits[0],
               buttons_enabled) &&
           make_setup_button(
               parent,
               LV_SYMBOL_BACKSPACE,
               kPinKeypadGridLeft + 2 * kPinKeypadButtonWidth,
               kPinKeypadGridTop + 3 * kPinKeypadRowHeight,
               kPinKeypadButtonWidth,
               kPinPanelButtonHeight,
               SetupButtonKind::outlined_keypad,
               lv_color_hex(0x667085),
               g_callbacks.on_pin_backspace_clicked,
               nullptr,
               buttons_enabled);
}

static bool make_settings_row_label(lv_obj_t* parent, const char* text, int y)
{
    lv_obj_t* label = lv_label_create(parent);
    if (label == nullptr) {
        return false;
    }
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(label, kSettingsMenuRowControlX - kSettingsMenuRowLabelX - 8);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(label, lv_color_hex(0x063A1D), 0);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, kSettingsMenuRowLabelX, y + 4);
    return true;
}

static void rotate_processing_arc(void* obj, int32_t rotation)
{
    lv_arc_set_rotation(static_cast<lv_obj_t*>(obj), rotation);
}

static bool make_pin_processing_overlay(lv_obj_t* parent)
{
    if (g_pin_processing_overlay != nullptr &&
        lv_obj_is_valid(g_pin_processing_overlay) &&
        lv_obj_get_parent(g_pin_processing_overlay) == parent) {
        lv_obj_move_foreground(g_pin_processing_overlay);
        return true;
    }

    clear_pin_processing_overlay_locked();

    lv_obj_t* blocker = lv_obj_create(parent);
    if (blocker == nullptr) {
        return false;
    }

    lv_obj_remove_style_all(blocker);
    lv_obj_set_size(blocker, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(blocker, LV_ALIGN_TOP_LEFT, 0, 0);
    lv_obj_remove_flag(blocker, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(blocker, LV_SCROLLBAR_MODE_OFF);
    lv_obj_add_flag(blocker, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_bg_opa(blocker, LV_OPA_TRANSP, 0);

    lv_obj_t* card = lv_obj_create(blocker);
    if (card == nullptr) {
        lv_obj_delete(blocker);
        return false;
    }

    lv_obj_remove_style_all(card);
    lv_obj_set_size(card, kPinProcessingOverlaySize, kPinProcessingOverlaySize);
    lv_obj_align(card, LV_ALIGN_TOP_LEFT, kPinProcessingOverlayX, kPinProcessingOverlayY);
    lv_obj_remove_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(card, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(card, kPinPanelButtonRadius, 0);
    lv_obj_set_style_border_width(card, 0, 0);
    lv_obj_set_style_bg_color(card, lv_color_hex(0x667085), 0);
    lv_obj_set_style_bg_opa(card, LV_OPA_40, 0);

#if LV_USE_ARC
    lv_obj_t* spinner = lv_arc_create(card);
    if (spinner == nullptr) {
        lv_obj_delete(blocker);
        return false;
    }

    lv_obj_remove_style(spinner, nullptr, LV_PART_KNOB);
    lv_obj_remove_flag(spinner, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_size(spinner, kPinProcessingSpinnerSize, kPinProcessingSpinnerSize);
    lv_arc_set_bg_angles(spinner, 0, 360);
    lv_arc_set_angles(spinner, 0, kPinProcessingArcDegrees);
    lv_arc_set_rotation(spinner, 270);
    lv_obj_set_style_arc_width(spinner, 4, LV_PART_MAIN);
    lv_obj_set_style_arc_width(spinner, 4, LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(spinner, lv_color_hex(0xD0D5DD), LV_PART_MAIN);
    lv_obj_set_style_arc_color(spinner, lv_color_hex(0x24875A), LV_PART_INDICATOR);
    lv_obj_center(spinner);

    lv_anim_t animation;
    lv_anim_init(&animation);
    lv_anim_set_var(&animation, spinner);
    lv_anim_set_values(&animation, 0, 360);
    lv_anim_set_duration(&animation, kPinProcessingSpinMs);
    lv_anim_set_repeat_count(&animation, LV_ANIM_REPEAT_INFINITE);
    lv_anim_set_path_cb(&animation, lv_anim_path_linear);
    lv_anim_set_exec_cb(&animation, rotate_processing_arc);
    lv_anim_start(&animation);
#else
    lv_obj_t* loading = lv_label_create(card);
    if (loading != nullptr) {
        lv_label_set_text(loading, "...");
        lv_obj_set_style_text_font(loading, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(loading, lv_color_hex(0xFFFFFF), 0);
        lv_obj_center(loading);
    }
#endif

    g_pin_processing_overlay = blocker;
    lv_obj_add_event_cb(blocker, on_pin_processing_overlay_deleted, LV_EVENT_DELETE, nullptr);
    lv_obj_move_foreground(blocker);
    return true;
}

bool modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind expected_kind)
{
    LvglLockGuard lock;
    lv_obj_t* panel = drawing_surface_panel_locked();
    if (panel == nullptr ||
        drawing_surface_panel_kind_locked() != expected_kind) {
        return false;
    }
    return make_pin_processing_overlay(panel);
}


bool modal_draw_decision_panel()
{
    {
        LvglLockGuard lock;
        drawing_surface_clear_panel_locked();

        lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::decision_strip);
        if (panel == nullptr) {
            return false;
        }
        lv_obj_remove_style_all(panel);
        lv_obj_set_size(panel, kScreenWidth, kDecisionPanelHeight);
        lv_obj_align(panel, LV_ALIGN_BOTTOM_MID, 0, 0);
        lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
        lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
        lv_obj_set_style_radius(panel, 0, 0);
        lv_obj_set_style_clip_corner(panel, true, 0);
        lv_obj_set_style_border_width(panel, 0, 0);
        lv_obj_set_style_outline_width(panel, 0, 0);
        lv_obj_set_style_shadow_width(panel, 0, 0);
        lv_obj_set_style_bg_opa(panel, LV_OPA_TRANSP, 0);
        lv_obj_set_style_pad_all(panel, 0, 0);

        make_decision_button(panel, "Cancel", 0, lv_color_hex(0xA53B3B), g_callbacks.on_no_clicked);
        make_decision_button(panel, "Confirm", kDecisionButtonWidth, lv_color_hex(0x24875A), g_callbacks.on_yes_clicked);

        drawing_surface_move_panel_foreground_locked();
    }
    return true;
}


bool modal_draw_setup_choice_panel()
{
    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::setup_choice);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "Set up Agent-Q");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 24);

    if (!make_setup_button(
            panel,
            "Generate",
            kSettingsMenuButtonCenterX,
            kSetupMenuGenerateButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            g_callbacks.on_setup_generate_clicked) ||
        !make_setup_button(
            panel,
            "Recover",
            kSettingsMenuButtonCenterX,
            kSetupMenuRecoverButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x1D4ED8),
            g_callbacks.on_setup_recover_clicked) ||
        !make_setup_button(
            panel,
            "Cancel",
            kSettingsMenuButtonCenterX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x667085),
            g_callbacks.on_setup_cancel_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

static bool make_recover_word_cell(lv_obj_t* parent, uint8_t slot)
{
    static const uint8_t kSlotUserData[kRecoverWordsPerPage] = {0, 1, 2};
    if (slot >= kRecoverWordsPerPage) {
        return false;
    }

    const agent_q::AgentQProvisioningFlowSnapshot flow =
        agent_q::provisioning_flow_snapshot();
    const size_t global_slot =
        agent_q::provisioning_flow_recover_global_word_slot_for(flow.recover_page, slot);
    if (global_slot >= agent_q::kBip39MnemonicWordCount) {
        return false;
    }

    lv_obj_t* cell = lv_obj_create(parent);
    if (cell == nullptr) {
        return false;
    }
    lv_obj_remove_flag(cell, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_size(cell, kMnemonicWordCellWidth, kMnemonicWordCellHeight);
    lv_obj_align(
        cell,
        LV_ALIGN_TOP_LEFT,
        kMnemonicWordCellLeft + static_cast<int>(slot) * kMnemonicWordCellWidth,
        kRecoverWordCellTop);
    lv_obj_set_style_radius(cell, 4, 0);
    lv_obj_set_style_border_width(cell, 1, 0);
    lv_obj_set_style_border_color(cell, lv_color_hex(kSetupCellBorderColor), 0);
    lv_obj_set_style_bg_color(cell, lv_color_hex(
        slot == flow.recover_active_slot ? 0xE9F8EF : 0xFFFFFF), 0);
    lv_obj_set_style_bg_opa(cell, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(cell, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(cell, LV_OPA_30, LV_STATE_PRESSED);
    lv_obj_set_style_pad_all(cell, 0, 0);
    lv_obj_add_flag(cell, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(
        cell,
        g_callbacks.on_recover_slot_clicked,
        LV_EVENT_CLICKED,
        const_cast<uint8_t*>(&kSlotUserData[slot]));

    lv_obj_t* index_label = lv_label_create(cell);
    if (index_label == nullptr) {
        return false;
    }
    char index_text[3] = {};
    snprintf(index_text, sizeof(index_text), "%02u", static_cast<unsigned>(global_slot + 1));
    lv_label_set_text(index_label, index_text);
    lv_label_set_long_mode(index_label, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(index_label, kMnemonicWordIndexWidth);
    lv_obj_set_style_text_align(index_label, LV_TEXT_ALIGN_RIGHT, 0);
    lv_obj_set_style_text_font(index_label, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_color(index_label, lv_color_hex(0x475467), 0);
    lv_obj_set_style_bg_opa(index_label, LV_OPA_TRANSP, 0);
    lv_obj_set_style_radius(index_label, 4, LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(index_label, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(index_label, LV_OPA_30, LV_STATE_PRESSED);
    lv_obj_align(index_label, LV_ALIGN_LEFT_MID, 4, 0);
    lv_obj_add_flag(index_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(
        index_label,
        g_callbacks.on_recover_slot_clicked,
        LV_EVENT_CLICKED,
        const_cast<uint8_t*>(&kSlotUserData[slot]));

    lv_obj_t* prefix_label = lv_label_create(cell);
    if (prefix_label == nullptr) {
        return false;
    }
    const char* prefix = agent_q::provisioning_flow_recover_prefix(global_slot);
    lv_label_set_text(prefix_label, prefix[0] != '\0' ? prefix : "____");
    lv_label_set_long_mode(prefix_label, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(prefix_label, kMnemonicWordPrefixWidth);
    lv_obj_set_style_text_align(prefix_label, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(prefix_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(prefix_label, lv_color_hex(0x111827), 0);
    lv_obj_set_style_bg_opa(prefix_label, LV_OPA_TRANSP, 0);
    lv_obj_set_style_radius(prefix_label, 4, LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(prefix_label, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(prefix_label, LV_OPA_30, LV_STATE_PRESSED);
    lv_obj_align(prefix_label, LV_ALIGN_LEFT_MID, kMnemonicWordPrefixLeft, 0);
    lv_obj_add_flag(prefix_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(
        prefix_label,
        g_callbacks.on_recover_slot_clicked,
        LV_EVENT_CLICKED,
        const_cast<uint8_t*>(&kSlotUserData[slot]));
    return true;
}

static bool make_recover_alphabet_buttons(lv_obj_t* parent)
{
    static const char* const kLetters[26] = {
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
        "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    };

    for (int index = 0; index < 26; ++index) {
        char label[2] = {};
        label[0] = static_cast<char>('A' + index);
        const int column = index % 13;
        const int row = index / 13;
        if (!make_setup_button(
                parent,
                label,
                kRecoverAlphabetLeft + column * kRecoverAlphabetButtonWidth,
                kRecoverAlphabetTop + row * (kRecoverAlphabetButtonHeight + 4),
                kRecoverAlphabetButtonWidth,
                kRecoverAlphabetButtonHeight,
                SetupButtonKind::outlined_keypad,
                lv_color_hex(kSetupInputPressedColor),
                g_callbacks.on_recover_letter_clicked,
                kLetters[index])) {
            return false;
        }
    }
    return true;
}

static bool make_recover_candidate_area(lv_obj_t* parent)
{
    lv_obj_t* area = lv_obj_create(parent);
    if (area == nullptr) {
        return false;
    }
    lv_obj_remove_style_all(area);
    lv_obj_set_size(area, kRecoverCandidateWidth, kRecoverCandidateHeight);
    lv_obj_align(area, LV_ALIGN_TOP_LEFT, kRecoverCandidateLeft, kRecoverCandidateTop);
    lv_obj_set_scroll_dir(area, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(area, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_set_style_pad_all(area, 0, 0);
    lv_obj_set_style_bg_opa(area, LV_OPA_TRANSP, 0);

    const size_t global_slot = agent_q::provisioning_flow_recover_global_word_slot();
    const char* prefix = agent_q::provisioning_flow_recover_prefix(global_slot);
    if (prefix[0] == '\0') {
        lv_obj_t* label = lv_label_create(area);
        if (label == nullptr) {
            return false;
        }
        lv_label_set_text(label, "Tap a letter to list BIP-39 words.");
        lv_obj_set_width(label, kRecoverCandidateWidth - 8);
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(label, lv_color_hex(0x475467), 0);
        lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 16);
        return true;
    }

    size_t candidate_count = 0;
    for (uint16_t word_index = 0; word_index < agent_q::kBip39WordCount; ++word_index) {
        const char* word = agent_q::bip39_english_word(word_index);
        if (!agent_q::provisioning_flow_word_starts_with_prefix(word, prefix)) {
            continue;
        }
        if (candidate_count >= agent_q::kBip39WordCount) {
            break;
        }
        g_recover_candidate_event_indices[candidate_count] = word_index;

        lv_obj_t* button = lv_obj_create(area);
        if (button == nullptr) {
            return false;
        }
        const int column = static_cast<int>(candidate_count % 3);
        const int row = static_cast<int>(candidate_count / 3);
        lv_obj_remove_style_all(button);
        lv_obj_set_size(button, kRecoverCandidateButtonWidth, kRecoverCandidateButtonHeight);
        lv_obj_align(
            button,
            LV_ALIGN_TOP_LEFT,
            column * (kRecoverCandidateButtonWidth + 6),
            row * (kRecoverCandidateButtonHeight + 4));
        lv_obj_set_style_radius(button, kPinPanelButtonRadius, 0);
        lv_obj_set_style_border_width(button, 1, 0);
        lv_obj_set_style_border_color(button, lv_color_hex(kSetupCellBorderColor), 0);
        lv_obj_set_style_bg_opa(button, LV_OPA_TRANSP, 0);
        lv_obj_set_style_bg_color(button, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
        lv_obj_set_style_bg_opa(button, LV_OPA_30, LV_STATE_PRESSED);
        lv_obj_add_flag(button, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(
            button,
            g_callbacks.on_recover_candidate_clicked,
            LV_EVENT_CLICKED,
            &g_recover_candidate_event_indices[candidate_count]);

        lv_obj_t* label = lv_label_create(button);
        if (label == nullptr) {
            return false;
        }
        lv_obj_remove_style_all(label);
        lv_label_set_text_static(label, word);
        lv_label_set_long_mode(label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(label, kRecoverCandidateButtonWidth - 6);
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(label, &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(label, lv_color_hex(0x111827), 0);
        lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
        lv_obj_set_style_radius(label, kPinPanelButtonRadius, LV_STATE_PRESSED);
        lv_obj_set_style_bg_color(label, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
        lv_obj_set_style_bg_opa(label, LV_OPA_30, LV_STATE_PRESSED);
        lv_obj_center(label);
        lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(
            label,
            g_callbacks.on_recover_candidate_clicked,
            LV_EVENT_CLICKED,
            &g_recover_candidate_event_indices[candidate_count]);
        ++candidate_count;
    }

    if (candidate_count == 0) {
        lv_obj_t* label = lv_label_create(area);
        if (label == nullptr) {
            return false;
        }
        lv_label_set_text(label, "No matching BIP-39 words.");
        lv_obj_set_width(label, kRecoverCandidateWidth - 8);
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(label, lv_color_hex(0xA53B3B), 0);
        lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 16);
    }

    return true;
}

bool modal_draw_recover_word_entry_panel(const char* notice)
{
    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::recovery_word_entry);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    const agent_q::AgentQProvisioningFlowSnapshot flow =
        agent_q::provisioning_flow_snapshot();
    char title_text[32] = {};
    snprintf(title_text, sizeof(title_text), "Recover words %u-%u",
             static_cast<unsigned>(flow.recover_page * kRecoverWordsPerPage + 1),
             static_cast<unsigned>((flow.recover_page + 1) * kRecoverWordsPerPage));
    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, title_text);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

    if (notice != nullptr && notice[0] != '\0') {
        lv_obj_t* notice_label = lv_label_create(panel);
        if (notice_label == nullptr) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        lv_label_set_text(notice_label, notice);
        lv_obj_set_width(notice_label, kScreenWidth - 44);
        lv_obj_set_style_text_align(notice_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(notice_label, &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(notice_label, lv_color_hex(0xA53B3B), 0);
        lv_obj_align(notice_label, LV_ALIGN_TOP_MID, 0, 26);
    }

    for (uint8_t slot = 0; slot < kRecoverWordsPerPage; ++slot) {
        if (!make_recover_word_cell(panel, slot)) {
            drawing_surface_clear_panel_locked();
            return false;
        }
    }

    if (!make_recover_alphabet_buttons(panel) ||
        !make_recover_candidate_area(panel)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoverNavigationButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            g_callbacks.on_recover_cancel_clicked) ||
        !make_setup_button(
            panel,
            "Clear",
            kRecoveryPhraseButtonLeftX + kRecoverNavigationButtonWidth + 8,
            kSetupActionButtonY,
            kRecoverNavigationButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(0x667085),
            g_callbacks.on_recover_clear_clicked) ||
        !make_setup_button(
            panel,
            "Prev",
            kRecoveryPhraseButtonLeftX + 2 * (kRecoverNavigationButtonWidth + 8),
            kSetupActionButtonY,
            kRecoverNavigationButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x667085),
            g_callbacks.on_recover_previous_clicked,
            nullptr,
            flow.recover_page > 0) ||
        !make_setup_button(
            panel,
            flow.recover_page + 1 >= kRecoverPageCount ? "Verify" : "Next",
            kRecoveryPhraseButtonLeftX + 3 * (kRecoverNavigationButtonWidth + 8),
            kSetupActionButtonY,
            kRecoverNavigationButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            g_callbacks.on_recover_next_clicked,
            nullptr,
            flow.recover_current_page_complete)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_recovery_phrase_display(const char* recovery_phrase)
{
    if (recovery_phrase == nullptr || recovery_phrase[0] == '\0') {
        return false;
    }

    avatar_overlay_clear();

    LvglLockGuard lock;
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::recovery_phrase_display);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "BIP-39 prefixes (DEV)");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kRecoveryPhraseTopMargin);

    lv_obj_t* warning = lv_label_create(panel);
    if (warning == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(warning, "Write up-to-4-letter prefixes. Host cannot read them.");
    lv_label_set_long_mode(warning, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(warning, kScreenWidth - 44);
    lv_obj_set_style_text_align(warning, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(warning, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(warning, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(warning, LV_ALIGN_TOP_MID, 0, 22 + kRecoveryPhraseTopMargin);

    constexpr int kGridTop = 58 + kRecoveryPhraseTopMargin;
    constexpr int kGridRowHeight = 25;
    for (size_t index = 0; index < kRecoveryPhrasePrefixCellCount; ++index) {
        lv_obj_t* cell = lv_obj_create(panel);
        if (cell == nullptr) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        lv_obj_remove_flag(cell, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_size(cell, kMnemonicWordCellWidth, kMnemonicWordCellHeight);
        lv_obj_set_style_radius(cell, 4, 0);
        lv_obj_set_style_border_width(cell, 1, 0);
        lv_obj_set_style_border_color(cell, lv_color_hex(0xB7E4C7), 0);
        lv_obj_set_style_bg_color(cell, lv_color_hex(0xFFFFFF), 0);
        lv_obj_set_style_bg_opa(cell, LV_OPA_COVER, 0);
        lv_obj_set_style_pad_all(cell, 0, 0);
        const int column = static_cast<int>(index % 3);
        const int row = static_cast<int>(index / 3);
        lv_obj_align(
            cell,
            LV_ALIGN_TOP_LEFT,
            kMnemonicWordCellLeft + column * kMnemonicWordCellWidth,
            kGridTop + row * kGridRowHeight);

        lv_obj_t* index_label = lv_label_create(cell);
        if (index_label == nullptr) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        char index_text[3] = {};
        snprintf(index_text, sizeof(index_text), "%02u", static_cast<unsigned>(index + 1));
        lv_label_set_text(index_label, index_text);
        lv_label_set_long_mode(index_label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(index_label, kMnemonicWordIndexWidth);
        lv_obj_set_style_text_align(index_label, LV_TEXT_ALIGN_RIGHT, 0);
        lv_obj_set_style_text_font(index_label, &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(index_label, lv_color_hex(0x475467), 0);
        lv_obj_align(index_label, LV_ALIGN_LEFT_MID, 4, 0);

        lv_obj_t* prefix_label = lv_label_create(cell);
        if (prefix_label == nullptr) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        lv_label_set_text_static(prefix_label, agent_q::provisioning_flow_recovery_phrase_prefix_cell(index));
        lv_label_set_long_mode(prefix_label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(prefix_label, kMnemonicWordPrefixWidth);
        lv_obj_set_style_text_align(prefix_label, LV_TEXT_ALIGN_LEFT, 0);
        lv_obj_set_style_text_font(prefix_label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(prefix_label, lv_color_hex(0x111827), 0);
        lv_obj_align(prefix_label, LV_ALIGN_LEFT_MID, kMnemonicWordPrefixLeft, 0);
    }
    if (!make_setup_button(
            panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            g_callbacks.on_recovery_phrase_cancel_clicked) ||
        !make_setup_button(
            panel,
            "Confirm",
            kRecoveryPhraseButtonRightX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            g_callbacks.on_recovery_phrase_confirm_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_pin_setup_panel(const char* notice)
{
    avatar_overlay_clear();

    LvglLockGuard lock;
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::pin_entry);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    const agent_q::AgentQProvisioningFlowSnapshot flow =
        agent_q::provisioning_flow_snapshot();
    const bool repeat_stage = flow.stage == AgentQProvisioningFlowStage::pin_repeat_entry;
    const bool committing_stage = flow.stage == AgentQProvisioningFlowStage::pin_committing;
    const bool buttons_enabled = !committing_stage;
    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, committing_stage ? "Saving setup" : (repeat_stage ? "Repeat 6-digit PIN" : "Set 6-digit PIN"));
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

    lv_obj_t* message = lv_label_create(panel);
    if (message == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(
        message,
        notice != nullptr && notice[0] != '\0'
            ? notice
            : (committing_stage ? "Processing. Please wait." : "Choose a local setup PIN."));
    lv_label_set_long_mode(message, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message, kScreenWidth - 44);
    lv_obj_set_style_text_align(message, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(message, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(message, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(message, LV_ALIGN_TOP_MID, 0, 30);

    char pin_mask[agent_q::kLocalPinDigits + 1] = {};
    for (size_t index = 0; index < agent_q::kLocalPinDigits; ++index) {
        pin_mask[index] = index < flow.pin_entry_length ? '*' : '_';
    }
    char pin_text[16] = {};
    snprintf(pin_text, sizeof(pin_text), "PIN: %s", pin_mask);
    lv_obj_t* pin_label = lv_label_create(panel);
    if (pin_label == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(pin_label, pin_text);
    lv_obj_set_style_text_font(pin_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(pin_label, lv_color_hex(0x111827), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    if (!make_pin_keypad_buttons(panel, buttons_enabled)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            g_callbacks.on_pin_cancel_clicked,
            nullptr,
            buttons_enabled) ||
        !make_setup_button(
            panel,
            "Confirm",
            kRecoveryPhraseButtonRightX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            g_callbacks.on_pin_submit_clicked,
            nullptr,
            buttons_enabled)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (committing_stage && !make_pin_processing_overlay(panel)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_settings_menu_panel()
{
    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::settings_menu);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "Settings");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 24);

    bool require_pin_on_connect = true;
    const bool connect_setting_read_ok =
        agent_q::read_require_pin_on_connect(&require_pin_on_connect);

    // Settings are fixed rows: add future settings by appending the same
    // label/control pair, not by adding explanatory text blocks.
    if (!make_settings_row_label(panel, "PIN on connect", kSettingsMenuRowOneY) ||
        !make_setup_button(
            panel,
            require_pin_on_connect ? "ON" : "OFF",
            kSettingsMenuRowControlX,
            kSettingsMenuRowOneY,
            kSettingsMenuActionButtonWidth,
            kSettingsMenuActionButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(0x24875A),
            connect_setting_read_ok ? g_callbacks.on_settings_connect_pin_clicked : nullptr,
            nullptr,
            connect_setting_read_ok) ||
        !make_settings_row_label(panel, "Change PIN", kSettingsMenuRowTwoY) ||
        !make_setup_button(
            panel,
            "CHANGE",
            kSettingsMenuRowControlX,
            kSettingsMenuRowTwoY,
            kSettingsMenuActionButtonWidth,
            kSettingsMenuActionButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(0x24875A),
            g_callbacks.on_settings_change_pin_clicked) ||
        !make_settings_row_label(panel, "Reset device", kSettingsMenuRowThreeY) ||
        !make_setup_button(
            panel,
            "RESET",
            kSettingsMenuRowControlX,
            kSettingsMenuRowThreeY,
            kSettingsMenuActionButtonWidth,
            kSettingsMenuActionButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            g_callbacks.on_settings_reset_clicked) ||
        !make_setup_button(
            panel,
            "Close",
            kSettingsMenuButtonCenterX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(0x24875A),
            g_callbacks.on_settings_cancel_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_error_recovery_panel(bool confirm)
{
    const bool wiping =
        agent_q::local_reset_snapshot(xTaskGetTickCount()).stage ==
        agent_q::AgentQLocalResetStage::wiping;
    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::error_recovery);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(0xFFF7F7), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, wiping ? "Erasing device" : (confirm ? "Erase device data" : "Device data error"));
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x7A1E1E), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 26);

    lv_obj_t* message = lv_label_create(panel);
    if (message == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(
        message,
        wiping
            ? "Processing. Please wait."
            : (confirm
            ? "This deletes local root material, policy, PIN, and settings."
            : "Stored device material is inconsistent. Erase before setup."));
    lv_label_set_long_mode(message, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message, kScreenWidth - 54);
    lv_obj_set_style_text_align(message, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(message, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(message, lv_color_hex(0x3C0505), 0);
    lv_obj_align(message, LV_ALIGN_TOP_MID, 0, 70);

    if (wiping) {
        if (!make_pin_processing_overlay(panel)) {
            drawing_surface_clear_panel_locked();
            return false;
        }
    } else if (confirm) {
        if (!make_setup_button(
                panel,
                "Cancel",
                kRecoveryPhraseButtonLeftX,
                kSetupActionButtonY,
                kRecoveryPhraseButtonWidth,
                kRecoveryPhraseButtonHeight,
                SetupButtonKind::outlined_keypad,
                lv_color_hex(0xA53B3B),
                g_callbacks.on_error_recovery_cancel_clicked) ||
            !make_setup_button(
                panel,
                "Erase",
                kRecoveryPhraseButtonRightX,
                kSetupActionButtonY,
                kRecoveryPhraseButtonWidth,
                kRecoveryPhraseButtonHeight,
                SetupButtonKind::solid_action,
                lv_color_hex(0xA53B3B),
                g_callbacks.on_error_recovery_erase_clicked)) {
            drawing_surface_clear_panel_locked();
            return false;
        }
    } else if (!make_setup_button(
                   panel,
                   "Erase",
                   kSettingsMenuButtonCenterX,
                   kSetupActionButtonY,
                   kRecoveryPhraseButtonWidth,
                   kRecoveryPhraseButtonHeight,
                   SetupButtonKind::solid_action,
                   lv_color_hex(0xA53B3B),
                   g_callbacks.on_error_recovery_erase_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_reset_pin_panel(const char* notice)
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::reset_pin_entry);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    const bool processing_stage =
        reset.stage == agent_q::AgentQLocalResetStage::pin_verifying ||
        reset.stage == agent_q::AgentQLocalResetStage::wiping;
    const bool locked_stage = reset.lockout_active;
    const bool buttons_enabled = !processing_stage && !locked_stage;

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, processing_stage ? "Processing reset" : "Enter reset PIN");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

    lv_obj_t* message = lv_label_create(panel);
    if (message == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(
        message,
        notice != nullptr && notice[0] != '\0'
            ? notice
            : (processing_stage ? "Processing. Please wait." : "Confirm reset with local PIN."));
    lv_label_set_long_mode(message, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message, kScreenWidth - 44);
    lv_obj_set_style_text_align(message, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(message, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(message, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(message, LV_ALIGN_TOP_MID, 0, 30);

    char pin_mask[agent_q::kLocalPinDigits + 1] = {};
    for (size_t index = 0; index < agent_q::kLocalPinDigits; ++index) {
        pin_mask[index] = index < reset.pin_entry_length ? '*' : '_';
    }
    char pin_text[16] = {};
    snprintf(pin_text, sizeof(pin_text), "PIN: %s", pin_mask);
    lv_obj_t* pin_label = lv_label_create(panel);
    if (pin_label == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(pin_label, pin_text);
    lv_obj_set_style_text_font(pin_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(pin_label, lv_color_hex(0x111827), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    if (!make_pin_keypad_buttons(panel, buttons_enabled)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x667085),
            g_callbacks.on_reset_cancel_clicked,
            nullptr,
            !processing_stage) ||
        !make_setup_button(
            panel,
            "Reset",
            kRecoveryPhraseButtonRightX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            g_callbacks.on_pin_submit_clicked,
            nullptr,
            buttons_enabled)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (processing_stage && !make_pin_processing_overlay(panel)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

static const char* local_pin_auth_default_message(
    const agent_q::AgentQLocalPinAuthSnapshot& snapshot)
{
    if (snapshot.lockout_active) {
        return "Too many wrong PINs. Wait 30s.";
    }
    if (snapshot.processing) {
        return "Processing. Please wait.";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::connect) {
        return "Enter local PIN to connect.";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::policy_update) {
        const AgentQPolicyUpdateFlowSnapshot update = policy_update_flow_snapshot();
        static char message[48] = {};
        snprintf(message, sizeof(message), "Approve %s-only policy.",
                 update.highest_action != nullptr ? update.highest_action : "reject");
        return message;
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::method_signing) {
        return "Enter local PIN to sign reviewed request.";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::settings_change_pin) {
        if (snapshot.stage == AgentQLocalPinAuthStage::new_pin_entry) {
            return "Enter new PIN.";
        }
        if (snapshot.stage == AgentQLocalPinAuthStage::repeat_pin_entry) {
            return "Repeat new PIN.";
        }
        return "Enter current PIN.";
    }
    return "Enter PIN to change setting.";
}

static const char* local_pin_auth_title(const agent_q::AgentQLocalPinAuthSnapshot& snapshot)
{
    if (snapshot.processing) {
        return "Processing PIN";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::connect) {
        return "Connect PIN";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::policy_update) {
        return "Policy PIN";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::method_signing) {
        return "Signing PIN";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::settings_change_pin) {
        if (snapshot.stage == AgentQLocalPinAuthStage::new_pin_entry) {
            return "New PIN";
        }
        if (snapshot.stage == AgentQLocalPinAuthStage::repeat_pin_entry) {
            return "Repeat PIN";
        }
        return "Change PIN";
    }
    return "Settings PIN";
}

static bool make_signing_summary_line(lv_obj_t* parent, const char* text, int y)
{
    lv_obj_t* label = lv_label_create(parent);
    if (label == nullptr) {
        return false;
    }
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(label, kScreenWidth - 44);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(label, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 16, y);
    return true;
}

static bool method_signing_summary_ready(
    const agent_q::AgentQMethodSigningRequestSnapshot& signing)
{
    return signing.active &&
           signing.chain != nullptr &&
           signing.method != nullptr &&
           signing.network != nullptr &&
           signing.recipient != nullptr &&
           signing.amount != nullptr &&
           signing.gas_budget != nullptr &&
           signing.gas_price != nullptr &&
           signing.asset != nullptr &&
           signing.chain[0] != '\0' &&
           signing.method[0] != '\0' &&
           signing.network[0] != '\0' &&
           signing.recipient[0] != '\0' &&
           signing.amount[0] != '\0' &&
           signing.gas_budget[0] != '\0' &&
           signing.gas_price[0] != '\0' &&
           signing.asset[0] != '\0';
}

static bool make_method_signing_review_summary(lv_obj_t* panel)
{
    const agent_q::AgentQMethodSigningRequestSnapshot signing =
        method_signing_request_flow_snapshot();
    if (!method_signing_summary_ready(signing)) {
        return false;
    }

    char method_line[80] = {};
    char amount_line[80] = {};
    char asset_line[80] = {};
    char recipient_line_one[48] = {};
    char recipient_line_two[48] = {};
    char gas_budget_line[48] = {};
    char gas_price_line[48] = {};
    snprintf(method_line, sizeof(method_line), "%s/%s on %s", signing.chain, signing.method, signing.network);
    snprintf(amount_line, sizeof(amount_line), "Amount %s", signing.amount);
    snprintf(asset_line, sizeof(asset_line), "Asset %s", signing.asset);
    const size_t recipient_length = strlen(signing.recipient);
    const size_t recipient_first_length = recipient_length > 34 ? 34 : recipient_length;
    snprintf(
        recipient_line_one,
        sizeof(recipient_line_one),
        "To %.*s",
        static_cast<int>(recipient_first_length),
        signing.recipient);
    snprintf(
        recipient_line_two,
        sizeof(recipient_line_two),
        "%s",
        signing.recipient + recipient_first_length);
    snprintf(gas_budget_line, sizeof(gas_budget_line), "Gas budget %s", signing.gas_budget);
    snprintf(gas_price_line, sizeof(gas_price_line), "Gas price %s", signing.gas_price);

    return make_signing_summary_line(panel, method_line, 30) &&
           make_signing_summary_line(panel, amount_line, 50) &&
           make_signing_summary_line(panel, asset_line, 70) &&
           make_signing_summary_line(panel, recipient_line_one, 90) &&
           make_signing_summary_line(panel, recipient_line_two, 110) &&
           make_signing_summary_line(panel, gas_budget_line, 130) &&
           make_signing_summary_line(panel, gas_price_line, 150);
}

bool modal_draw_local_pin_auth_panel(const char* notice)
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(now);
    if (!snapshot.flow_active) {
        return false;
    }

    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::local_pin_auth);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    const bool buttons_enabled = !snapshot.processing && !snapshot.lockout_active;
    const bool method_signing = snapshot.purpose == AgentQLocalPinAuthPurpose::method_signing;
    const agent_q::AgentQMethodSigningRequestSnapshot signing_snapshot =
        method_signing ? method_signing_request_flow_snapshot() : agent_q::AgentQMethodSigningRequestSnapshot{};
    const bool method_signing_review =
        method_signing &&
        signing_snapshot.active &&
        signing_snapshot.stage == agent_q::AgentQMethodSigningRequestStage::awaiting_review;

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(
        title,
        method_signing_review ? "Review signing request" : local_pin_auth_title(snapshot));
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, method_signing_review ? 8 : (method_signing ? 2 : 8));

    if (method_signing_review) {
        if (!make_method_signing_review_summary(panel)) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        if (!make_setup_button(
                panel,
                "Cancel",
                kRecoveryPhraseButtonLeftX,
                kSetupActionButtonY,
                kRecoveryPhraseButtonWidth,
                kRecoveryPhraseButtonHeight,
                SetupButtonKind::solid_action,
                lv_color_hex(0x667085),
                g_callbacks.on_pin_cancel_clicked,
                nullptr,
                true) ||
            !make_setup_button(
                panel,
                "Enter PIN",
                kRecoveryPhraseButtonRightX,
                kSetupActionButtonY,
                kRecoveryPhraseButtonWidth,
                kRecoveryPhraseButtonHeight,
                SetupButtonKind::solid_action,
                lv_color_hex(0x24875A),
                g_callbacks.on_pin_submit_clicked,
                nullptr,
                true)) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        drawing_surface_move_panel_foreground_locked();
        return true;
    } else {
        lv_obj_t* message = lv_label_create(panel);
        if (message == nullptr) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        lv_label_set_text(
            message,
            notice != nullptr && notice[0] != '\0'
                ? notice
                : local_pin_auth_default_message(snapshot));
        lv_label_set_long_mode(message, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(message, kScreenWidth - 44);
        lv_obj_set_style_text_align(message, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(message, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(message, lv_color_hex(0x3A2B00), 0);
        lv_obj_align(message, LV_ALIGN_TOP_MID, 0, 30);
    }

    char pin_mask[agent_q::kLocalPinDigits + 1] = {};
    for (size_t index = 0; index < agent_q::kLocalPinDigits; ++index) {
        pin_mask[index] = index < snapshot.pin_entry_length ? '*' : '_';
    }
    char pin_text[16] = {};
    snprintf(pin_text, sizeof(pin_text), "PIN: %s", pin_mask);
    lv_obj_t* pin_label = lv_label_create(panel);
    if (pin_label == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(pin_label, pin_text);
    lv_obj_set_style_text_font(pin_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(pin_label, lv_color_hex(0x111827), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    if (!make_pin_keypad_buttons(panel, buttons_enabled)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x667085),
            g_callbacks.on_pin_cancel_clicked,
            nullptr,
            !snapshot.processing) ||
        !make_setup_button(
            panel,
            "Confirm",
            kRecoveryPhraseButtonRightX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            g_callbacks.on_pin_submit_clicked,
            nullptr,
            buttons_enabled)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (snapshot.processing && !make_pin_processing_overlay(panel)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}



}  // namespace agent_q
