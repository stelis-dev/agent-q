#include "agent_q_modal_drawing.h"

#include <stdio.h>
#include <string.h>

#include "agent_q_avatar_overlay_drawing.h"
#include "agent_q_bip39_wordlist.h"
#include "agent_q_human_approval_settings.h"
#include "agent_q_display_power.h"
#include "agent_q_local_auth.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_local_reset.h"
#include "agent_q_policy_update_flow.h"
#include "agent_q_provisioning_flow.h"
#include "agent_q_signing_mode.h"
#include "agent_q_ui_theme.h"
#include "freertos/task.h"
#include "hal/hal.h"

namespace agent_q {

namespace {


constexpr size_t kBackupPhrasePrefixCellCount = kProvisioningFlowPhrasePrefixCellCount;
constexpr size_t kImportWordsPerPage = kProvisioningFlowImportWordsPerPage;
constexpr size_t kImportPageCount = kProvisioningFlowImportPageCount;
constexpr int kScreenHeight = 240;
constexpr int kScreenWidth = 320;
// The modal panel fills the whole screen; only the rounded corners are kept (no
// outer margin). The panel sits at (0,0), so panel-relative child coordinates ARE
// screen coordinates, and a child whose bottom exceeds kPanelContentHeight (240) is
// clipped (panel overflow is hidden). All layout below is centered/anchored against
// these, so changing the panel size re-flows every modal from one place.
constexpr int kPanelContentWidth = kScreenWidth;    // 320 (full screen)
constexpr int kPanelContentHeight = kScreenHeight;  // 240 (full screen)
constexpr int kTimeoutTimerBarHeight = 4;
constexpr int kTimeoutTimerBarTrackInset = 8;
constexpr int kPanelGridCellWidth = 90;
constexpr int kPanelGridWidth = 3 * kPanelGridCellWidth;                     // 270
constexpr int kPanelGridLeft = (kPanelContentWidth - kPanelGridWidth) / 2;   // 25, centered
constexpr int kInsetPanelWidth = kPanelContentWidth;                         // 320, full width
constexpr int kModalTitleY = 16;  // unified modal title top (panel-relative); SoT
constexpr int kModalDescriptionY = 36;  // unified one-line description/subtitle top (below title)
constexpr int kPanelActionButtonGap = 8;
// Single source of truth for the bottom two-button decision row (left "reject" /
// "cancel" + right "confirm" / "sign") shared by every decision modal: connect
// review, user-signing review, policy-update review, backup-phrase display, PIN
// setup, reset PIN, error recovery, and local PIN auth. Every one of those rows
// MUST use these X/width constants together with kSetupActionButtonY (row Y) and
// kBackupPhraseButtonHeight (row height) so the layout stays identical across
// modals. Do NOT introduce a second decision-row constant set; extend these.
constexpr int kPanelActionButtonLeftX = kPanelGridLeft;
constexpr int kPanelActionButtonWidth =
    (kPanelGridWidth - kPanelActionButtonGap) / 2;
constexpr int kPanelActionButtonRightX =
    kPanelActionButtonLeftX + kPanelActionButtonWidth + kPanelActionButtonGap;
constexpr int kBackupPhraseButtonHeight = 28;
constexpr int kBackupPhraseButtonRadius = 7;
constexpr int kBackupPhraseButtonWidth = 142;
constexpr int kBackupPhraseButtonLeftX = 8;
constexpr int kBackupPhraseButtonRightX = 154;
constexpr int kBackupPhraseButtonBottomMargin = 8;
constexpr int kBackupPhraseTopMargin = kBackupPhraseButtonBottomMargin;
constexpr int kSetupActionButtonY =
    kPanelContentHeight - kBackupPhraseButtonHeight - kBackupPhraseButtonBottomMargin;
constexpr int kPinPanelButtonRadius = 6;
constexpr int kPinPanelButtonHeight = 22;
constexpr int kPinKeypadColumnGap = 6;  // horizontal gap between keypad columns
constexpr int kPinKeypadButtonWidth = (kPanelGridWidth - 2 * kPinKeypadColumnGap) / 3;  // 86
constexpr int kPinKeypadColumnStride = kPinKeypadButtonWidth + kPinKeypadColumnGap;      // 92
constexpr int kPinKeypadGridLeft = kPanelGridLeft;
constexpr int kPinKeypadGridTop = 78;
constexpr int kPinKeypadRowHeight = 25;
constexpr int kSettingsMenuButtonCenterX = (kPanelContentWidth - kBackupPhraseButtonWidth) / 2;
constexpr int kSettingsMenuContentY = 44;
constexpr int kSettingsMenuContentBottomGap = 8;
constexpr int kSettingsMenuContentHeight =
    kSetupActionButtonY - kSettingsMenuContentY - kSettingsMenuContentBottomGap;
constexpr int kSettingsMenuRowLabelX = 18;
constexpr int kSettingsMenuRowControlX = 208;
constexpr int kSettingsMenuRowHeight = 34;
constexpr int kSettingsMenuActionButtonWidth = 72;
constexpr int kSettingsMenuActionButtonHeight = 26;
constexpr int kConnectReviewTextLeft = 24;
constexpr int kConnectReviewClientNameValueY = 108;
constexpr int kConnectReviewClientNameValueWidth = kInsetPanelWidth - 48;
constexpr int kConnectReviewClientNameValueHeight = 34;
constexpr int kConnectReviewApprovalRowY = 150;
constexpr int kConnectReviewApprovalValueX = 104;
constexpr int kUserSigningReviewRowLabelX = 18;
constexpr int kUserSigningReviewRowValueX = 90;
constexpr int kUserSigningReviewRowTop = 34;
constexpr int kUserSigningReviewRowWidth = 206;
constexpr int kUserSigningReviewContentHeight = kSetupActionButtonY - kUserSigningReviewRowTop - 6;
constexpr int kUserSigningReviewNormalRowHeight = 16;
constexpr int kUserSigningReviewWrappedValueRowHeight = 34;
constexpr int kPolicyUpdateReviewRowTop = 50;
constexpr int kPolicyUpdateReviewRowHeight = 16;
constexpr int kPolicyUpdateReviewRowWidth = kInsetPanelWidth - 36;
constexpr int kPolicyUpdateReviewSummaryTop = 132;
constexpr int kPolicyUpdateReviewSummaryHeight =
    kSetupActionButtonY - kPolicyUpdateReviewSummaryTop - 6;
// Setup choice: three stacked buttons, vertically centered between the title and the
// bottom of the full-screen panel. Coordinates are panel-relative == screen (panel at
// 0,0); a child whose bottom exceeds kPanelContentHeight (240) is clipped, and it must
// also stay above the screen timeout bar at y=236. montserrat_14 line_height is 16, so
// the title (TOP_MID y=24) ends panel-y ~40.
//   block = 3*42 + 2*14 = 154, centered in [40,232] -> first Y = 58
//   Cancel bottom = 170 + 42 = 212  (<= 232, clears the y=236 timer bar). OK.
constexpr int kSetupChoiceButtonHeight = 42;
constexpr int kSetupChoiceButtonGap = 14;
constexpr int kSetupMenuGenerateButtonY = 58;
constexpr int kSetupMenuImportButtonY =
    kSetupMenuGenerateButtonY + kSetupChoiceButtonHeight + kSetupChoiceButtonGap;
constexpr int kSetupMenuCancelButtonY =
    kSetupMenuImportButtonY + kSetupChoiceButtonHeight + kSetupChoiceButtonGap;
constexpr int kMnemonicWordColumnGap = 6;  // horizontal gap between mnemonic columns
constexpr int kMnemonicWordCellWidth = (kPanelGridWidth - 2 * kMnemonicWordColumnGap) / 3;  // 86
constexpr int kMnemonicWordColumnStride = kMnemonicWordCellWidth + kMnemonicWordColumnGap;   // 92
constexpr int kMnemonicWordCellHeight = 22;
constexpr int kMnemonicWordCellLeft = kPanelGridLeft;
constexpr int kMnemonicWordIndexWidth = 22;
constexpr int kMnemonicWordPrefixLeft = 30;
constexpr int kMnemonicWordPrefixWidth = 54;
constexpr int kImportWordCellTop = 42;
constexpr int kImportAlphabetButtonWidth = 22;
constexpr int kImportAlphabetButtonHeight = 18;
constexpr int kImportAlphabetLeft = 9;
constexpr int kImportAlphabetTop = 82;
constexpr int kImportCandidateLeft = 17;
constexpr int kImportCandidateTop = 124;
constexpr int kImportCandidateWidth = 270;
constexpr int kImportCandidateHeight = 58;
constexpr int kImportCandidateButtonWidth = 84;
constexpr int kImportCandidateButtonHeight = 22;
constexpr int kImportNavigationButtonWidth = 68;
constexpr int kPinProcessingOverlaySize = 50;
constexpr int kPinProcessingOverlayX =
    (kPanelContentWidth - kPinProcessingOverlaySize) / 2;
constexpr int kPinProcessingOverlayY =
    (kPanelContentHeight - kPinProcessingOverlaySize) / 2;
constexpr int kPinProcessingSpinnerSize = 34;
constexpr int kPinProcessingArcDegrees = 112;
constexpr int kPinProcessingSpinMs = 650;
constexpr int kTimeoutTimerMinAnimationMs = 1;
constexpr uint32_t kSetupCellBorderColor = theme::kOutline;
constexpr uint32_t kSetupInputPressedColor = theme::kPressed;
constexpr uint32_t kDisabledControlTextColor = theme::kDisabledOnSurface;
constexpr uint32_t kDisabledActionTextColor = theme::kDisabledOnAction;

enum class SetupButtonKind {
    solid_action,
    outlined_keypad,
};

AgentQModalDrawingCallbacks g_callbacks;
lv_obj_t* g_pin_processing_overlay = nullptr;
lv_obj_t* g_screen_bottom_timeout_timer_bar = nullptr;

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

void on_screen_bottom_timeout_timer_bar_deleted(lv_event_t* event)
{
    lv_obj_t* target = static_cast<lv_obj_t*>(lv_event_get_target(event));
    if (target == g_screen_bottom_timeout_timer_bar) {
        g_screen_bottom_timeout_timer_bar = nullptr;
    }
}

void clear_screen_bottom_timeout_timer_bar_locked()
{
    if (g_screen_bottom_timeout_timer_bar == nullptr) {
        return;
    }
    if (lv_obj_is_valid(g_screen_bottom_timeout_timer_bar)) {
        lv_obj_delete(g_screen_bottom_timeout_timer_bar);
    }
    g_screen_bottom_timeout_timer_bar = nullptr;
}
uint16_t g_import_candidate_event_indices[kBip39WordCount] = {};

}  // namespace

void modal_drawing_set_callbacks(const AgentQModalDrawingCallbacks& callbacks)
{
    g_callbacks = callbacks;
}

static void set_timeout_timer_width(void* obj, int32_t width)
{
    lv_obj_set_width(static_cast<lv_obj_t*>(obj), width);
}

static void delete_linked_timeout_timer_bar(lv_event_t* event)
{
    lv_obj_t* track = static_cast<lv_obj_t*>(lv_event_get_user_data(event));
    if (track != nullptr && lv_obj_is_valid(track)) {
        lv_obj_delete(track);
    }
}

static bool make_timeout_timer_bar(
    lv_obj_t* parent,
    int x,
    int y,
    int width,
    AgentQTimeoutWindow timeout_window,
    TickType_t now,
    lv_obj_t** out_track = nullptr)
{
    if (!timeout_window_active(timeout_window) || width <= 0) {
        return true;
    }

    lv_obj_t* track = lv_obj_create(parent);
    if (track == nullptr) {
        return false;
    }
    if (out_track != nullptr) {
        *out_track = track;
    }
    lv_obj_remove_style_all(track);
    lv_obj_set_size(track, width, kTimeoutTimerBarHeight);
    lv_obj_align(track, LV_ALIGN_TOP_LEFT, x, y);
    lv_obj_remove_flag(track, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(track, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_scrollbar_mode(track, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(track, kTimeoutTimerBarHeight / 2, 0);
    lv_obj_set_style_bg_color(track, lv_color_hex(theme::kOutlineVariant), 0);
    lv_obj_set_style_bg_opa(track, LV_OPA_COVER, 0);

    lv_obj_t* fill = lv_obj_create(track);
    if (fill == nullptr) {
        lv_obj_delete(track);
        if (out_track != nullptr) {
            *out_track = nullptr;
        }
        return false;
    }
    lv_obj_remove_style_all(fill);
    lv_obj_set_height(fill, kTimeoutTimerBarHeight);
    lv_obj_align(fill, LV_ALIGN_LEFT_MID, 0, 0);
    lv_obj_remove_flag(fill, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(fill, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_scrollbar_mode(fill, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(fill, kTimeoutTimerBarHeight / 2, 0);
    lv_obj_set_style_bg_color(fill, lv_color_hex(theme::kPrimary), 0);
    lv_obj_set_style_bg_opa(fill, LV_OPA_COVER, 0);

    if (timeout_window_reached(timeout_window, now)) {
        lv_obj_set_width(fill, 0);
        return true;
    }

    const TickType_t remaining_ticks = timeout_window_remaining_ticks(timeout_window, now);
    const int32_t current_width = timeout_window_fill_width(timeout_window, now, width);
    lv_obj_set_width(fill, current_width);
    const uint32_t remaining_ms = pdTICKS_TO_MS(remaining_ticks);
    lv_anim_t animation;
    lv_anim_init(&animation);
    lv_anim_set_var(&animation, fill);
    lv_anim_set_values(&animation, current_width, 0);
    lv_anim_set_duration(&animation, remaining_ms > 0 ? remaining_ms : kTimeoutTimerMinAnimationMs);
    lv_anim_set_path_cb(&animation, lv_anim_path_linear);
    lv_anim_set_exec_cb(&animation, set_timeout_timer_width);
    lv_anim_start(&animation);
    return true;
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
        lv_obj_set_style_radius(button, kBackupPhraseButtonRadius, 0);
        lv_obj_set_style_border_width(button, 0, 0);
        lv_obj_set_style_bg_opa(button, enabled ? LV_OPA_COVER : LV_OPA_40, 0);
        label_color = lv_color_hex(enabled ? theme::kOnPrimary : kDisabledActionTextColor);
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
                kPinKeypadGridLeft + column * kPinKeypadColumnStride,
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
               lv_color_hex(theme::kSecondary),
               g_callbacks.on_pin_clear_clicked,
               nullptr,
               buttons_enabled) &&
           make_setup_button(
               parent,
               kDigits[0],
               kPinKeypadGridLeft + kPinKeypadColumnStride,
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
               kPinKeypadGridLeft + 2 * kPinKeypadColumnStride,
               kPinKeypadGridTop + 3 * kPinKeypadRowHeight,
               kPinKeypadButtonWidth,
               kPinPanelButtonHeight,
               SetupButtonKind::outlined_keypad,
               lv_color_hex(theme::kSecondary),
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
    lv_obj_set_style_text_color(label, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, kSettingsMenuRowLabelX, y + 4);
    return true;
}

static bool make_settings_menu_row(
    lv_obj_t* parent,
    const char* label,
    const char* button_text,
    int row_index,
    SetupButtonKind button_kind,
    lv_color_t color,
    lv_event_cb_t callback,
    bool enabled = true)
{
    const int y = row_index * kSettingsMenuRowHeight;
    return make_settings_row_label(parent, label, y) &&
           make_setup_button(
               parent,
               button_text,
               kSettingsMenuRowControlX,
               y,
               kSettingsMenuActionButtonWidth,
               kSettingsMenuActionButtonHeight,
               button_kind,
               color,
               callback,
               nullptr,
               enabled);
}

static bool make_user_signing_review_row(
    lv_obj_t* parent,
    const AgentQUserSigningReviewRow& row,
    int y)
{
    lv_obj_t* label = lv_label_create(parent);
    if (label == nullptr) {
        return false;
    }
    lv_label_set_text(label, row.label);
    lv_label_set_long_mode(label, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(label, kUserSigningReviewRowValueX - kUserSigningReviewRowLabelX - 8);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(label, &lv_font_unscii_8, 0);
    const bool warning = row.kind == AgentQUserSigningReviewRowKind::warning;
    const bool section = row.kind == AgentQUserSigningReviewRowKind::section;
    lv_obj_set_style_text_color(
        label,
        lv_color_hex(warning ? theme::kError : theme::kOnSurfaceVariant),
        0);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, kUserSigningReviewRowLabelX, y + 2);

    lv_obj_t* value = lv_label_create(parent);
    if (value == nullptr) {
        return false;
    }
    lv_label_set_text(value, row.value);
    const bool wrapped_value =
        row.kind == AgentQUserSigningReviewRowKind::wrapped_value ||
        row.kind == AgentQUserSigningReviewRowKind::section;
    lv_label_set_long_mode(
        value,
        wrapped_value ? LV_LABEL_LONG_WRAP : LV_LABEL_LONG_CLIP);
    lv_obj_set_width(value, kUserSigningReviewRowWidth);
    lv_obj_set_style_text_align(value, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(
        value,
        section ? &lv_font_montserrat_14 : &lv_font_unscii_8,
        0);
    lv_obj_set_style_text_color(
        value,
        lv_color_hex(warning ? theme::kError : theme::kOnSurface),
        0);
    lv_obj_align(value, LV_ALIGN_TOP_LEFT, kUserSigningReviewRowValueX, y + 2);
    return true;
}

static bool make_policy_update_review_row(
    lv_obj_t* parent,
    const char* label_text,
    const char* value_text,
    int y)
{
    char row_text[160] = {};
    snprintf(
        row_text,
        sizeof(row_text),
        "%s: %s",
        label_text != nullptr ? label_text : "",
        value_text != nullptr && value_text[0] != '\0' ? value_text : "none");

    lv_obj_t* row = lv_label_create(parent);
    if (row == nullptr) {
        return false;
    }
    lv_label_set_text(row, row_text);
    lv_label_set_long_mode(row, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(row, kPolicyUpdateReviewRowWidth);
    lv_obj_set_style_text_align(row, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(row, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_color(row, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(row, LV_ALIGN_TOP_LEFT, 18, y + 2);
    return true;
}

static void format_policy_hash_prefix(const char* policy_hash, char* output, size_t output_size)
{
    if (output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (policy_hash == nullptr || policy_hash[0] == '\0') {
        snprintf(output, output_size, "none");
        return;
    }
    if (strncmp(policy_hash, "sha256:", 7) == 0 && strlen(policy_hash) >= 15) {
        snprintf(output, output_size, "sha256:%.8s", policy_hash + 7);
        return;
    }
    snprintf(output, output_size, "%.15s", policy_hash);
}

static void rotate_processing_arc(void* obj, int32_t rotation)
{
    lv_arc_set_rotation(static_cast<lv_obj_t*>(obj), rotation);
}

static bool make_pin_processing_overlay(lv_obj_t* parent)
{
    clear_screen_bottom_timeout_timer_bar_locked();

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
    lv_obj_set_size(blocker, kPanelContentWidth, kPanelContentHeight);
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
    lv_obj_set_style_bg_color(card, lv_color_hex(theme::kSecondary), 0);
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
    lv_obj_set_style_arc_color(spinner, lv_color_hex(theme::kOutlineVariant), LV_PART_MAIN);
    lv_obj_set_style_arc_color(spinner, lv_color_hex(theme::kPrimary), LV_PART_INDICATOR);
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
        lv_obj_set_style_text_color(loading, lv_color_hex(theme::kOnPrimary), 0);
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

static bool make_screen_bottom_timeout_timer_bar(
    lv_obj_t* owner_panel,
    AgentQTimeoutWindow timeout_window,
    TickType_t now);


bool modal_draw_connect_review_panel(
    const char* client_name,
    AgentQHumanApprovalInputMode input_mode,
    AgentQTimeoutWindow timeout_window)
{
    if (client_name == nullptr || client_name[0] == '\0') {
        return false;
    }
    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::connect_review);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "Connect Request");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

    lv_obj_t* subtitle = lv_label_create(panel);
    if (subtitle == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(subtitle, "Connect only, not signing");
    lv_obj_set_style_text_font(subtitle, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(subtitle, lv_color_hex(theme::kOnSurfaceVariant), 0);
    lv_obj_align(subtitle, LV_ALIGN_TOP_MID, 0, kModalDescriptionY);

    lv_obj_t* client_label = lv_label_create(panel);
    if (client_label == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(client_label, "Requester");
    lv_obj_set_style_text_font(client_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(client_label, lv_color_hex(theme::kOnSurfaceVariant), 0);
    lv_obj_align(client_label, LV_ALIGN_TOP_LEFT, kConnectReviewTextLeft, 86);

    lv_obj_t* client_value = lv_label_create(panel);
    if (client_value == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(client_value, client_name);
    lv_label_set_long_mode(client_value, LV_LABEL_LONG_CLIP);
    lv_obj_set_size(
        client_value,
        kConnectReviewClientNameValueWidth,
        kConnectReviewClientNameValueHeight);
    lv_obj_set_style_text_align(client_value, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(client_value, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(client_value, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(
        client_value,
        LV_ALIGN_TOP_LEFT,
        kConnectReviewTextLeft,
        kConnectReviewClientNameValueY);

    lv_obj_t* mode_label = lv_label_create(panel);
    if (mode_label == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(mode_label, "Requires");
    lv_obj_set_style_text_font(mode_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(mode_label, lv_color_hex(theme::kOnSurfaceVariant), 0);
    lv_obj_align(
        mode_label,
        LV_ALIGN_TOP_LEFT,
        kConnectReviewTextLeft,
        kConnectReviewApprovalRowY);

    lv_obj_t* mode_value = lv_label_create(panel);
    if (mode_value == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(
        mode_value,
        input_mode == AgentQHumanApprovalInputMode::pin
            ? "PIN"
            : "Device confirm");
    lv_obj_set_style_text_font(mode_value, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(mode_value, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(
        mode_value,
        LV_ALIGN_TOP_LEFT,
        kConnectReviewApprovalValueX,
        kConnectReviewApprovalRowY);

    if (!make_screen_bottom_timeout_timer_bar(
            panel,
            timeout_window,
            xTaskGetTickCount())) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Reject",
            kPanelActionButtonLeftX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kError),
            g_callbacks.on_connect_review_reject_clicked) ||
        !make_setup_button(
            panel,
            input_mode == AgentQHumanApprovalInputMode::pin ? "Continue" : "Confirm",
            kPanelActionButtonRightX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kPrimary),
            g_callbacks.on_connect_review_accept_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}


bool modal_draw_setup_choice_panel()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQProvisioningFlowSnapshot flow =
        agent_q::provisioning_flow_snapshot();
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
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "Set up Agent-Q");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

    if (!make_setup_button(
            panel,
            "Generate",
            kSettingsMenuButtonCenterX,
            kSetupMenuGenerateButtonY,
            kBackupPhraseButtonWidth,
            kSetupChoiceButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kPrimary),
            g_callbacks.on_setup_generate_clicked) ||
        !make_setup_button(
            panel,
            "Import",
            kSettingsMenuButtonCenterX,
            kSetupMenuImportButtonY,
            kBackupPhraseButtonWidth,
            kSetupChoiceButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kPrimary),
            g_callbacks.on_setup_import_clicked) ||
        !make_setup_button(
            panel,
            "Cancel",
            kSettingsMenuButtonCenterX,
            kSetupMenuCancelButtonY,
            kBackupPhraseButtonWidth,
            kSetupChoiceButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kSecondary),
            g_callbacks.on_setup_cancel_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_screen_bottom_timeout_timer_bar(panel, flow.input_window, now)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

static bool make_import_word_cell(lv_obj_t* parent, uint8_t slot)
{
    static const uint8_t kSlotUserData[kImportWordsPerPage] = {0, 1, 2};
    if (slot >= kImportWordsPerPage) {
        return false;
    }

    const agent_q::AgentQProvisioningFlowSnapshot flow =
        agent_q::provisioning_flow_snapshot();
    const size_t global_slot =
        agent_q::provisioning_flow_import_global_word_slot_for(flow.import_page, slot);
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
        kMnemonicWordCellLeft + static_cast<int>(slot) * kMnemonicWordColumnStride,
        kImportWordCellTop);
    lv_obj_set_style_radius(cell, 4, 0);
    const bool cell_active = (slot == flow.import_active_slot);
    lv_obj_set_style_border_width(cell, cell_active ? 2 : 1, 0);
    lv_obj_set_style_border_color(
        cell, lv_color_hex(cell_active ? theme::kPrimary : kSetupCellBorderColor), 0);
    lv_obj_set_style_bg_color(
        cell, lv_color_hex(cell_active ? theme::kPrimaryContainer : theme::kSurface), 0);
    lv_obj_set_style_bg_opa(cell, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(cell, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(cell, LV_OPA_30, LV_STATE_PRESSED);
    lv_obj_set_style_pad_all(cell, 0, 0);
    lv_obj_add_flag(cell, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(
        cell,
        g_callbacks.on_import_slot_clicked,
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
    lv_obj_set_style_text_color(index_label, lv_color_hex(theme::kOnSurfaceVariant), 0);
    lv_obj_set_style_bg_opa(index_label, LV_OPA_TRANSP, 0);
    lv_obj_set_style_radius(index_label, 4, LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(index_label, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(index_label, LV_OPA_30, LV_STATE_PRESSED);
    lv_obj_align(index_label, LV_ALIGN_LEFT_MID, 4, 0);
    lv_obj_add_flag(index_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(
        index_label,
        g_callbacks.on_import_slot_clicked,
        LV_EVENT_CLICKED,
        const_cast<uint8_t*>(&kSlotUserData[slot]));

    lv_obj_t* prefix_label = lv_label_create(cell);
    if (prefix_label == nullptr) {
        return false;
    }
    const char* prefix = agent_q::provisioning_flow_import_prefix(global_slot);
    lv_label_set_text(prefix_label, prefix[0] != '\0' ? prefix : "____");
    lv_label_set_long_mode(prefix_label, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(prefix_label, kMnemonicWordPrefixWidth);
    lv_obj_set_style_text_align(prefix_label, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(prefix_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(prefix_label, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_set_style_bg_opa(prefix_label, LV_OPA_TRANSP, 0);
    lv_obj_set_style_radius(prefix_label, 4, LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(prefix_label, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(prefix_label, LV_OPA_30, LV_STATE_PRESSED);
    lv_obj_align(prefix_label, LV_ALIGN_LEFT_MID, kMnemonicWordPrefixLeft, 0);
    lv_obj_add_flag(prefix_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(
        prefix_label,
        g_callbacks.on_import_slot_clicked,
        LV_EVENT_CLICKED,
        const_cast<uint8_t*>(&kSlotUserData[slot]));
    return true;
}

static bool make_import_alphabet_buttons(lv_obj_t* parent)
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
                kImportAlphabetLeft + column * kImportAlphabetButtonWidth,
                kImportAlphabetTop + row * (kImportAlphabetButtonHeight + 4),
                kImportAlphabetButtonWidth,
                kImportAlphabetButtonHeight,
                SetupButtonKind::outlined_keypad,
                lv_color_hex(kSetupInputPressedColor),
                g_callbacks.on_import_letter_clicked,
                kLetters[index])) {
            return false;
        }
    }
    return true;
}

static bool make_import_candidate_area(lv_obj_t* parent)
{
    lv_obj_t* area = lv_obj_create(parent);
    if (area == nullptr) {
        return false;
    }
    lv_obj_remove_style_all(area);
    lv_obj_set_size(area, kImportCandidateWidth, kImportCandidateHeight);
    lv_obj_align(area, LV_ALIGN_TOP_LEFT, kImportCandidateLeft, kImportCandidateTop);
    lv_obj_set_scroll_dir(area, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(area, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_set_style_pad_all(area, 0, 0);
    lv_obj_set_style_bg_opa(area, LV_OPA_TRANSP, 0);

    const size_t global_slot = agent_q::provisioning_flow_import_global_word_slot();
    const char* prefix = agent_q::provisioning_flow_import_prefix(global_slot);
    if (prefix[0] == '\0') {
        lv_obj_t* label = lv_label_create(area);
        if (label == nullptr) {
            return false;
        }
        lv_label_set_text(label, "Tap a letter to list BIP-39 words.");
        lv_obj_set_width(label, kImportCandidateWidth - 8);
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(label, lv_color_hex(theme::kOnSurfaceVariant), 0);
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
        g_import_candidate_event_indices[candidate_count] = word_index;

        lv_obj_t* button = lv_obj_create(area);
        if (button == nullptr) {
            return false;
        }
        const int column = static_cast<int>(candidate_count % 3);
        const int row = static_cast<int>(candidate_count / 3);
        lv_obj_remove_style_all(button);
        lv_obj_set_size(button, kImportCandidateButtonWidth, kImportCandidateButtonHeight);
        lv_obj_align(
            button,
            LV_ALIGN_TOP_LEFT,
            column * (kImportCandidateButtonWidth + 6),
            row * (kImportCandidateButtonHeight + 4));
        lv_obj_set_style_radius(button, kPinPanelButtonRadius, 0);
        lv_obj_set_style_border_width(button, 1, 0);
        lv_obj_set_style_border_color(button, lv_color_hex(kSetupCellBorderColor), 0);
        lv_obj_set_style_bg_opa(button, LV_OPA_TRANSP, 0);
        lv_obj_set_style_bg_color(button, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
        lv_obj_set_style_bg_opa(button, LV_OPA_30, LV_STATE_PRESSED);
        lv_obj_add_flag(button, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(
            button,
            g_callbacks.on_import_candidate_clicked,
            LV_EVENT_CLICKED,
            &g_import_candidate_event_indices[candidate_count]);

        lv_obj_t* label = lv_label_create(button);
        if (label == nullptr) {
            return false;
        }
        lv_obj_remove_style_all(label);
        lv_label_set_text_static(label, word);
        lv_label_set_long_mode(label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(label, kImportCandidateButtonWidth - 6);
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(label, &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(label, lv_color_hex(theme::kOnSurface), 0);
        lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
        lv_obj_set_style_radius(label, kPinPanelButtonRadius, LV_STATE_PRESSED);
        lv_obj_set_style_bg_color(label, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
        lv_obj_set_style_bg_opa(label, LV_OPA_30, LV_STATE_PRESSED);
        lv_obj_center(label);
        lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(
            label,
            g_callbacks.on_import_candidate_clicked,
            LV_EVENT_CLICKED,
            &g_import_candidate_event_indices[candidate_count]);
        ++candidate_count;
    }

    if (candidate_count == 0) {
        lv_obj_t* label = lv_label_create(area);
        if (label == nullptr) {
            return false;
        }
        lv_label_set_text(label, "No matching BIP-39 words.");
        lv_obj_set_width(label, kImportCandidateWidth - 8);
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(label, lv_color_hex(theme::kError), 0);
        lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 16);
    }

    return true;
}

static bool make_screen_bottom_timeout_timer_bar(
    lv_obj_t* owner_panel,
    AgentQTimeoutWindow timeout_window,
    TickType_t now)
{
    if (!timeout_window_active(timeout_window)) {
        return true;
    }
    clear_screen_bottom_timeout_timer_bar_locked();
    lv_obj_t* track = nullptr;
    if (!make_timeout_timer_bar(
            lv_layer_top(),  // top layer: keep the timer bar above the full-screen modal panel
            kTimeoutTimerBarTrackInset,
            kScreenHeight - kTimeoutTimerBarHeight,
            kScreenWidth - 2 * kTimeoutTimerBarTrackInset,
            timeout_window,
            now,
            &track)) {
        return false;
    }
    if (track == nullptr) {
        return true;
    }
    lv_obj_add_flag(track, LV_OBJ_FLAG_FLOATING);
    g_screen_bottom_timeout_timer_bar = track;
    lv_obj_add_event_cb(
        track,
        on_screen_bottom_timeout_timer_bar_deleted,
        LV_EVENT_DELETE,
        nullptr);
    lv_obj_add_event_cb(owner_panel, delete_linked_timeout_timer_bar, LV_EVENT_DELETE, track);
    lv_obj_move_foreground(track);
    return true;
}

bool modal_draw_import_word_entry_panel(const char* notice)
{
    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::import_word_entry);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    const agent_q::AgentQProvisioningFlowSnapshot flow =
        agent_q::provisioning_flow_snapshot();
    char title_text[32] = {};
    snprintf(title_text, sizeof(title_text), "Import words %u-%u",
             static_cast<unsigned>(flow.import_page * kImportWordsPerPage + 1),
             static_cast<unsigned>((flow.import_page + 1) * kImportWordsPerPage));
    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, title_text);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

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
        lv_obj_set_style_text_color(notice_label, lv_color_hex(theme::kError), 0);
        lv_obj_align(notice_label, LV_ALIGN_TOP_MID, 0, kModalDescriptionY);
    }

    for (uint8_t slot = 0; slot < kImportWordsPerPage; ++slot) {
        if (!make_import_word_cell(panel, slot)) {
            drawing_surface_clear_panel_locked();
            return false;
        }
    }

    if (!make_import_alphabet_buttons(panel) ||
        !make_import_candidate_area(panel)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Cancel",
            kBackupPhraseButtonLeftX,
            kSetupActionButtonY,
            kImportNavigationButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kError),
            g_callbacks.on_import_cancel_clicked) ||
        !make_setup_button(
            panel,
            "Clear",
            kBackupPhraseButtonLeftX + kImportNavigationButtonWidth + 8,
            kSetupActionButtonY,
            kImportNavigationButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(theme::kSecondary),
            g_callbacks.on_import_clear_clicked) ||
        !make_setup_button(
            panel,
            "Prev",
            kBackupPhraseButtonLeftX + 2 * (kImportNavigationButtonWidth + 8),
            kSetupActionButtonY,
            kImportNavigationButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kSecondary),
            g_callbacks.on_import_previous_clicked,
            nullptr,
            flow.import_page > 0) ||
        !make_setup_button(
            panel,
            flow.import_page + 1 >= kImportPageCount ? "Verify" : "Next",
            kBackupPhraseButtonLeftX + 3 * (kImportNavigationButtonWidth + 8),
            kSetupActionButtonY,
            kImportNavigationButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kPrimary),
            g_callbacks.on_import_next_clicked,
            nullptr,
            flow.import_current_page_complete)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_screen_bottom_timeout_timer_bar(panel, flow.input_window, xTaskGetTickCount())) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_backup_phrase_display(const char* backup_phrase)
{
    if (backup_phrase == nullptr || backup_phrase[0] == '\0') {
        return false;
    }

    avatar_overlay_clear();
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQProvisioningFlowSnapshot flow =
        agent_q::provisioning_flow_snapshot();

    LvglLockGuard lock;
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::backup_phrase_display);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "BIP-39 prefixes");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kBackupPhraseTopMargin);

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
    lv_obj_set_style_text_color(warning, lv_color_hex(theme::kWarning), 0);
    lv_obj_align(warning, LV_ALIGN_TOP_MID, 0, 22 + kBackupPhraseTopMargin);

    constexpr int kGridTop = 58 + kBackupPhraseTopMargin;
    constexpr int kGridRowHeight = 25;
    for (size_t index = 0; index < kBackupPhrasePrefixCellCount; ++index) {
        lv_obj_t* cell = lv_obj_create(panel);
        if (cell == nullptr) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        lv_obj_remove_flag(cell, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_size(cell, kMnemonicWordCellWidth, kMnemonicWordCellHeight);
        lv_obj_set_style_radius(cell, 4, 0);
        lv_obj_set_style_border_width(cell, 1, 0);
        lv_obj_set_style_border_color(cell, lv_color_hex(theme::kOutline), 0);
        lv_obj_set_style_bg_color(cell, lv_color_hex(theme::kSurface), 0);
        lv_obj_set_style_bg_opa(cell, LV_OPA_COVER, 0);
        lv_obj_set_style_pad_all(cell, 0, 0);
        const int column = static_cast<int>(index % 3);
        const int row = static_cast<int>(index / 3);
        lv_obj_align(
            cell,
            LV_ALIGN_TOP_LEFT,
            kMnemonicWordCellLeft + column * kMnemonicWordColumnStride,
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
        lv_obj_set_style_text_color(index_label, lv_color_hex(theme::kOnSurfaceVariant), 0);
        lv_obj_align(index_label, LV_ALIGN_LEFT_MID, 4, 0);

        lv_obj_t* prefix_label = lv_label_create(cell);
        if (prefix_label == nullptr) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        lv_label_set_text_static(prefix_label, agent_q::provisioning_flow_backup_phrase_prefix_cell(index));
        lv_label_set_long_mode(prefix_label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(prefix_label, kMnemonicWordPrefixWidth);
        lv_obj_set_style_text_align(prefix_label, LV_TEXT_ALIGN_LEFT, 0);
        lv_obj_set_style_text_font(prefix_label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(prefix_label, lv_color_hex(theme::kOnSurface), 0);
        lv_obj_align(prefix_label, LV_ALIGN_LEFT_MID, kMnemonicWordPrefixLeft, 0);
    }
    if (!make_setup_button(
            panel,
            "Cancel",
            kPanelActionButtonLeftX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kError),
            g_callbacks.on_backup_phrase_cancel_clicked) ||
        !make_setup_button(
            panel,
            "Confirm",
            kPanelActionButtonRightX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kPrimary),
            g_callbacks.on_backup_phrase_confirm_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_screen_bottom_timeout_timer_bar(panel, flow.input_window, now)) {
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
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
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
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

    lv_obj_t* message = lv_label_create(panel);
    if (message == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(
        message,
        notice != nullptr && notice[0] != '\0'
            ? notice
            : (committing_stage ? "Processing. Please wait." : ""));
    lv_label_set_long_mode(message, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message, kScreenWidth - 44);
    lv_obj_set_style_text_align(message, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(message, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(message, lv_color_hex(theme::kWarning), 0);
    lv_obj_align(message, LV_ALIGN_TOP_MID, 0, kModalDescriptionY);

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
    lv_obj_set_style_text_color(pin_label, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    if (!make_pin_keypad_buttons(panel, buttons_enabled)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Cancel",
            kPanelActionButtonLeftX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kError),
            g_callbacks.on_pin_cancel_clicked,
            nullptr,
            buttons_enabled) ||
        !make_setup_button(
            panel,
            "Confirm",
            kPanelActionButtonRightX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kPrimary),
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

    if (!committing_stage &&
        !make_screen_bottom_timeout_timer_bar(panel, flow.input_window, xTaskGetTickCount())) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_settings_menu_panel()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(now);
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
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "Settings");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

    agent_q::AgentQHumanApprovalInputMode human_approval_input_mode =
        agent_q::AgentQHumanApprovalInputMode::pin;
    const bool human_approval_setting_read_ok =
        agent_q::read_human_approval_input_mode(&human_approval_input_mode);
    AgentQSigningAuthorizationMode signing_mode = AgentQSigningAuthorizationMode::user;
    const bool signing_mode_read_ok =
        agent_q::read_signing_authorization_mode(&signing_mode);

    lv_obj_t* content = lv_obj_create(panel);
    if (content == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_obj_set_size(content, kPanelContentWidth, kSettingsMenuContentHeight);
    lv_obj_align(content, LV_ALIGN_TOP_LEFT, 0, kSettingsMenuContentY);
    lv_obj_set_style_radius(content, 0, 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_pad_all(content, 0, 0);
    lv_obj_add_flag(content, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(content, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(content, LV_SCROLLBAR_MODE_AUTO);

    if (!make_settings_menu_row(
            content,
            "Approval input",
            human_approval_setting_read_ok
                ? agent_q::human_approval_input_mode_label(human_approval_input_mode)
                : "ERR",
            0,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(theme::kPrimary),
            human_approval_setting_read_ok ? g_callbacks.on_settings_human_approval_input_clicked : nullptr,
            human_approval_setting_read_ok) ||
        !make_settings_menu_row(
            content,
            "Sign auth",
            signing_mode_read_ok
                ? (signing_mode == AgentQSigningAuthorizationMode::policy ? "POLICY" : "USER")
                : "ERR",
            1,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(theme::kPrimary),
            signing_mode_read_ok ? g_callbacks.on_settings_signing_mode_clicked : nullptr,
            signing_mode_read_ok) ||
        !make_settings_menu_row(
            content,
            "Change PIN",
            "CHANGE",
            2,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(theme::kPrimary),
            g_callbacks.on_settings_change_pin_clicked) ||
        !make_settings_menu_row(
            content,
            "Reset policy",
            "RESET",
            3,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kError),
            g_callbacks.on_settings_policy_reset_clicked) ||
        !make_settings_menu_row(
            content,
            "Reset device",
            "RESET",
            4,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kError),
            g_callbacks.on_settings_reset_clicked) ||
        !make_setup_button(
            panel,
            "Close",
            kSettingsMenuButtonCenterX,
            kSetupActionButtonY,
            kBackupPhraseButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(theme::kPrimary),
            g_callbacks.on_settings_cancel_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_screen_bottom_timeout_timer_bar(panel, reset.input_window, now)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_error_recovery_panel(bool confirm)
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(now);
    const bool wiping =
        reset.stage == agent_q::AgentQLocalResetStage::wiping;
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
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kErrorContainer), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, wiping ? "Erasing device" : (confirm ? "Erase device data" : "Device data error"));
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnErrorContainer), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

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
    lv_obj_set_style_text_color(message, lv_color_hex(theme::kOnErrorContainerStrong), 0);
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
                kPanelActionButtonLeftX,
                kSetupActionButtonY,
                kPanelActionButtonWidth,
                kBackupPhraseButtonHeight,
                SetupButtonKind::outlined_keypad,
                lv_color_hex(theme::kError),
                g_callbacks.on_error_recovery_cancel_clicked) ||
            !make_setup_button(
                panel,
                "Erase",
                kPanelActionButtonRightX,
                kSetupActionButtonY,
                kPanelActionButtonWidth,
                kBackupPhraseButtonHeight,
                SetupButtonKind::solid_action,
                lv_color_hex(theme::kError),
                g_callbacks.on_error_recovery_erase_clicked)) {
            drawing_surface_clear_panel_locked();
            return false;
        }
    } else if (!make_setup_button(
                   panel,
                   "Erase",
                   kSettingsMenuButtonCenterX,
                   kSetupActionButtonY,
                   kBackupPhraseButtonWidth,
                   kBackupPhraseButtonHeight,
                   SetupButtonKind::solid_action,
                   lv_color_hex(theme::kError),
                   g_callbacks.on_error_recovery_erase_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (confirm && !wiping &&
        !make_screen_bottom_timeout_timer_bar(panel, reset.input_window, now)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_reset_pin_panel(const char* notice)
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(now);
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
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
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
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

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
    lv_obj_set_style_text_color(message, lv_color_hex(theme::kWarning), 0);
    lv_obj_align(message, LV_ALIGN_TOP_MID, 0, kModalDescriptionY);

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
    lv_obj_set_style_text_color(pin_label, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    if (!make_pin_keypad_buttons(panel, buttons_enabled)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Cancel",
            kPanelActionButtonLeftX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kSecondary),
            g_callbacks.on_reset_cancel_clicked,
            nullptr,
            !processing_stage) ||
        !make_setup_button(
            panel,
            "Reset",
            kPanelActionButtonRightX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kError),
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

    if (!processing_stage &&
        !make_screen_bottom_timeout_timer_bar(panel, reset.input_window, now)) {
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
        return "Enter PIN to apply policy change.";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::user_signing) {
        return "Confirm signing with local PIN.";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::settings_signing_mode) {
        return "Enter PIN to change signing mode.";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::settings_policy_reset) {
        return "Enter PIN to reset policy.";
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
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::user_signing) {
        return "Signing PIN";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::settings_signing_mode) {
        return "Signing Mode";
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::settings_policy_reset) {
        return "Reset Policy";
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

bool modal_draw_policy_update_review_panel(
    const AgentQPolicyUpdateReviewViewModel& model,
    AgentQTimeoutWindow timeout_window)
{
    if (model.policy_hash == nullptr || model.policy_hash[0] == '\0' ||
        model.default_action == nullptr ||
        model.highest_action == nullptr ||
        model.scope_summary == nullptr ||
        model.review_summary == nullptr || model.review_summary[0] == '\0') {
        return false;
    }

    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::policy_update_review);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "Review policy update");
    lv_label_set_long_mode(title, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(title, kScreenWidth - 44);
    lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

    lv_obj_t* subtitle = lv_label_create(panel);
    if (subtitle == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(subtitle, "Confirm on device before PIN.");
    lv_label_set_long_mode(subtitle, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(subtitle, kScreenWidth - 44);
    lv_obj_set_style_text_align(subtitle, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(subtitle, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_color(subtitle, lv_color_hex(theme::kOnSurfaceVariant), 0);
    lv_obj_align(subtitle, LV_ALIGN_TOP_MID, 0, kModalDescriptionY);

    char scope_count[24] = {};
    char policy_count[24] = {};
    char policy_hash_prefix[24] = {};
    char action_summary[32] = {};
    snprintf(
        scope_count,
        sizeof(scope_count),
        "%u/%u",
        static_cast<unsigned>(model.blockchain_count),
        static_cast<unsigned>(model.network_count));
    snprintf(
        policy_count,
        sizeof(policy_count),
        "%u/%u",
        static_cast<unsigned>(model.policy_count),
        static_cast<unsigned>(model.condition_count));
    format_policy_hash_prefix(model.policy_hash, policy_hash_prefix, sizeof(policy_hash_prefix));
    snprintf(
        action_summary,
        sizeof(action_summary),
        "%s -> %s",
        model.default_action,
        model.highest_action);
    int row_y = kPolicyUpdateReviewRowTop;
    if (!make_policy_update_review_row(panel, "Hash", policy_hash_prefix, row_y) ||
        !make_policy_update_review_row(panel, "Scopes", scope_count, row_y + kPolicyUpdateReviewRowHeight) ||
        !make_policy_update_review_row(panel, "Action", action_summary, row_y + 2 * kPolicyUpdateReviewRowHeight) ||
        !make_policy_update_review_row(panel, "Policies/Cond", policy_count, row_y + 3 * kPolicyUpdateReviewRowHeight)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    lv_obj_t* summary_area = lv_obj_create(panel);
    if (summary_area == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_obj_set_size(summary_area, kPolicyUpdateReviewRowWidth, kPolicyUpdateReviewSummaryHeight);
    lv_obj_align(summary_area, LV_ALIGN_TOP_LEFT, 18, kPolicyUpdateReviewSummaryTop);
    lv_obj_set_style_bg_opa(summary_area, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(summary_area, 0, 0);
    lv_obj_set_style_pad_all(summary_area, 0, 0);
    lv_obj_set_scrollbar_mode(summary_area, LV_SCROLLBAR_MODE_AUTO);

    lv_obj_t* summary = lv_label_create(summary_area);
    if (summary == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(summary, model.review_summary);
    lv_label_set_long_mode(summary, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(summary, kPolicyUpdateReviewRowWidth);
    lv_obj_set_style_text_align(summary, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(summary, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_color(summary, lv_color_hex(theme::kWarning), 0);
    lv_obj_align(summary, LV_ALIGN_TOP_LEFT, 0, 0);

    if (!make_screen_bottom_timeout_timer_bar(
            panel,
            timeout_window,
            xTaskGetTickCount())) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Reject",
            kPanelActionButtonLeftX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kError),
            g_callbacks.on_policy_update_review_reject_clicked) ||
        !make_setup_button(
            panel,
            "Continue",
            kPanelActionButtonRightX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kPrimary),
            g_callbacks.on_policy_update_review_continue_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
}

bool modal_draw_user_signing_review_panel(
    const AgentQUserSigningReviewViewModel& model,
    AgentQTimeoutWindow timeout_window)
{
    if (model.title[0] == '\0' ||
        model.row_count == 0 ||
        model.row_count > kAgentQUserSigningReviewMaxRows) {
        return false;
    }

    avatar_overlay_clear();

    LvglLockGuard lock;
    request_display_power_wake();
    drawing_surface_clear_panel_locked();

    lv_obj_t* panel = drawing_surface_create_panel_locked(AgentQUiPanelKind::user_signing_review);
    if (panel == nullptr) {
        return false;
    }
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, model.title);
    lv_label_set_long_mode(title, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(title, kScreenWidth - 44);
    lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

    lv_obj_t* content = lv_obj_create(panel);
    if (content == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_obj_set_size(content, kPanelContentWidth, kUserSigningReviewContentHeight);
    lv_obj_align(content, LV_ALIGN_TOP_LEFT, 0, kUserSigningReviewRowTop);
    lv_obj_set_style_radius(content, 0, 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_pad_all(content, 0, 0);
    lv_obj_add_flag(content, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(content, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(content, LV_SCROLLBAR_MODE_AUTO);

    int row_y = 0;
    for (size_t index = 0; index < model.row_count; ++index) {
        const bool wrapped_value =
            model.rows[index].kind == AgentQUserSigningReviewRowKind::wrapped_value ||
            model.rows[index].kind == AgentQUserSigningReviewRowKind::section;
        if (!make_user_signing_review_row(content, model.rows[index], row_y)) {
            drawing_surface_clear_panel_locked();
            return false;
        }
        row_y += wrapped_value
            ? kUserSigningReviewWrappedValueRowHeight
            : kUserSigningReviewNormalRowHeight;
    }

    if (!make_screen_bottom_timeout_timer_bar(
            panel,
            timeout_window,
            xTaskGetTickCount())) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            "Reject",
            kPanelActionButtonLeftX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kError),
            g_callbacks.on_user_signing_review_reject_clicked) ||
        !make_setup_button(
            panel,
            "Sign",
            kPanelActionButtonRightX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kPrimary),
            g_callbacks.on_user_signing_review_accept_clicked)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    drawing_surface_move_panel_foreground_locked();
    return true;
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
    lv_obj_set_size(panel, kPanelContentWidth, kPanelContentHeight);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_radius(panel, 8, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_bg_color(panel, lv_color_hex(theme::kSurface), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(panel, 0, 0);

    const bool buttons_enabled = !snapshot.processing && !snapshot.lockout_active;

    lv_obj_t* title = lv_label_create(panel);
    if (title == nullptr) {
        drawing_surface_clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, local_pin_auth_title(snapshot));
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kModalTitleY);

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
    lv_obj_set_style_text_color(message, lv_color_hex(theme::kWarning), 0);
    lv_obj_align(message, LV_ALIGN_TOP_MID, 0, kModalDescriptionY);

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
    lv_obj_set_style_text_color(pin_label, lv_color_hex(theme::kOnSurface), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    if (!make_pin_keypad_buttons(panel, buttons_enabled)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (snapshot.accepts_keypad_input &&
        !make_screen_bottom_timeout_timer_bar(
            panel,
            snapshot.input_window,
            now)) {
        drawing_surface_clear_panel_locked();
        return false;
    }

    if (!make_setup_button(
            panel,
            snapshot.purpose == AgentQLocalPinAuthPurpose::policy_update ||
                    snapshot.purpose == AgentQLocalPinAuthPurpose::user_signing
                ? "Back"
                : "Cancel",
            kPanelActionButtonLeftX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kSecondary),
            g_callbacks.on_pin_cancel_clicked,
            nullptr,
            !snapshot.processing) ||
        !make_setup_button(
            panel,
            "Confirm",
            kPanelActionButtonRightX,
            kSetupActionButtonY,
            kPanelActionButtonWidth,
            kBackupPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(theme::kPrimary),
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
