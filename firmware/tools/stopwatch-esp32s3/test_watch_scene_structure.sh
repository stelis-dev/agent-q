#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
APP_CPP="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime/app.cpp"
APP_H="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime/app.h"
CLOCK_CPP="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime/clock_scene.cpp"
CLOCK_H="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime/clock_scene.h"
WATCH_FACE_BIN="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/assets/watch/clock_1_face.i8.bin"
WATCH_ASSET_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/assets/watch"

require_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq "$needle" "$file"; then
    echo "Missing expected text in ${file}: ${needle}" >&2
    exit 1
  fi
}

require_absent_in_clock_scene() {
  local needle="$1"
  if grep -Fq "$needle" "$CLOCK_CPP" "$CLOCK_H"; then
    echo "ClockScene must not own auth, USB, or policy state: ${needle}" >&2
    exit 1
  fi
}

require_contains "$APP_H" "ClockScene clock_scene_;"
require_contains "$APP_H" "bool unlock_watch_timer_armed_ = false;"
require_contains "$APP_H" "bool watch_visible_ = false;"
require_contains "$APP_H" "bool ignore_touch_until_release_ = false;"
require_contains "$APP_CPP" "#include \"display_geometry.h\""
require_contains "$APP_CPP" "lv_obj_set_size(root_, kDisplaySizePx, kDisplaySizePx);"
require_contains "$APP_CPP" "lv_obj_set_style_radius(root_, kDisplayCenterPx, LV_PART_MAIN);"
require_contains "$APP_CPP" "constexpr uint32_t kUnlockWatchDelayMs = 60U * 1000U;"
require_contains "$APP_CPP" "watch_visible_"
require_contains "$APP_CPP" "void RuntimeApp::maybe_enter_watch(uint32_t now_ms)"
require_contains "$APP_CPP" "void RuntimeApp::reset_unlock_watch()"
require_contains "$APP_CPP" "void RuntimeApp::show_unlock_watch()"
require_contains "$APP_CPP" "bool RuntimeApp::unlock_watch_allowed() const"
require_contains "$APP_CPP" "pending.kind != UsbPendingRequestKind::none"
require_contains "$APP_CPP" "identification.active"
require_contains "$APP_CPP" "if (!unlock_watch_timer_armed_)"
require_contains "$APP_CPP" "unlock_watch_timer_armed_ = true;"
require_contains "$APP_CPP" "auth_entry_.length() == 0"
require_contains "$APP_CPP" "const bool state_allows_watch = unlock_watch_allowed();"
require_contains "$APP_CPP" "if (screen_mode_ != ScreenMode::setup_enter &&"
require_contains "$APP_CPP" "screen_mode_ != ScreenMode::unlock"
require_contains "$APP_CPP" "clock_scene_.set_visible(watch_visible_);"
require_contains "$APP_CPP" "clock_scene_.update(now);"
require_contains "$APP_CPP" "rotary_dial_.set_visible(auth_entry_mode() && !watch_visible_);"
require_contains "$APP_CPP" "if (!auth_entry_mode() || watch_visible_)"
require_contains "$APP_CPP" "const bool touch_was_down = touch_down_;"
require_contains "$APP_CPP" "ignore_touch_until_release_ = true;"
require_contains "$CLOCK_H" "lv_obj_t* scene_root_ = nullptr;"
require_contains "$CLOCK_H" "void refresh_hand_lines();"
require_contains "$CLOCK_H" "void invalidate_hands();"
require_contains "$CLOCK_CPP" "#include \"display_geometry.h\""
require_contains "$CLOCK_CPP" "lv_obj_set_style_bg_opa(scene_root_, LV_OPA_COVER, LV_PART_MAIN);"
require_contains "$CLOCK_CPP" "lv_obj_set_style_radius(scene_root_, kDisplayCenterPx, LV_PART_MAIN);"
require_contains "$CLOCK_CPP" "lv_obj_set_size(line, kDisplaySizePx, kDisplaySizePx);"
require_contains "$CLOCK_CPP" "lv_obj_set_pos(line, 0, 0);"
require_contains "$CLOCK_CPP" "lv_obj_set_style_line_rounded(line, false, LV_PART_MAIN);"
require_contains "$CLOCK_CPP" "constexpr lv_value_precise_t kClockPivotCoordinate = kDisplayCenterPx;"
require_contains "$CLOCK_CPP" "void set_twelve_o_clock_hand_points("
require_contains "$CLOCK_CPP" "if (normalized_degrees == 0.0F) {"
require_contains "$CLOCK_CPP" "const bool became_visible = visible && !visible_;"
require_contains "$CLOCK_CPP" "hour_hand_ = make_line(scene_root_, hour_points_, 8, lv_color_hex(0xF4E8D0), LV_OPA_COVER);"
require_contains "$CLOCK_CPP" "minute_hand_ = make_line(scene_root_, minute_points_, 6, lv_color_hex(0xF4E8D0), LV_OPA_COVER);"
require_contains "$CLOCK_CPP" "second_hand_ = make_line(scene_root_, second_points_, 3, lv_color_hex(0xB74D45), LV_OPA_COVER);"
require_contains "$CLOCK_CPP" "void ClockScene::refresh_hand_lines()"
require_contains "$CLOCK_CPP" "void ClockScene::invalidate_hands()"
require_contains "$CLOCK_CPP" "invalidate_hands();"
require_contains "$CLOCK_CPP" "lv_line_set_points_mutable(hour_hand_, hour_points_, 2);"
require_contains "$CLOCK_CPP" "lv_line_set_points_mutable(minute_hand_, minute_points_, 2);"
require_contains "$CLOCK_CPP" "lv_line_set_points_mutable(second_hand_, second_points_, 2);"

if grep -Fq "constexpr int kScreenCenter" "$CLOCK_CPP" "$REPO_ROOT/firmware/src/stopwatch-esp32s3/overlay/main/runtime/rotary_dial_scene.cpp"; then
  echo "Display center must be owned by display_geometry.h, not per-scene constants." >&2
  exit 1
fi

if grep -Fq "lv_obj_move_foreground(hand)" "$CLOCK_CPP"; then
  echo "ClockScene must not reorder hand objects on every second update." >&2
  exit 1
fi

watch_touch_block="$(sed -n '/void RuntimeApp::handle_touch_poll/,/void RuntimeApp::handle_power_button/p' "$APP_CPP")"
if grep -F "watch_visible_" <<<"$watch_touch_block" | grep -Fq "enter_mode"; then
  echo "Touch handling must not leave watch mode; use physical input only." >&2
  exit 1
fi

watch_allowed_block="$(sed -n '/bool RuntimeApp::unlock_watch_allowed/,/void RuntimeApp::refresh_auth_mode/p' "$APP_CPP")"
if grep -Fq "touch_down_" <<<"$watch_allowed_block"; then
  echo "Watch eligibility must not depend on touch state; touch must not leave watch mode." >&2
  exit 1
fi
require_contains "$APP_CPP" "const bool request_prompt_active = pending.kind != UsbPendingRequestKind::none ||"

maybe_watch_block="$(sed -n '/void RuntimeApp::maybe_enter_watch/,/void RuntimeApp::sync_usb_runtime_state/p' "$APP_CPP")"
if ! grep -Fq "const bool touch_was_down = touch_down_;" <<<"$maybe_watch_block" ||
   ! grep -Fq "ignore_touch_until_release_ = true;" <<<"$maybe_watch_block"; then
  echo "Automatic watch exit must preserve touch-ignore until a finger that started on the watch is released." >&2
  exit 1
fi

auth_input_block="$(sed -n '/void RuntimeApp::append_digit/,/void RuntimeApp::submit_entry/p' "$APP_CPP")"
if grep -Fq "unlock_idle_started_ms_" <<<"$auth_input_block"; then
  echo "Auth input functions must not own the watch timer; maybe_enter_watch owns it." >&2
  exit 1
fi

same_mode_enter_block="$(sed -n '/void RuntimeApp::enter_mode/,/if (screen_mode_ == ScreenMode::setup_confirm/p' "$APP_CPP")"
if grep -Fq "reset_unlock_watch" <<<"$same_mode_enter_block"; then
  echo "Same-mode enter must not reset the unlock watch timer." >&2
  exit 1
fi

auth_entry_block="$(sed -n '/bool RuntimeApp::auth_entry_mode/,/bool RuntimeApp::input_timed_out/p' "$APP_CPP")"
if grep -Fq "ScreenMode::watch" <<<"$auth_entry_block"; then
    echo "watch must not be an auth-entry mode." >&2
    exit 1
fi

if grep -Fq "ScreenMode::watch" "$APP_CPP" "$APP_H"; then
  echo "watch must be a display layer, not a ScreenMode." >&2
  exit 1
fi

require_absent_in_clock_scene "usb_transport"
require_absent_in_clock_scene "local_auth"
require_absent_in_clock_scene "policy"
require_absent_in_clock_scene "session"

unexpected_watch_pngs="$(find "$WATCH_ASSET_DIR" -maxdepth 1 -type f -name '*.png' ! -name 'clock_1_face.png' -print)"
if [[ -n "$unexpected_watch_pngs" ]]; then
  echo "Watch scene must keep only the opaque face source PNG:" >&2
  echo "$unexpected_watch_pngs" >&2
  exit 1
fi

node --input-type=module - "$WATCH_FACE_BIN" <<'NODE'
import fs from "node:fs";
const file = process.argv[2];
const data = fs.readFileSync(file);
for (let offset = 3; offset < 256 * 4; offset += 4) {
  if (data[offset] !== 255) {
    console.error(`Watch face palette must be opaque; alpha ${data[offset]} at palette byte ${offset}`);
    process.exit(1);
  }
}
NODE

echo "watch scene structure checks passed"
