#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
APP_CPP="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime/app.cpp"
APP_H="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime/app.h"

require_contains() {
  local haystack="$1"
  local needle="$2"
  local message="$3"
  if ! grep -Fq "$needle" <<<"$haystack"; then
    echo "$message" >&2
    exit 1
  fi
}

if ! grep -Fq "bool handle_power_button(bool external_power_present);" "$APP_H"; then
  echo "Power-button handling must report whether it consumed the input frame." >&2
  exit 1
fi

running_block="$(sed -n '/void RuntimeApp::onRunning()/,/void RuntimeApp::onClose()/p' "$APP_CPP")"
require_contains "$running_block" \
  "const bool power_button_handled = handle_power_button(external_power_present);" \
  "The app loop must retain the power-button consumption result."
require_contains "$running_block" \
  "if (!power_button_handled)" \
  "A consumed power-button frame must not also execute a KEYA or KEYB action."

power_block="$(sed -n '/bool RuntimeApp::handle_power_button/,/void RuntimeApp::sync_power_button_policy/p' "$APP_CPP")"
require_contains "$power_block" \
  "if (!external_power_present)" \
  "The app must leave battery-powered short-click behavior to the PMIC."
require_contains "$power_block" \
  "set_display_on(!display_on_);" \
  "USB-powered short click must toggle the display."
require_contains "$power_block" \
  "return true;" \
  "An app-handled power-button click must consume the input frame."

display_block="$(sed -n '/void RuntimeApp::set_display_on/,/void RuntimeApp::set_button_feedback_suppressed/p' "$APP_CPP")"
refresh_line="$(grep -nF 'refresh_auth_mode();' <<<"$display_block" | head -n 1 | cut -d: -f1)"
guard_line="$(grep -nF 'ignore_touch_until_release_ = true;' <<<"$display_block" | head -n 1 | cut -d: -f1)"
if [[ -z "$refresh_line" || -z "$guard_line" || "$guard_line" -le "$refresh_line" ]]; then
  echo "Every display wake must arm the touch-release guard after auth-mode refresh." >&2
  exit 1
fi

touch_handler="$(sed -n '/void RuntimeApp::handle_touch_poll/,/bool RuntimeApp::handle_power_button/p' "$APP_CPP")"
touch_off_block="$(sed -n '/if (!display_on_) {/,/^[[:space:]]*return;/p' <<<"$touch_handler")"
if grep -Fq "set_display_on" <<<"$touch_off_block"; then
  echo "Touch input must not wake a display that is off." >&2
  exit 1
fi
require_contains "$touch_off_block" \
  "touch_down_ = down;" \
  "Display-off touch must be tracked only for the post-wake release guard."

key_block="$(sed -n '/void RuntimeApp::handle_key_event/,/void RuntimeApp::handle_touch_poll/p' "$APP_CPP")"

require_physical_wake() {
  local case_block="$1"
  local key_name="$2"
  local off_line
  local wake_line
  local return_line
  off_line="$(grep -nF 'if (!display_on_) {' <<<"$case_block" | head -n 1 | cut -d: -f1)"
  wake_line="$(grep -nF 'set_display_on(true, false, false);' <<<"$case_block" | head -n 1 | cut -d: -f1)"
  return_line="$(grep -nE '^[[:space:]]+return;' <<<"$case_block" | head -n 1 | cut -d: -f1)"
  if [[ -z "$off_line" || -z "$wake_line" || -z "$return_line" ||
        "$off_line" -ge "$wake_line" || "$wake_line" -ge "$return_line" ]]; then
    echo "${key_name} must wake an off display and consume the first input." >&2
    exit 1
  fi
}

previous_block="$(sed -n '/case input::KeyEvent::GoPrevious:/,/case input::KeyEvent::GoNext:/p' <<<"$key_block")"
next_block="$(sed -n '/case input::KeyEvent::GoNext:/,/case input::KeyEvent::GoHome:/p' <<<"$key_block")"
home_block="$(sed -n '/case input::KeyEvent::GoHome:/,/case input::KeyEvent::None:/p' <<<"$key_block")"
require_physical_wake "$previous_block" "KEYA"
require_physical_wake "$next_block" "KEYB"
require_physical_wake "$home_block" "KEYA+KEYB"

echo "physical wake policy structure checks passed"
