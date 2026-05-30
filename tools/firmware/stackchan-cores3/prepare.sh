#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 /path/to/StackChan/firmware" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
FIRMWARE_DIR="$(cd "$1" && pwd)"
TARGET_ROOT="${REPO_ROOT}/products/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/products/firmware/src/common/agent_q"

if [[ ! -f "${FIRMWARE_DIR}/main/CMakeLists.txt" || ! -f "${FIRMWARE_DIR}/main/main.cpp" ]]; then
  echo "Expected a StackChan firmware directory with main/CMakeLists.txt and main/main.cpp: ${FIRMWARE_DIR}" >&2
  exit 1
fi

if [[ ! -d "${TARGET_ROOT}/agent_q" || ! -d "${TARGET_ROOT}/components/signing_crypto" || ! -d "${COMMON_ROOT}" ]]; then
  echo "Missing tracked StackChan CoreS3 overlay under ${TARGET_ROOT} or common Agent-Q source under ${COMMON_ROOT}" >&2
  exit 1
fi

rm -rf "${FIRMWARE_DIR}/main/agent_q"
cp -R "${TARGET_ROOT}/agent_q" "${FIRMWARE_DIR}/main/agent_q"
rm -rf "${FIRMWARE_DIR}/main/agent_q_common"
cp -R "${COMMON_ROOT}" "${FIRMWARE_DIR}/main/agent_q_common"

mkdir -p "${FIRMWARE_DIR}/components"
rm -rf "${FIRMWARE_DIR}/components/signing_crypto"
cp -R "${TARGET_ROOT}/components/signing_crypto" "${FIRMWARE_DIR}/components/signing_crypto"

BIP39_WORDLIST_FILE="${AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE:-}"
if [[ -z "${BIP39_WORDLIST_FILE}" && -n "${AGENT_Q_BIP39_WORDLIST_ROOT:-}" && -n "${AGENT_Q_BIP39_ENGLISH_WORDLIST_PATH:-}" ]]; then
  BIP39_WORDLIST_FILE="${AGENT_Q_BIP39_WORDLIST_ROOT}/${AGENT_Q_BIP39_ENGLISH_WORDLIST_PATH}"
fi
if [[ -z "${BIP39_WORDLIST_FILE}" || ! -f "${BIP39_WORDLIST_FILE}" ]]; then
  echo "Missing pinned BIP-39 English wordlist. Run tools/firmware/stackchan-cores3/build.sh or set AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE." >&2
  exit 1
fi

python3 "${SCRIPT_DIR}/generate_bip39_wordlist.py" \
  "${BIP39_WORDLIST_FILE}" \
  "${FIRMWARE_DIR}/main/agent_q/agent_q_bip39_wordlist.cpp"

python3 - "${FIRMWARE_DIR}/main/CMakeLists.txt" "${FIRMWARE_DIR}/main/main.cpp" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path


def insert_after_once(text: str, needle: str, insert: str, label: str) -> str:
    if insert.strip() in text:
        return text
    if needle not in text:
        raise SystemExit(f"Could not patch {label}; expected anchor not found.")
    return text.replace(needle, needle + insert, 1)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new.strip() and new.strip() in text:
        return text
    if old not in text:
        raise SystemExit(f"Could not patch {label}; expected anchor not found.")
    return text.replace(old, new, 1)


def replace_any_once(text: str, old_values: list[str], new: str, label: str) -> str:
    if new.strip() and new.strip() in text:
        return text
    for old in old_values:
        if old in text:
            return text.replace(old, new, 1)
    raise SystemExit(f"Could not patch {label}; expected anchor not found.")


def remove_once(text: str, old: str, forbidden: str, label: str) -> str:
    if old in text:
        return text.replace(old, "", 1)
    if forbidden in text:
        raise SystemExit(f"Could not patch {label}; unsafe call still present.")
    return text


def replace_function(text: str, signature: str, new_body: str, label: str) -> str:
    replacement = signature + "\n" + new_body
    if replacement in text:
        return text

    start = text.find(signature)
    if start == -1:
        raise SystemExit(f"Could not patch {label}; function signature not found.")

    brace_start = text.find("{", start + len(signature))
    if brace_start == -1:
        raise SystemExit(f"Could not patch {label}; function body not found.")

    depth = 0
    end = None
    for index in range(brace_start, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break

    if end is None:
        raise SystemExit(f"Could not patch {label}; function body did not close.")

    return text[:start] + replacement + text[end:]


def assert_not_contains(text: str, forbidden: str, label: str) -> None:
    if forbidden in text:
        raise SystemExit(f"Agent-Q firmware hardening failed; {label} remains.")


cmake_path = Path(sys.argv[1])
main_path = Path(sys.argv[2])
firmware_dir = main_path.parents[1]

cmake = cmake_path.read_text()
cmake = insert_after_once(
    cmake,
    '    "hal/*.cpp"\n',
    '    "agent_q/*.c"\n    "agent_q/*.cc"\n    "agent_q/*.cpp"\n    "agent_q_common/sui/*.c"\n    "agent_q_common/sui/*.cc"\n    "agent_q_common/sui/*.cpp"\n',
    "main/CMakeLists.txt sources",
)
cmake = insert_after_once(
    cmake,
    '    "agent_q_common/sui/*.cpp"\n',
    '    "agent_q_common/policy/*.c"\n    "agent_q_common/policy/*.cc"\n    "agent_q_common/policy/*.cpp"\n',
    "main/CMakeLists.txt common policy sources",
)
cmake = insert_after_once(
    cmake,
    '    "stackchan/*.cpp"\n)\n',
    r'''

# Agent-Q firmware is a local USB signing-device build, not a general
# StackChan/Xiaozhi AI firmware. Remove upstream app/cloud/camera sources from
# the hardware-specific StackChan source glob so those surfaces are not linked
# into this build. The glob may contain relative or absolute paths depending on
# CMake configuration, so each pattern must match either form.
set(AGENT_Q_FORBIDDEN_STACKCHAN_SOURCE_PATTERNS
    "(^|.*/)apps/app_ai_agent/.*"
    "(^|.*/)apps/app_avatar/.*"
    "(^|.*/)apps/app_ezdata/.*"
    "(^|.*/)apps/app_setup/.*"
    "(^|.*/)apps/app_app_center/.*"
    "(^|.*/)apps/app_espnow_ctrl/.*"
    "(^|.*/)apps/app_dance/.*"
    "(^|.*/)hal/hal_account\\.cpp$"
    "(^|.*/)hal/hal_ezdata\\.cpp$"
    "(^|.*/)hal/hal_mcp\\.cpp$"
    "(^|.*/)hal/hal_ws_avatar\\.cpp$"
    "(^|.*/)hal/board/stackchan_camera\\.cc$"
)
foreach(AGENT_Q_FORBIDDEN_PATTERN IN LISTS AGENT_Q_FORBIDDEN_STACKCHAN_SOURCE_PATTERNS)
    list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX "${AGENT_Q_FORBIDDEN_PATTERN}")
endforeach()
foreach(AGENT_Q_SOURCE_FILE IN LISTS STACK_CHAN_SOURCES)
    foreach(AGENT_Q_FORBIDDEN_PATTERN IN LISTS AGENT_Q_FORBIDDEN_STACKCHAN_SOURCE_PATTERNS)
        if(AGENT_Q_SOURCE_FILE MATCHES "${AGENT_Q_FORBIDDEN_PATTERN}")
            message(FATAL_ERROR "Agent-Q forbidden StackChan source still included: ${AGENT_Q_SOURCE_FILE}")
        endif()
    endforeach()
endforeach()
''',
    "main/CMakeLists.txt Agent-Q source filters",
)
cmake = insert_after_once(
    cmake,
    "                        esp_driver_uart\n",
    "                        esp_driver_usb_serial_jtag\n",
    "main/CMakeLists.txt usb dependency",
)
cmake = insert_after_once(
    cmake,
    "                        mooncake_log\n",
    "                        signing_crypto\n",
    "main/CMakeLists.txt signing dependency",
)
cmake = insert_after_once(
    cmake,
    "                        signing_crypto\n",
    "                        mbedtls\n",
    "main/CMakeLists.txt BIP-39 checksum dependency",
)
cmake = insert_after_once(
    cmake,
    "                        mbedtls\n",
    "                        bootloader_support\n",
    "main/CMakeLists.txt early entropy dependency",
)
cmake_path.write_text(cmake)

main_cpp = main_path.read_text()
main_cpp = insert_after_once(
    main_cpp,
    "#include <hal/hal.h>\n",
    "#include <agent_q/agent_q_entropy.h>\n#include <agent_q/agent_q_signing_self_test.h>\n#include <agent_q/agent_q_usb_request_server.h>\n",
    "main.cpp includes",
)
main_cpp = insert_after_once(
    main_cpp,
    "    // HAL init\n",
    "    if (!agent_q::init_secure_random_from_early_boot_entropy()) {\n        mclog::tagError(\"AgentQ\", \"secure RNG init failed\");\n    }\n\n",
    "main.cpp early entropy",
)
main_cpp = insert_after_once(
    main_cpp,
    "    GetHAL().init();\n",
    "\n    // Agent-Q smoke checks\n    agent_q::run_signing_self_test();\n    agent_q::init_usb_request_server();\n",
    "main.cpp startup",
)
main_cpp = replace_once(
    main_cpp,
    """    // Install apps
    GetMooncake().installApp(std::make_unique<AppLauncher>());
    GetMooncake().installApp(std::make_unique<AppAiAgent>());
    GetMooncake().installApp(std::make_unique<AppAvatar>());
    GetMooncake().installApp(std::make_unique<AppEspnowControl>());
    GetMooncake().installApp(std::make_unique<AppAppCenter>());
    GetMooncake().installApp(std::make_unique<AppEzdata>());
    GetMooncake().installApp(std::make_unique<AppDance>());
    GetMooncake().installApp(std::make_unique<AppSetup>());
""",
    """    // Agent-Q firmware keeps only the local launcher surface. Remote AI,
    // cloud, camera upload, screen upload, setup, and app-center surfaces are
    // not part of the signing-device firmware.
    GetMooncake().installApp(std::make_unique<AppLauncher>());
""",
    "main.cpp installed apps",
)
main_cpp = replace_once(
    main_cpp,
    """        if (GetHAL().isXiaozhiStartRequested()) {
            break;
        }
""",
    """        // Agent-Q firmware never enters the remote Xiaozhi agent runtime.
    """,
    "main.cpp xiaozhi start request",
)
main_cpp = remove_once(
    main_cpp,
    """
    // Uninstall all apps and destroy mooncake
    GetMooncake().uninstallAllApps();
    DestroyMooncake();

    // Start xiaozhi, never returns
    GetHAL().startXiaozhi();
""",
    "GetHAL().startXiaozhi(",
    "main.cpp xiaozhi start tail",
)
assert_not_contains(main_cpp, "GetHAL().startXiaozhi(", "main.cpp Xiaozhi runtime start")
assert_not_contains(main_cpp, "GetMooncake().installApp(std::make_unique<AppAiAgent>", "main.cpp AI agent app install")
assert_not_contains(main_cpp, "GetMooncake().installApp(std::make_unique<AppAvatar>", "main.cpp avatar app install")
assert_not_contains(main_cpp, "GetMooncake().installApp(std::make_unique<AppEspnowControl>", "main.cpp ESP-NOW app install")
assert_not_contains(main_cpp, "GetMooncake().installApp(std::make_unique<AppAppCenter>", "main.cpp app center install")
assert_not_contains(main_cpp, "GetMooncake().installApp(std::make_unique<AppEzdata>", "main.cpp EzData app install")
assert_not_contains(main_cpp, "GetMooncake().installApp(std::make_unique<AppDance>", "main.cpp dance app install")
assert_not_contains(main_cpp, "GetMooncake().installApp(std::make_unique<AppSetup>", "main.cpp setup app install")
main_path.write_text(main_cpp)

hal_path = firmware_dir / "main/hal/hal.cpp"
hal = hal_path.read_text()
hal = replace_once(
    hal,
    "    xiaozhi_mcp_init();\n",
    "    // Agent-Q firmware does not register Xiaozhi remote MCP tools.\n",
    "hal.cpp xiaozhi mcp init",
)
hal = replace_once(
    hal,
    "static void _stackchan_update_task(void* param)\n",
    "[[maybe_unused]] static void _stackchan_update_task(void* param)\n",
    "hal.cpp unused xiaozhi update task",
)
hal = replace_function(
    hal,
    "void Hal::startXiaozhi()",
    """{
    mclog::tagInfo(_tag, "xiaozhi runtime disabled for Agent-Q firmware");
}
""",
    "hal.cpp xiaozhi runtime disabled",
)
assert_not_contains(hal, "xiaozhi_mcp_init();", "hal.cpp Xiaozhi MCP registration")
hal_path.write_text(hal)

launcher_path = firmware_dir / "main/apps/app_launcher/app_launcher.cpp"
launcher_header_path = firmware_dir / "main/apps/app_launcher/app_launcher.h"
launcher_header = launcher_header_path.read_text()
launcher_header = remove_once(
    launcher_header,
    "#include <apps/app_setup/workers/workers.h>\n",
    "apps/app_setup/workers/workers.h",
    "app_launcher.h setup worker include disabled",
)
launcher_header = remove_once(
    launcher_header,
    "    std::unique_ptr<setup_workers::StartupWorker> _startup_worker;\n",
    "setup_workers::StartupWorker",
    "app_launcher.h setup worker member disabled",
)
assert_not_contains(launcher_header, "setup_workers::StartupWorker", "app_launcher.h setup startup worker")
assert_not_contains(launcher_header, "apps/app_setup/workers/workers.h", "app_launcher.h setup worker include")
launcher_header_path.write_text(launcher_header)

launcher = launcher_path.read_text()
launcher = insert_after_once(
    launcher,
    "#include <stackchan/stackchan.h>\n",
    "#include <agent_q/agent_q_usb_request_server.h>\n"
    "#include <agent_q/agent_q_display_power.h>\n",
    "app_launcher.cpp Agent-Q provisioning UI include",
)
launcher = replace_any_once(
    launcher,
    [
        """    if (!_startup_checked && !GetHAL().isAppConfiged()) {
        mclog::tagInfo(getAppInfo().name, "app not configured, start startup worker");
        _startup_worker = std::make_unique<setup_workers::StartupWorker>();
    } else {
        create_launcher_view();
    }
""",
        """    _startup_checked = true;
    create_launcher_view();
""",
        """    _startup_checked = true;
    if (getAppProps().empty()) {
        auto avatar = std::make_unique<avatar::DefaultAvatar>();
        avatar->init(lv_screen_active());
        GetStackChan().attachAvatar(std::move(avatar));
        _view.reset();
    } else {
        create_launcher_view();
    }
""",
        """    _startup_checked = true;
    if (getAppProps().empty()) {
        auto default_avatar = std::make_unique<stackchan::avatar::DefaultAvatar>();
        default_avatar->init(lv_screen_active());
        GetStackChan().attachAvatar(std::move(default_avatar));
        _view.reset();
    } else {
        create_launcher_view();
    }
""",
    ],
    """    _startup_checked = true;
    if (getAppProps().empty()) {
        auto default_avatar = std::make_unique<stackchan::avatar::DefaultAvatar>();
        default_avatar->init(lv_screen_active());
        if (default_avatar->getKeyElements().speechBubble) {
            default_avatar->getKeyElements().speechBubble->setVisible(false);
        }
        GetStackChan().attachAvatar(std::move(default_avatar));
        GetStackChan().addModifier(std::make_unique<stackchan::BlinkModifier>());
        GetStackChan().addModifier(std::make_unique<stackchan::IdleExpressionModifier>(8000, 20000));
        GetStackChan().motion().moveWithSpeed(0, 540, 500);
        agent_q::show_provisioning_welcome_if_needed();
        _view.reset();
    } else {
        create_launcher_view();
    }
""",
    "app_launcher.cpp startup setup disabled",
)
launcher = replace_any_once(
    launcher,
    [
        """    if (_startup_worker) {
        _startup_worker->update();
        if (_startup_worker->isDone()) {
            _startup_worker.reset();
            _startup_checked = true;
            create_launcher_view();
        }
    } else {
        _view->update();
        screensaver_update();
    }

    GetStackChan().update();
""",
        """    _view->update();
    screensaver_update();

    GetStackChan().update();
""",
    ],
    """    if (_view) {
        _view->update();
    }
    screensaver_update();

    GetStackChan().update();
""",
    "app_launcher.cpp startup worker loop disabled",
)
launcher = replace_once(
    launcher,
    """void AppLauncher::screensaver_update()
{
    const uint32_t SCREENSAVER_TIMEOUT_MS = 30000;

    uint32_t idle_time = lv_display_get_inactive_time(NULL);
    if (idle_time >= SCREENSAVER_TIMEOUT_MS) {
        if (!_screensaver) {
            _screensaver = std::make_unique<view::Screensaver>();
            _screensaver->init();
        }
    } else if (_screensaver) {
        _screensaver.reset();
    }

    // Update in 30ms interval
    if (_screensaver && GetHAL().millis() - _screensaver_timecount > 30) {
        _screensaver_timecount = GetHAL().millis();
        _screensaver->update();
    }
}
""",
    """void AppLauncher::screensaver_update()
{
    uint32_t idle_time = lv_display_get_inactive_time(NULL);
    if (_screensaver) {
        _screensaver.reset();
    }

    agent_q::update_display_power(idle_time);
}
""",
    "app_launcher.cpp Agent-Q screen sleep without screensaver",
)
assert_not_contains(launcher, "_startup_worker", "app_launcher.cpp setup startup worker")
launcher_path.write_text(launcher)

board_path = firmware_dir / "main/hal/board/stackchan.cc"
board = board_path.read_text()
board = insert_after_once(
    board,
    "#include \"hal_bridge.h\"\n",
    "#include \"agent_q/agent_q_display_power.h\"\n#include <freertos/FreeRTOS.h>\n#include <freertos/task.h>\n",
    "stackchan.cc Agent-Q display power include",
)
board = replace_once(
    board,
    "    StackChanCamera* camera_;\n",
    "    StackChanCamera* camera_ = nullptr;\n",
    "stackchan.cc camera member default",
)
board = replace_once(
    board,
    "        InitializeCamera();\n",
    "        // Agent-Q firmware does not initialize the camera.\n",
    "stackchan.cc camera init disabled",
)
assert_not_contains(board, "InitializeCamera();", "stackchan.cc camera initialization")
board = replace_once(
    board,
    """    bool IsExternalPowerConnected()
    {
        const uint8_t power_status      = ReadReg(0x01);
        const uint8_t current_direction = (power_status & 0b01100000) >> 5;
        const bool is_charging_done     = (power_status & 0b00000111) == 0b00000100;

        // Treat any non-discharging state as externally powered so a plugged-in cable
        // still counts even after the battery is full.
        return current_direction != 2 || is_charging_done;
    }
};
""",
    """    void EnablePowerKeyIrqs()
    {
        const uint8_t irq_enable = ReadReg(0x41);
        WriteReg(0x41, irq_enable | 0x0C);
        WriteReg(0x49, 0x0C);
    }

    uint8_t ConsumePowerKeyIrqs()
    {
        const uint8_t irq_status = ReadReg(0x49) & 0x0C;
        if (irq_status != 0) {
            WriteReg(0x49, irq_status);
        }
        return irq_status;
    }

    bool IsExternalPowerConnected()
    {
        const uint8_t power_status      = ReadReg(0x01);
        const uint8_t current_direction = (power_status & 0b01100000) >> 5;
        const bool is_charging_done     = (power_status & 0b00000111) == 0b00000100;

        // Treat any non-discharging state as externally powered so a plugged-in cable
        // still counts even after the battery is full.
        return current_direction != 2 || is_charging_done;
    }
};
""",
    "stackchan.cc AXP2101 power key IRQ helpers",
)
board = insert_after_once(
    board,
    "    static constexpr int kPowerStatePollIntervalMs   = 1000;\n",
    "    static constexpr int kPowerKeyPollIntervalMs     = 100;\n",
    "stackchan.cc power key poll constant",
)
board = insert_after_once(
    board,
    "    int64_t last_power_state_check_ms_ = 0;\n",
    "    int64_t last_power_key_check_ms_   = 0;\n",
    "stackchan.cc power key poll timestamp",
)
board = insert_after_once(
    board,
    """    void UpdatePowerSaveEnabled(bool has_external_power, bool is_discharging)
    {
        const bool should_enable_power_save = ShouldEnablePowerSave(has_external_power, is_discharging);
        if (should_enable_power_save == last_power_save_enabled_) {
            return;
        }

        ESP_LOGI(TAG, "Power save timer %s: external_power=%d, discharging=%d, allowShutdownWhenCharging=%d",
                 should_enable_power_save ? "enabled" : "disabled", has_external_power, is_discharging,
                 xiaozhi_config_.allowShutdownWhenCharging);
        power_save_timer_->SetEnabled(should_enable_power_save);
        last_power_save_enabled_ = should_enable_power_save;
    }

""",
    """    void PollPowerKeyState(int64_t now_ms)
    {
        if (last_power_key_check_ms_ != 0 && (now_ms - last_power_key_check_ms_) < kPowerKeyPollIntervalMs) {
            return;
        }
        last_power_key_check_ms_ = now_ms;

        const uint8_t power_key_irqs = pmic_->ConsumePowerKeyIrqs();
        if ((power_key_irqs & 0x04) != 0) {
            ESP_LOGI(TAG, "Power key long press: moving to rest posture and powering off");
            agent_q::prepare_display_power_rest_posture();
            vTaskDelay(pdMS_TO_TICKS(agent_q::display_power_rest_posture_delay_ms()));
            pmic_->PowerOff();
            return;
        }
        if ((power_key_irqs & 0x08) != 0) {
            ESP_LOGI(TAG, "Power key short press: toggling display power");
            agent_q::request_display_power_toggle();
        }
    }

""",
    "stackchan.cc Agent-Q power key polling",
)
board = insert_after_once(
    board,
    """    void PollPowerSaveState()
    {
        const int64_t now_ms = esp_timer_get_time() / 1000;
""",
    """        PollPowerKeyState(now_ms);

""",
    "stackchan.cc polls power key before power-save throttle",
)
board = insert_after_once(
    board,
    """        pmic_ = new Pmic(i2c_bus_, 0x34);
""",
    """        pmic_->EnablePowerKeyIrqs();
""",
    "stackchan.cc enables AXP2101 power key IRQs",
)
board_path.write_text(board)

mcp_path = firmware_dir / "xiaozhi-esp32/main/mcp_server.cc"
mcp = mcp_path.read_text()
mcp = replace_function(
    mcp,
    "void McpServer::AddCommonTools()",
    """{
    ESP_LOGI(TAG, "Xiaozhi common tools disabled for Agent-Q firmware");
}
""",
    "mcp_server.cc common tools disabled",
)
mcp = replace_function(
    mcp,
    "void McpServer::AddUserOnlyTools()",
    """{
    ESP_LOGI(TAG, "Xiaozhi user-only tools disabled for Agent-Q firmware");
}
""",
    "mcp_server.cc user tools disabled",
)
mcp = replace_function(
    mcp,
    "void McpServer::ParseCapabilities(const cJSON* capabilities)",
    """{
    (void)capabilities;
    ESP_LOGI(TAG, "Xiaozhi capabilities ignored for Agent-Q firmware");
}
""",
    "mcp_server.cc capabilities ignored",
)
assert_not_contains(mcp, "self.camera.take_photo", "Xiaozhi camera MCP tool")
assert_not_contains(mcp, "self.screen.snapshot", "Xiaozhi screen snapshot MCP tool")
assert_not_contains(mcp, "camera->SetExplainUrl", "Xiaozhi vision upload capability")
mcp_path.write_text(mcp)

ws_avatar_path = firmware_dir / "main/hal/hal_ws_avatar.cpp"
ws_avatar = ws_avatar_path.read_text()
ws_avatar = replace_function(
    ws_avatar,
    "void Hal::startWebSocketAvatarService(std::function<void(std::string_view)> onStartLog)",
    """{
    mclog::tagInfo(_tag, "websocket avatar service disabled for Agent-Q firmware");
    onStartLog("Remote avatar disabled");
}
""",
    "hal_ws_avatar.cpp websocket avatar disabled",
)
ws_avatar_path.write_text(ws_avatar)
PY

python3 - "${FIRMWARE_DIR}/sdkconfig.defaults" "${FIRMWARE_DIR}/sdkconfig" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path


def enable_unscii_8(config_path: Path) -> None:
    if not config_path.exists():
        return

    text = config_path.read_text()
    if "CONFIG_LV_FONT_UNSCII_8=y" in text:
        return
    text = text.replace("# CONFIG_LV_FONT_UNSCII_8 is not set\n", "")
    if not text.endswith("\n"):
        text += "\n"
    text += "CONFIG_LV_FONT_UNSCII_8=y\n"
    config_path.write_text(text)


for arg in sys.argv[1:]:
    enable_unscii_8(Path(arg))
PY

echo "Prepared StackChan CoreS3 firmware at ${FIRMWARE_DIR}"
