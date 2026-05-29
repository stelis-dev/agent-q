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

if [[ ! -f "${FIRMWARE_DIR}/main/CMakeLists.txt" || ! -f "${FIRMWARE_DIR}/main/main.cpp" ]]; then
  echo "Expected a StackChan firmware directory with main/CMakeLists.txt and main/main.cpp: ${FIRMWARE_DIR}" >&2
  exit 1
fi

if [[ ! -d "${TARGET_ROOT}/agent_q" || ! -d "${TARGET_ROOT}/components/signing_crypto" ]]; then
  echo "Missing tracked StackChan CoreS3 firmware overlay under ${TARGET_ROOT}" >&2
  exit 1
fi

rm -rf "${FIRMWARE_DIR}/main/agent_q"
cp -R "${TARGET_ROOT}/agent_q" "${FIRMWARE_DIR}/main/agent_q"

mkdir -p "${FIRMWARE_DIR}/components"
rm -rf "${FIRMWARE_DIR}/components/signing_crypto"
cp -R "${TARGET_ROOT}/components/signing_crypto" "${FIRMWARE_DIR}/components/signing_crypto"

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
    '    "agent_q/*.c"\n    "agent_q/*.cc"\n    "agent_q/*.cpp"\n',
    "main/CMakeLists.txt sources",
)
cmake = insert_after_once(
    cmake,
    '    "stackchan/*.cpp"\n)\n',
    r'''

# Agent-Q firmware is a local USB signing-device build, not a general
# StackChan/Xiaozhi AI firmware. Remove upstream app/cloud/camera sources from
# the hardware-specific StackChan source glob so those surfaces are not linked
# into this build.
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/apps/app_ai_agent/.*")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/apps/app_avatar/.*")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/apps/app_ezdata/.*")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/apps/app_setup/.*")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/apps/app_app_center/.*")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/apps/app_espnow_ctrl/.*")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/apps/app_dance/.*")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/hal/hal_account\\.cpp$")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/hal/hal_ezdata\\.cpp$")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/hal/hal_mcp\\.cpp$")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/hal/hal_ws_avatar\\.cpp$")
list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX ".*/hal/board/stackchan_camera\\.cc$")
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
cmake_path.write_text(cmake)

main_cpp = main_path.read_text()
main_cpp = insert_after_once(
    main_cpp,
    "#include <hal/hal.h>\n",
    "#include <agent_q/agent_q_signing_self_test.h>\n#include <agent_q/agent_q_usb_request_server.h>\n",
    "main.cpp includes",
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
        screensaver_update();
    }

    GetStackChan().update();
""",
    "app_launcher.cpp startup worker loop disabled",
)
assert_not_contains(launcher, "_startup_worker", "app_launcher.cpp setup startup worker")
launcher_path.write_text(launcher)

board_path = firmware_dir / "main/hal/board/stackchan.cc"
board = board_path.read_text()
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

echo "Prepared StackChan CoreS3 firmware at ${FIRMWARE_DIR}"
