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
TARGET_ROOT="${REPO_ROOT}/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"

if [[ ! -f "${FIRMWARE_DIR}/main/CMakeLists.txt" || ! -f "${FIRMWARE_DIR}/main/main.cpp" ]]; then
  echo "Expected a StackChan firmware directory with main/CMakeLists.txt and main/main.cpp: ${FIRMWARE_DIR}" >&2
  exit 1
fi

if [[ ! -d "${TARGET_ROOT}/runtime" || ! -d "${TARGET_ROOT}/components/signing_crypto" || ! -d "${COMMON_ROOT}" ]]; then
  echo "Missing tracked StackChan CoreS3 overlay under ${TARGET_ROOT} or common firmware source under ${COMMON_ROOT}" >&2
  exit 1
fi

python3 - \
  "${TARGET_ROOT}/runtime" "${FIRMWARE_DIR}/main/runtime" "bip39_wordlist.cpp" \
  "${COMMON_ROOT}" "${FIRMWARE_DIR}/main/firmware_common" "" \
  "${TARGET_ROOT}/components/signing_crypto" "${FIRMWARE_DIR}/components/signing_crypto" "" <<'PY'
from __future__ import annotations

import filecmp
import shutil
import sys
from pathlib import Path


def remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def prepare_target_root(target_root: Path) -> None:
    parent = target_root.parent
    if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
        raise SystemExit(f"Refusing to sync through non-regular target parent: {parent}")
    if target_root.is_symlink() or (target_root.exists() and not target_root.is_dir()):
        remove_path(target_root)
    target_root.mkdir(parents=True, exist_ok=True)


def copy_file_if_changed(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        remove_path(target)
    if target.exists() and not target.is_file():
        remove_path(target)
    if target.exists() and target.is_file() and filecmp.cmp(source, target, shallow=False):
        return
    shutil.copy2(source, target)


def sync_tree(source_root: Path, target_root: Path, keep_relative_paths: set[Path]) -> None:
    if not source_root.is_dir():
        raise SystemExit(f"Source tree does not exist: {source_root}")
    prepare_target_root(target_root)

    source_entries: set[Path] = set()
    for source_path in source_root.rglob("*"):
        relative_path = source_path.relative_to(source_root)
        source_entries.add(relative_path)
        target_path = target_root / relative_path

        if source_path.is_dir():
            if target_path.is_symlink() or (target_path.exists() and not target_path.is_dir()):
                remove_path(target_path)
            target_path.mkdir(parents=True, exist_ok=True)
            continue
        if source_path.is_symlink():
            if target_path.exists() or target_path.is_symlink():
                remove_path(target_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.symlink_to(source_path.readlink())
            continue
        copy_file_if_changed(source_path, target_path)

    if not target_root.exists():
        return

    for target_path in sorted(target_root.rglob("*"), key=lambda path: len(path.parts), reverse=True):
        relative_path = target_path.relative_to(target_root)
        if relative_path in keep_relative_paths:
            continue
        if relative_path not in source_entries:
            remove_path(target_path)


if len(sys.argv) != 10:
    raise SystemExit("Expected three source/target/keep triplets.")

for index in range(1, len(sys.argv), 3):
    source = Path(sys.argv[index])
    target = Path(sys.argv[index + 1])
    keep = {Path(value) for value in sys.argv[index + 2].split(":") if value}
    sync_tree(source, target, keep)
PY

BIP39_WORDLIST_FILE="${BIP39_ENGLISH_WORDLIST_FILE:-}"
if [[ -z "${BIP39_WORDLIST_FILE}" && -n "${BIP39_WORDLIST_ROOT:-}" && -n "${BIP39_ENGLISH_WORDLIST_PATH:-}" ]]; then
  BIP39_WORDLIST_FILE="${BIP39_WORDLIST_ROOT}/${BIP39_ENGLISH_WORDLIST_PATH}"
fi
if [[ -z "${BIP39_WORDLIST_FILE}" || ! -f "${BIP39_WORDLIST_FILE}" ]]; then
  echo "Missing pinned BIP-39 English wordlist. Run firmware/tools/stackchan-cores3/build.sh or set BIP39_ENGLISH_WORDLIST_FILE." >&2
  exit 1
fi

python3 "${SCRIPT_DIR}/generate_bip39_wordlist.py" \
  "${BIP39_WORDLIST_FILE}" \
  "${FIRMWARE_DIR}/main/runtime/bip39_wordlist.cpp"

python3 - "${FIRMWARE_DIR}/main/CMakeLists.txt" "${FIRMWARE_DIR}/main/main.cpp" <<'PY'
from __future__ import annotations

import sys
import shutil
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


NVS_FLASH_ERASE = "nvs_flash_" + "erase"


def assert_no_symlink_ancestors(path: Path, root: Path, label: str) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise SystemExit(f"Could not patch {label}; path is outside firmware tree: {path}")

    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise SystemExit(f"Could not patch {label}; symlink ancestor in generated firmware path: {current}")


def remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def write_text_if_changed(path: Path, text: str) -> None:
    assert_no_symlink_ancestors(path, firmware_dir, str(path))
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SystemExit(f"Refusing to write through non-regular generated firmware path: {path}")
    if path.exists() and path.read_text() == text:
        return
    path.write_text(text)


def read_text_file(path: Path, label: str) -> str:
    assert_no_symlink_ancestors(path, firmware_dir, label)
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"Could not patch {label}; expected regular file at {path}.")
    return path.read_text()


def assert_generated_tree_not_contains(forbidden: str, label: str) -> None:
    search_roots = [
        firmware_dir / "main",
        firmware_dir / "components",
        firmware_dir / "xiaozhi-esp32",
    ]
    suffixes = {
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".ipp",
    }
    for root in search_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_symlink() or not path.is_file() or path.suffix not in suffixes:
                continue
            try:
                text = path.read_text()
            except UnicodeDecodeError:
                continue
            if forbidden in text:
                relative = path.relative_to(firmware_dir)
                raise SystemExit(
                    f"Agent-Q firmware hardening failed; {label} remains in {relative}."
                )


def patch_partition_table(text: str) -> str:
    replacements = {
        "nvs": ("0x9000", "0x10000"),
        "otadata": ("0x19000", "0x2000"),
        "phy_init": ("0x1b000", "0x1000"),
    }
    seen: set[str] = set()
    output_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            output_lines.append(line)
            continue

        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 5:
            parts = stripped.rstrip(",").split()
        if len(parts) < 5 or parts[0] not in replacements:
            output_lines.append(line)
            continue

        offset, size = replacements[parts[0]]
        parts[3] = offset
        parts[4] = size
        seen.add(parts[0])
        output_lines.append(
            f"{parts[0] + ',':<10}{parts[1] + ',':<7}{parts[2] + ',':<10}{parts[3] + ',':<12}{parts[4]},"
        )

    missing = set(replacements) - seen
    if missing:
        raise SystemExit(
            "Could not patch partitions.csv; expected partition rows missing: "
            + ", ".join(sorted(missing))
        )
    return "\n".join(output_lines) + "\n"


cmake_path = Path(sys.argv[1])
main_path = Path(sys.argv[2])
firmware_dir = main_path.parents[1]

for stale_root in [
    firmware_dir / "main/signing",
    firmware_dir / "main/signing_common",
    firmware_dir / "main/agent_q",
    firmware_dir / "main/agent_q_common",
]:
    assert_no_symlink_ancestors(stale_root, firmware_dir, str(stale_root))
    if stale_root.exists() or stale_root.is_symlink():
        remove_path(stale_root)

partitions_path = firmware_dir / "partitions.csv"
partitions = read_text_file(partitions_path, "partitions.csv")
partitions = patch_partition_table(partitions)
write_text_if_changed(partitions_path, partitions)

cmake = read_text_file(cmake_path, "main/CMakeLists.txt")
cmake = insert_after_once(
    cmake,
    '    "hal/*.cpp"\n',
    '    "runtime/*.c"\n    "runtime/*.cc"\n    "runtime/*.cpp"\n    "firmware_common/sui/*.c"\n    "firmware_common/sui/*.cc"\n    "firmware_common/sui/*.cpp"\n',
    "main/CMakeLists.txt sources",
)
cmake = insert_after_once(
    cmake,
    '    "firmware_common/sui/*.cpp"\n',
    '    "firmware_common/policy/*.c"\n    "firmware_common/policy/*.cc"\n    "firmware_common/policy/*.cpp"\n',
    "main/CMakeLists.txt common policy sources",
)
cmake = insert_after_once(
    cmake,
    '    "firmware_common/policy/*.cpp"\n',
    '    "firmware_common/protocol/*.c"\n    "firmware_common/protocol/*.cc"\n    "firmware_common/protocol/*.cpp"\n',
    "main/CMakeLists.txt common protocol sources",
)
cmake = insert_after_once(
    cmake,
    '    "firmware_common/protocol/*.cpp"\n',
    '    "firmware_common/signing/*.c"\n    "firmware_common/signing/*.cc"\n    "firmware_common/signing/*.cpp"\n',
    "main/CMakeLists.txt common signing sources",
)
cmake = insert_after_once(
    cmake,
    '    "firmware_common/signing/*.cpp"\n',
    '    "firmware_common/transport/*.c"\n    "firmware_common/transport/*.cc"\n    "firmware_common/transport/*.cpp"\n',
    "main/CMakeLists.txt common transport sources",
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
set(FIRMWARE_FORBIDDEN_STACKCHAN_SOURCE_PATTERNS
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
    "(^|.*/)hal/hal_ble\\.cpp$"
    "(^|.*/)hal/utils/bleprph/.*"
    "(^|.*/)hal/board/stackchan_camera\\.cc$"
)
foreach(FIRMWARE_FORBIDDEN_PATTERN IN LISTS FIRMWARE_FORBIDDEN_STACKCHAN_SOURCE_PATTERNS)
    list(FILTER STACK_CHAN_SOURCES EXCLUDE REGEX "${FIRMWARE_FORBIDDEN_PATTERN}")
endforeach()
foreach(FIRMWARE_SOURCE_FILE IN LISTS STACK_CHAN_SOURCES)
    foreach(FIRMWARE_FORBIDDEN_PATTERN IN LISTS FIRMWARE_FORBIDDEN_STACKCHAN_SOURCE_PATTERNS)
        if(FIRMWARE_SOURCE_FILE MATCHES "${FIRMWARE_FORBIDDEN_PATTERN}")
            message(FATAL_ERROR "Forbidden StackChan source still included: ${FIRMWARE_SOURCE_FILE}")
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
cmake = insert_after_once(
    cmake,
    'set(STACK_CHAN_INCLUDE_DIRS \n    "."\n',
    '    "firmware_common"\n',
    "main/CMakeLists.txt Agent-Q common include dir",
)
write_text_if_changed(cmake_path, cmake)

main_cpp = read_text_file(main_path, "main.cpp")
main_cpp = insert_after_once(
    main_cpp,
    "#include <hal/hal.h>\n",
    "#include <runtime/entropy.h>\n#include <runtime/signing_self_test.h>\n#include <runtime/usb_request_server.h>\n",
    "main.cpp includes",
)
main_cpp = insert_after_once(
    main_cpp,
    "    // HAL init\n",
    "    if (!signing::init_secure_random_from_early_boot_entropy()) {\n        mclog::tagError(\"Signing\", \"secure RNG init failed\");\n    }\n\n",
    "main.cpp early entropy",
)
main_cpp = insert_after_once(
    main_cpp,
    "    GetHAL().init();\n",
    "\n    // Agent-Q smoke checks\n    signing::run_signing_self_test();\n    signing::init_usb_request_server();\n",
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
write_text_if_changed(main_path, main_cpp)

hal_path = firmware_dir / "main/hal/hal.cpp"
hal = read_text_file(hal_path, "hal.cpp")
hal = replace_any_once(
    hal,
    [
        """    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(NVS_FLASH_ERASE_CALL());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
""".replace("NVS_FLASH_ERASE_CALL", NVS_FLASH_ERASE),
        """    esp_err_t ret = nvs_flash_init();
    ESP_ERROR_CHECK(ret);
""",
    ],
    """    esp_err_t ret = nvs_flash_init();
    if (ret != ESP_OK) {
        mclog::tagError(_tag, "NVS init failed; continuing so storage state can fail closed: {}", esp_err_to_name(ret));
    }
""",
    "hal.cpp NVS init without automatic erase",
)
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
hal = replace_function(
    hal,
    "void Hal::factoryReset()",
    """{
    mclog::tagWarn(_tag, "factory reset disabled; use device reset");
}
""",
    "hal.cpp NVS factory reset disabled",
)
assert_not_contains(hal, "xiaozhi_mcp_init();", "hal.cpp Xiaozhi MCP registration")
assert_not_contains(hal, NVS_FLASH_ERASE, "hal.cpp NVS partition erase")
write_text_if_changed(hal_path, hal)

wifi_manager_path = firmware_dir / "managed_components/78__esp-wifi-connect/wifi_manager.cc"
wifi_manager = read_text_file(wifi_manager_path, "wifi_manager.cc")
wifi_manager = replace_once(
    wifi_manager,
    """    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "Erasing NVS...");
        ESP_ERROR_CHECK(NVS_FLASH_ERASE_CALL());
        ret = nvs_flash_init();
    }
""".replace("NVS_FLASH_ERASE_CALL", NVS_FLASH_ERASE),
    """    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGE(TAG, "NVS initialization requires a development flash-erase workflow: %s", esp_err_to_name(ret));
        return false;
    }
""",
    "wifi_manager.cc NVS init without automatic erase",
)
assert_not_contains(wifi_manager, NVS_FLASH_ERASE, "wifi_manager.cc NVS partition erase")
write_text_if_changed(wifi_manager_path, wifi_manager)

bleprph_path = firmware_dir / "main/hal/utils/bleprph/bleprph.c"
bleprph = read_text_file(bleprph_path, "bleprph.c")
bleprph = remove_once(
    bleprph,
    f"    //     ESP_ERROR_CHECK({NVS_FLASH_ERASE}());\n",
    NVS_FLASH_ERASE,
    "bleprph.c commented NVS partition erase",
)
assert_not_contains(bleprph, NVS_FLASH_ERASE, "bleprph.c NVS partition erase")
write_text_if_changed(bleprph_path, bleprph)

espnow_storage_path = firmware_dir / "components/esp-now/src/utils/src/espnow_storage.c"
espnow_storage = read_text_file(espnow_storage_path, "espnow_storage.c")
espnow_storage = replace_once(
    espnow_storage,
    (
        """        if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            // NVS partition was truncated and needs to be erased
            // Retry nvs_flash_init
            ret = NVS_FLASH_ERASE_CALL();
"""
        "            \n"
        """            if(ret == ESP_OK) {
                ret = nvs_flash_init();
            }
        }
"""
    ).replace("NVS_FLASH_ERASE_CALL", NVS_FLASH_ERASE),
    """        if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            ESP_LOGE(TAG, "nvs_flash_init requires a development flash-erase workflow: %s", esp_err_to_name(ret));
            return ret;
        }
""",
    "espnow_storage.c NVS init without automatic erase",
)
assert_not_contains(espnow_storage, NVS_FLASH_ERASE, "espnow_storage.c NVS partition erase")
write_text_if_changed(espnow_storage_path, espnow_storage)

rndis_board_path = firmware_dir / "xiaozhi-esp32/main/boards/common/rndis_board.cc"
rndis_board = read_text_file(rndis_board_path, "rndis_board.cc")
rndis_board = replace_any_once(
    rndis_board,
    [
        """    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* NVS partition was truncated and needs to be erased
         * Retry nvs_flash_init */
        ESP_ERROR_CHECK(NVS_FLASH_ERASE_CALL());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
""".replace("NVS_FLASH_ERASE_CALL", NVS_FLASH_ERASE),
        """    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGE(TAG, "NVS initialization requires a development flash-erase workflow: %d", ret);
        ESP_ERROR_CHECK(ret);
    }
""",
    ],
    """    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGE(TAG, "NVS initialization requires a development flash-erase workflow: %d", ret);
        return;
    }
""",
    "rndis_board.cc NVS init without automatic erase",
)
assert_not_contains(rndis_board, NVS_FLASH_ERASE, "rndis_board.cc NVS partition erase")
write_text_if_changed(rndis_board_path, rndis_board)

system_reset_path = firmware_dir / "xiaozhi-esp32/main/boards/common/system_reset.cc"
system_reset = read_text_file(system_reset_path, "system_reset.cc")
system_reset = replace_function(
    system_reset,
    "void SystemReset::ResetNvsFlash()",
    """{
    ESP_LOGW(TAG, "NVS partition erase disabled for Agent-Q firmware");
    esp_err_t ret = nvs_flash_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize NVS flash");
    }
}
""",
    "system_reset.cc NVS erase disabled",
)
assert_not_contains(system_reset, NVS_FLASH_ERASE, "system_reset.cc NVS partition erase")
write_text_if_changed(system_reset_path, system_reset)

sensecap_path = firmware_dir / "xiaozhi-esp32/main/boards/sensecap-watcher/sensecap_watcher.cc"
sensecap = read_text_file(sensecap_path, "sensecap_watcher.cc")
sensecap = replace_once(
    sensecap,
    """                ESP_LOGI(TAG, "Factory reset");
                NVS_FLASH_ERASE_CALL();
                esp_restart();
""".replace("NVS_FLASH_ERASE_CALL", NVS_FLASH_ERASE),
    """                ESP_LOGI(TAG, "Factory reset requested; NVS partition erase disabled");
                esp_restart();
""",
    "sensecap_watcher.cc button factory erase disabled",
)
sensecap = replace_once(
    sensecap,
    """                NVS_FLASH_ERASE_CALL();
                esp_restart();
                return 0;
""".replace("NVS_FLASH_ERASE_CALL", NVS_FLASH_ERASE),
    """                ESP_LOGI(TAG, "Factory reset requested; NVS partition erase disabled");
                esp_restart();
                return 0;
""",
    "sensecap_watcher.cc console factory erase disabled",
)
assert_not_contains(sensecap, NVS_FLASH_ERASE, "sensecap_watcher.cc NVS partition erase")
write_text_if_changed(sensecap_path, sensecap)

launcher_path = firmware_dir / "main/apps/app_launcher/app_launcher.cpp"
launcher_header_path = firmware_dir / "main/apps/app_launcher/app_launcher.h"
launcher_header = read_text_file(launcher_header_path, "app_launcher.h")
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
write_text_if_changed(launcher_header_path, launcher_header)

launcher = read_text_file(launcher_path, "app_launcher.cpp")
launcher = insert_after_once(
    launcher,
    "#include <stackchan/stackchan.h>\n",
    "#include <runtime/usb_request_server.h>\n"
    "#include <runtime/display_power.h>\n"
    "#include <runtime/motion_state.h>\n",
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
        signing::set_motion_posture(signing::MotionPostureState::awake);
        signing::notify_signing_ui_surface_ready();
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

    signing::update_display_power(idle_time);
}
""",
    "app_launcher.cpp Agent-Q screen sleep without screensaver",
)
assert_not_contains(launcher, "_startup_worker", "app_launcher.cpp setup startup worker")
write_text_if_changed(launcher_path, launcher)

board_path = firmware_dir / "main/hal/board/stackchan.cc"
board = read_text_file(board_path, "stackchan.cc")
board = insert_after_once(
    board,
    "#include \"hal_bridge.h\"\n",
    "#include \"runtime/display_power.h\"\n#include \"runtime/motion_state.h\"\n#include <freertos/FreeRTOS.h>\n#include <freertos/task.h>\n",
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
            signing::set_motion_posture(signing::MotionPostureState::rest);
            vTaskDelay(pdMS_TO_TICKS(signing::motion_rest_posture_settle_ms()));
            pmic_->PowerOff();
            return;
        }
        if ((power_key_irqs & 0x08) != 0) {
            ESP_LOGI(TAG, "Power key short press: toggling display power");
            signing::request_display_power_toggle();
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
write_text_if_changed(board_path, board)

# Agent-Q downstream hardening of the shared I2C helpers.
#
# Rationale: a transient I2C timeout (observed in the field as an FT6336
# touch-controller read during display wake) was wrapped in ESP_ERROR_CHECK,
# which calls abort() and reboots the whole device (reset_reason=4 / PANIC).
# Rebooting a signing device because one touch register read timed out is
# unacceptable; a missed/late read is recoverable. Upstream already ships a
# tolerant TryReadRegs, so we extend the same policy to the per-register helpers:
# log and continue instead of abort. The boot-time bus-add ESP_ERROR_CHECK is
# left intact (a real configuration error should still fail fast).
#
# Maintainability: this uses replace_function(), which is idempotent and FAILS
# THE BUILD ("function signature not found") if a future upstream pin changes
# these signatures -- so this downstream change can never be silently dropped by
# an upstream update; it forces a deliberate review instead.
i2c_device_path = firmware_dir / "xiaozhi-esp32/main/boards/common/i2c_device.cc"
i2c_device = read_text_file(i2c_device_path, "i2c_device.cc")
i2c_device = insert_after_once(
    i2c_device,
    "#define TAG \"I2cDevice\"\n",
    "\n// Agent-Q downstream change: WriteReg/ReadReg/ReadRegs log-and-continue on a\n"
    "// transient I2C error instead of ESP_ERROR_CHECK/abort(), so a touch-controller\n"
    "// read timing out during display wake cannot reboot the signing device.\n",
    "i2c_device.cc Agent-Q tolerance note",
)
i2c_device = replace_function(
    i2c_device,
    "void I2cDevice::WriteReg(uint8_t reg, uint8_t value)",
    """{
    uint8_t buffer[2] = {reg, value};
    esp_err_t i2c_err = i2c_master_transmit(i2c_device_, buffer, 2, 100);
    if (i2c_err != ESP_OK) {
        ESP_LOGW(TAG, "WriteReg(0x%02x) failed: %s (Agent-Q: not fatal)", reg, esp_err_to_name(i2c_err));
    }
}
""",
    "i2c_device.cc WriteReg tolerant",
)
i2c_device = replace_function(
    i2c_device,
    "uint8_t I2cDevice::ReadReg(uint8_t reg)",
    """{
    uint8_t buffer[1] = {0};
    esp_err_t i2c_err = i2c_master_transmit_receive(i2c_device_, &reg, 1, buffer, 1, 100);
    if (i2c_err != ESP_OK) {
        ESP_LOGW(TAG, "ReadReg(0x%02x) failed: %s (Agent-Q: not fatal)", reg, esp_err_to_name(i2c_err));
    }
    return buffer[0];
}
""",
    "i2c_device.cc ReadReg tolerant",
)
i2c_device = replace_function(
    i2c_device,
    "void I2cDevice::ReadRegs(uint8_t reg, uint8_t* buffer, size_t length)",
    """{
    esp_err_t i2c_err = i2c_master_transmit_receive(i2c_device_, &reg, 1, buffer, length, 100);
    if (i2c_err != ESP_OK) {
        ESP_LOGW(TAG, "ReadRegs(0x%02x) failed: %s (Agent-Q: not fatal)", reg, esp_err_to_name(i2c_err));
    }
}
""",
    "i2c_device.cc ReadRegs tolerant",
)
assert_not_contains(i2c_device, "ESP_ERROR_CHECK(i2c_master_transmit(", "i2c_device.cc WriteReg abort removed")
assert_not_contains(i2c_device, "ESP_ERROR_CHECK(i2c_master_transmit_receive(", "i2c_device.cc read abort removed")
write_text_if_changed(i2c_device_path, i2c_device)

mcp_path = firmware_dir / "xiaozhi-esp32/main/mcp_server.cc"
mcp = read_text_file(mcp_path, "mcp_server.cc")
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
write_text_if_changed(mcp_path, mcp)

xiaozhi_main_path = firmware_dir / "xiaozhi-esp32/main/main.cc"
xiaozhi_main = read_text_file(xiaozhi_main_path, "xiaozhi main.cc")
xiaozhi_main = replace_any_once(
    xiaozhi_main,
    [
        """    // Initialize NVS flash for WiFi configuration
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "Erasing NVS flash to fix corruption");
        ESP_ERROR_CHECK(NVS_FLASH_ERASE_CALL());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
""".replace("NVS_FLASH_ERASE_CALL", NVS_FLASH_ERASE),
        """    // Initialize NVS flash without automatic erase.
    esp_err_t ret = nvs_flash_init();
    ESP_ERROR_CHECK(ret);
""",
    ],
    """    // Initialize NVS flash without automatic erase.
    esp_err_t ret = nvs_flash_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed; continuing so storage state can fail closed: %s", esp_err_to_name(ret));
    }
""",
    "xiaozhi main.cc NVS init without automatic erase",
)
assert_not_contains(xiaozhi_main, NVS_FLASH_ERASE, "xiaozhi main.cc NVS partition erase")
write_text_if_changed(xiaozhi_main_path, xiaozhi_main)

ws_avatar_path = firmware_dir / "main/hal/hal_ws_avatar.cpp"
ws_avatar = read_text_file(ws_avatar_path, "hal_ws_avatar.cpp")
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
write_text_if_changed(ws_avatar_path, ws_avatar)

assert_generated_tree_not_contains(NVS_FLASH_ERASE, "NVS partition erase")
PY

python3 - "${FIRMWARE_DIR}/sdkconfig.defaults" "${FIRMWARE_DIR}/sdkconfig" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path


REQUIRED_CONFIG = {
    "CONFIG_LV_FONT_UNSCII_8": "y",
    "CONFIG_LV_USE_QRCODE": "y",
    # Agent-Q local transport uses StackChan as a BLE peripheral. Keep the
    # BLE/NimBLE shape bounded to one central peer for the LT slices; this is
    # not a general Bluetooth product surface.
    "CONFIG_BT_ENABLED": "y",
    "CONFIG_BT_NIMBLE_ENABLED": "y",
    "CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_INTERNAL": "n",
    "CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL": "y",
    "CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_DEFAULT": "n",
    "CONFIG_BT_NIMBLE_ROLE_CENTRAL": "n",
    "CONFIG_BT_NIMBLE_ROLE_PERIPHERAL": "y",
    "CONFIG_BT_NIMBLE_ROLE_BROADCASTER": "y",
    "CONFIG_BT_NIMBLE_ROLE_OBSERVER": "n",
    "CONFIG_BT_NIMBLE_GATT_CLIENT": "n",
    "CONFIG_BT_NIMBLE_GATT_SERVER": "y",
    "CONFIG_BT_NIMBLE_SECURITY_ENABLE": "n",
    "CONFIG_BT_NIMBLE_HS_PVCY": "n",
    "CONFIG_MBEDTLS_HKDF_C": "y",
    "CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP": "y",
    "CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY": "y",
    "CONFIG_BT_NIMBLE_MAX_BONDS": "1",
    "CONFIG_BT_NIMBLE_MAX_CONNECTIONS": "1",
    "CONFIG_BT_NIMBLE_MAX_CCCDS": "2",
    "CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU": "128",
    "CONFIG_BT_NIMBLE_ATT_MAX_PREP_ENTRIES": "4",
    "CONFIG_BT_NIMBLE_MSYS_1_BLOCK_COUNT": "8",
    "CONFIG_BT_NIMBLE_MSYS_1_BLOCK_SIZE": "256",
    "CONFIG_BT_NIMBLE_MSYS_2_BLOCK_COUNT": "8",
    "CONFIG_BT_NIMBLE_MSYS_2_BLOCK_SIZE": "320",
    "CONFIG_BT_NIMBLE_TRANSPORT_ACL_FROM_LL_COUNT": "8",
    "CONFIG_BT_NIMBLE_TRANSPORT_ACL_SIZE": "255",
    "CONFIG_BT_NIMBLE_TRANSPORT_EVT_COUNT": "12",
    "CONFIG_BT_NIMBLE_TRANSPORT_EVT_DISCARD_COUNT": "2",
    "CONFIG_BT_NIMBLE_50_FEATURE_SUPPORT": "n",
    "CONFIG_BT_NIMBLE_PROX_SERVICE": "n",
    "CONFIG_BT_NIMBLE_ANS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_CTS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_HTP_SERVICE": "n",
    "CONFIG_BT_NIMBLE_IPSS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_TPS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_IAS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_LLS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_SPS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_HR_SERVICE": "n",
    "CONFIG_BT_NIMBLE_BAS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_DIS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_DTM_MODE_TEST": "n",
    "CONFIG_BT_CTRL_BLE_MAX_ACT": "2",
    "CONFIG_BT_CTRL_BLE_SCAN": "n",
    "CONFIG_BT_CTRL_BLE_SECURITY_ENABLE": "n",
    "CONFIG_BT_CTRL_DTM_ENABLE": "n",
}


def remove_existing_setting(text: str, key: str) -> str:
    lines = []
    for line in text.splitlines():
        if line == f"# {key} is not set" or line.startswith(f"{key}="):
            continue
        lines.append(line)
    if text.endswith("\n"):
        return "\n".join(lines) + "\n"
    return "\n".join(lines)


def ensure_required_config(config_path: Path) -> None:
    if not config_path.exists():
        return
    if config_path.is_symlink() or not config_path.is_file():
        raise SystemExit(f"Refusing to write through non-regular config path: {config_path}")

    text = config_path.read_text()
    changed = False
    for key, value in REQUIRED_CONFIG.items():
        desired = f"# {key} is not set\n" if value == "n" else f"{key}={value}\n"
        if desired in text:
            continue
        text = remove_existing_setting(text, key)
        if not text.endswith("\n"):
            text += "\n"
        text += desired
        changed = True
    if not changed:
        return
    if not text.endswith("\n"):
        text += "\n"
    config_path.write_text(text)


for arg in sys.argv[1:]:
    ensure_required_config(Path(arg))
PY

echo "Prepared StackChan CoreS3 firmware at ${FIRMWARE_DIR}"
