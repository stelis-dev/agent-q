#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-prepare-config.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

CHECKOUT_DIR="${TMP_DIR}/M5StopWatch-UserDemo"
mkdir -p \
  "${CHECKOUT_DIR}/main/hal" \
  "${CHECKOUT_DIR}/main/hal/utils/config_ap" \
  "${CHECKOUT_DIR}/components/M5GFX" \
  "${CHECKOUT_DIR}/components/lvgl" \
  "${CHECKOUT_DIR}/components/M5PM1" \
  "${CHECKOUT_DIR}/components/M5IOE1"

cat >"${CHECKOUT_DIR}/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(M5StopWatch-UserDemo)
EOF
cat >"${CHECKOUT_DIR}/main/CMakeLists.txt" <<'EOF'
idf_component_register(SRCS "main.cpp" INCLUDE_DIRS ".")
EOF
cat >"${CHECKOUT_DIR}/main/main.cpp" <<'EOF'
extern "C" void app_main(void) {}
EOF
cat >"${CHECKOUT_DIR}/main/hal/hal.cpp" <<'EOF'
#include "hal.h"

void Hal::init()
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
}

void Hal::factoryReset()
{
    mclog::tagInfo(_tag, "start factory reset");
    ESP_ERROR_CHECK(nvs_flash_erase());
    reboot();
}
EOF
cat >"${CHECKOUT_DIR}/main/hal/utils/config_ap/config_ap.cpp" <<'EOF'
bool ensure_wifi_stack_ready()
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    if (ret != ESP_OK) {
        return false;
    }
    return true;
}
EOF
cat >"${CHECKOUT_DIR}/sdkconfig.defaults" <<'EOF'
CONFIG_IDF_TARGET="esp32s3"
CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192
EOF
cat >"${CHECKOUT_DIR}/sdkconfig" <<'EOF'
CONFIG_IDF_TARGET="esp32s3"
CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192
EOF

git -C "${CHECKOUT_DIR}" init -q
git -C "${CHECKOUT_DIR}" add CMakeLists.txt main/CMakeLists.txt main/main.cpp main/hal/hal.cpp main/hal/utils/config_ap/config_ap.cpp sdkconfig.defaults sdkconfig

"${SCRIPT_DIR}/prepare.sh" "${CHECKOUT_DIR}" >/dev/null

for config_file in "${CHECKOUT_DIR}/sdkconfig.defaults" "${CHECKOUT_DIR}/sdkconfig"; do
  count="$(grep -Ec '^CONFIG_ESP_MAIN_TASK_STACK_SIZE=' "${config_file}")"
  if [[ "${count}" != "1" ]]; then
    echo "Expected exactly one main task stack setting in ${config_file}, found ${count}" >&2
    exit 1
  fi
  if ! grep -qx 'CONFIG_ESP_MAIN_TASK_STACK_SIZE=32768' "${config_file}"; then
    echo "prepare.sh did not set StopWatch main task stack to 32768 in ${config_file}" >&2
    exit 1
  fi
done

if grep -R "nvs_flash_erase" "${CHECKOUT_DIR}/main" "${CHECKOUT_DIR}/components" >/dev/null; then
  echo "prepare.sh left unsafe nvs_flash_erase in prepared tree" >&2
  exit 1
fi
if grep -R "factoryReset" "${CHECKOUT_DIR}/main" "${CHECKOUT_DIR}/components" >/dev/null; then
  echo "prepare.sh left factoryReset in prepared tree" >&2
  exit 1
fi

echo "StopWatch prepare config test passed"
