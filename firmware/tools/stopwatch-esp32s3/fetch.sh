#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stopwatch-esp32s3/fetch.sh [path-to-M5StopWatch-UserDemo]

Fetches the pinned M5Stack StopWatch ESP32-S3 firmware host repository and its
pinned Git component dependencies into the given directory. The default
destination is the ignored .firmware-cache directory. The script does not depend
on .WORK paths.
EOF
}

if [[ $# -gt 1 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SOURCE_ENV="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/source.env"
DEFAULT_CHECKOUT_DIR="${REPO_ROOT}/.firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo"

# shellcheck source=/dev/null
source "${SOURCE_ENV}"

CHECKOUT_DIR="${1:-${DEFAULT_CHECKOUT_DIR}}"

fetch_pinned_repo() {
  local repo_url="$1"
  local commit="$2"
  local checkout_dir="$3"

  if [[ -e "${checkout_dir}" && ! -d "${checkout_dir}/.git" ]]; then
    echo "Destination exists but is not a git checkout: ${checkout_dir}" >&2
    exit 1
  fi

  if [[ ! -d "${checkout_dir}/.git" ]]; then
    mkdir -p "$(dirname "${checkout_dir}")"
    git clone "${repo_url}" "${checkout_dir}"
  else
    local origin_url
    origin_url="$(git -C "${checkout_dir}" remote get-url origin 2>/dev/null || true)"
    if [[ "${origin_url}" != "${repo_url}" ]]; then
      echo "Destination has unexpected origin: ${checkout_dir}" >&2
      echo "Expected: ${repo_url}" >&2
      echo "Found: ${origin_url:-<none>}" >&2
      exit 1
    fi
  fi

  if ! git -C "${checkout_dir}" cat-file -e "${commit}^{commit}" 2>/dev/null; then
    git -C "${checkout_dir}" fetch --tags origin
  fi
  git -C "${checkout_dir}" checkout --force "${commit}"
  if [[ "${checkout_dir}" == "${CHECKOUT_DIR}" ]]; then
    git -C "${checkout_dir}" clean -fdx -e components >/dev/null
    if [[ -e "${checkout_dir}/managed_components" ]]; then
      git -C "${checkout_dir}" clean -fdx -- managed_components >/dev/null
    fi
  else
    git -C "${checkout_dir}" clean -fdx >/dev/null
  fi
}

apply_patch_if_needed() {
  local checkout_dir="$1"
  local patch_file="$2"

  if git -C "${checkout_dir}" apply --reverse --check "${patch_file}" >/dev/null 2>&1; then
    return
  fi
  if git -C "${checkout_dir}" apply --check "${patch_file}" >/dev/null 2>&1; then
    git -C "${checkout_dir}" apply "${patch_file}"
    return
  fi

  echo "Patch cannot be applied cleanly and is not already applied: ${patch_file}" >&2
  exit 1
}

fetch_component() {
  local repo_url="$1"
  local commit="$2"
  local relative_path="$3"
  local patch_path="${4:-}"
  local with_submodules="${5:-false}"
  local component_dir="${CHECKOUT_DIR}/${relative_path}"

  fetch_pinned_repo "${repo_url}" "${commit}" "${component_dir}"

  if [[ "${with_submodules}" == "true" ]]; then
    git -C "${component_dir}" submodule update --init --recursive
    git -C "${component_dir}" submodule foreach --recursive 'git reset --hard >/dev/null && git clean -fdx >/dev/null' >/dev/null
  fi

  if [[ -n "${patch_path}" ]]; then
    if [[ ! -f "${CHECKOUT_DIR}/${patch_path}" ]]; then
      echo "Missing upstream patch file: ${CHECKOUT_DIR}/${patch_path}" >&2
      exit 1
    fi
    apply_patch_if_needed "${component_dir}" "${CHECKOUT_DIR}/${patch_path}"
  fi
}

remove_unexpected_components() {
  local components_dir="${CHECKOUT_DIR}/components"
  if [[ ! -d "${components_dir}" ]]; then
    return
  fi

  local component_path
  for component_path in "${components_dir}"/*; do
    if [[ ! -e "${component_path}" ]]; then
      continue
    fi
    local component_name
    component_name="$(basename "${component_path}")"
    case "${component_name}" in
      mooncake|mooncake_log|smooth_ui_toolkit|M5GFX|ArduinoJson|lvgl|M5IOE1|M5PM1|BMI270_BMM150_Sensor)
        ;;
      *)
        rm -rf "${component_path}"
        ;;
    esac
  done
}

fetch_pinned_repo "${STOPWATCH_REPOSITORY}" "${STOPWATCH_COMMIT}" "${CHECKOUT_DIR}"
remove_unexpected_components

fetch_component "${STOPWATCH_MOONCAKE_REPOSITORY}" "${STOPWATCH_MOONCAKE_COMMIT}" "components/mooncake"
fetch_component "${STOPWATCH_MOONCAKE_LOG_REPOSITORY}" "${STOPWATCH_MOONCAKE_LOG_COMMIT}" "components/mooncake_log"
fetch_component "${STOPWATCH_SMOOTH_UI_TOOLKIT_REPOSITORY}" "${STOPWATCH_SMOOTH_UI_TOOLKIT_COMMIT}" "components/smooth_ui_toolkit"
fetch_component "${STOPWATCH_M5GFX_REPOSITORY}" "${STOPWATCH_M5GFX_COMMIT}" "components/M5GFX"
fetch_component "${STOPWATCH_ARDUINOJSON_REPOSITORY}" "${STOPWATCH_ARDUINOJSON_COMMIT}" "components/ArduinoJson"
fetch_component "${STOPWATCH_LVGL_REPOSITORY}" "${STOPWATCH_LVGL_COMMIT}" "components/lvgl"
fetch_component "${STOPWATCH_M5IOE1_REPOSITORY}" "${STOPWATCH_M5IOE1_COMMIT}" "components/M5IOE1" "patches/M5IOE1.patch"
fetch_component "${STOPWATCH_M5PM1_REPOSITORY}" "${STOPWATCH_M5PM1_COMMIT}" "components/M5PM1" "patches/M5PM1.patch"
fetch_component "${STOPWATCH_BMI270_REPOSITORY}" "${STOPWATCH_BMI270_COMMIT}" "components/BMI270_BMM150_Sensor" "" "true"

echo "${CHECKOUT_DIR}"
