#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
CXX_BIN="${CXX:-c++}"

for required in \
  "${RUNTIME_DIR}/usb_line_receiver.cpp" \
  "${RUNTIME_DIR}/usb_line_receiver.h" \
  "${COMMON_ROOT}/protocol/request_line.cpp" \
  "${COMMON_ROOT}/protocol/request_line.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

mkdir -p "${TMP_DIR}/driver" "${TMP_DIR}/freertos"

cat >"${TMP_DIR}/esp_attr.h" <<'H'
#pragma once

#define EXT_RAM_BSS_ATTR
H

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
H

cat >"${TMP_DIR}/driver/usb_serial_jtag.h" <<'H'
#pragma once

#include <stdint.h>

#include "freertos/FreeRTOS.h"

int usb_serial_jtag_read_bytes(uint8_t* buffer, uint32_t length, TickType_t ticks_to_wait);
H

cat >"${TMP_DIR}/usb_line_receiver_test.cpp" <<'CPP'
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include "usb_line_receiver.h"
#include "freertos/FreeRTOS.h"

namespace {

std::vector<uint8_t> g_input;
size_t g_input_offset = 0;
std::vector<std::string> g_lines;
std::vector<std::string> g_errors;

void set_input(const std::string& input)
{
    g_input.assign(input.begin(), input.end());
    g_input_offset = 0;
}

void set_input(const std::vector<uint8_t>& input)
{
    g_input = input;
    g_input_offset = 0;
}

void handle_line(const char* line)
{
    g_lines.emplace_back(line != nullptr ? line : "");
}

void write_error(const char* code)
{
    g_errors.emplace_back(code != nullptr ? code : "");
}

void poll_all()
{
    for (int guard = 0; guard < 200 && g_input_offset < g_input.size(); ++guard) {
        signing::usb_line_receiver_poll(handle_line, write_error);
    }
}

}  // namespace

int usb_serial_jtag_read_bytes(uint8_t* buffer, uint32_t length, TickType_t)
{
    if (buffer == nullptr || length == 0 || g_input_offset >= g_input.size()) {
        return 0;
    }
    const size_t remaining = g_input.size() - g_input_offset;
    const size_t count = remaining < length ? remaining : length;
    memcpy(buffer, g_input.data() + g_input_offset, count);
    g_input_offset += count;
    return static_cast<int>(count);
}

int main()
{
    signing::usb_line_receiver_reset();
    set_input("abc\nxyz\n");
    poll_all();
    assert(g_lines.size() == 2);
    assert(g_lines[0] == "abc");
    assert(g_lines[1] == "xyz");
    assert(g_errors.empty());

    g_lines.clear();
    g_errors.clear();
    signing::usb_line_receiver_reset();
    set_input(std::vector<uint8_t>{'a', '\0', 'b', '\n', 'o', 'k', '\n'});
    poll_all();
    assert(g_errors.size() == 1);
    assert(g_errors[0] == "invalid_request");
    assert(g_lines.size() == 1);
    assert(g_lines[0] == "ok");

    g_lines.clear();
    g_errors.clear();
    signing::usb_line_receiver_reset();
    std::vector<uint8_t> oversized(signing::kRequestLineMaxBytes + 1, 'z');
    oversized.push_back('\n');
    oversized.push_back('h');
    oversized.push_back('i');
    oversized.push_back('\n');
    set_input(oversized);
    poll_all();
    assert(g_errors.size() == 1);
    assert(g_errors[0] == "invalid_request");
    assert(g_lines.size() == 1);
    assert(g_lines[0] == "hi");

    g_lines.clear();
    g_errors.clear();
    signing::usb_line_receiver_reset();
    set_input("partial");
    poll_all();
    signing::usb_line_receiver_reset();
    set_input("\nnext\n");
    poll_all();
    assert(g_errors.empty());
    assert(g_lines.size() == 1);
    assert(g_lines[0] == "next");

    printf("USB line receiver tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/usb_line_receiver_test.cpp" \
  "${RUNTIME_DIR}/usb_line_receiver.cpp" \
  "${COMMON_ROOT}/protocol/request_line.cpp" \
  -o "${TMP_DIR}/usb_line_receiver_test"

"${TMP_DIR}/usb_line_receiver_test"
