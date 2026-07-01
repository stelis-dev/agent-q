#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_provisioning_ui_flow.sh

Compiles the StackChan CoreS3 provisioning UI-flow controller against host
stubs and verifies that device-local setup UI actions route setup-choice,
generate/import, PIN setup, display-failure cleanup, and commit-result behavior
without linking the USB request server.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"

for required in \
  "${AGENT_Q_DIR}/agent_q_provisioning_ui_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_provisioning_ui_flow.h" \
  "${AGENT_Q_DIR}/agent_q_provisioning_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_provisioning_flow.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-provisioning-ui-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos"
mkdir -p "${TMP_DIR}/stubs/lvgl"
mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"

cat >"${TMP_DIR}/stubs/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/stubs/lvgl.h" <<'H'
#pragma once

typedef void (*lv_event_cb_t)(void*);
typedef struct {
    int x1;
    int y1;
    int x2;
    int y2;
} lv_area_t;
typedef struct _lv_obj_t lv_obj_t;
H

cat >"${TMP_DIR}/stubs.cpp" <<'CPP'
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_bip39_wordlist.h"
#include "agent_q_entropy.h"
#include "agent_q_local_auth.h"
#include "agent_q_local_auth_worker.h"

namespace {

const char* const kWords[] = {
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid",
};

}  // namespace

namespace agent_q {

bool g_test_worker_accepts_jobs = true;
uint32_t g_last_worker_job_id = 0;

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool fill_secure_random(void* output, size_t size)
{
    if (output == nullptr) {
        return false;
    }
    uint8_t* bytes = static_cast<uint8_t*>(output);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<uint8_t>(index + 1);
    }
    return true;
}

bool make_bip39_mnemonic_12_words(
    const uint8_t*, char* output, size_t output_size)
{
    if (output == nullptr || output_size < 96) {
        return false;
    }
    snprintf(output, output_size,
             "abandon ability able about above absent absorb abstract absurd abuse access accident");
    return true;
}

const char* bip39_english_word(uint16_t index)
{
    if (index >= sizeof(kWords) / sizeof(kWords[0])) {
        return nullptr;
    }
    return kWords[index];
}

Bip39EntropyDecodeResult decode_bip39_entropy_12_words(
    const uint16_t word_indices[kBip39MnemonicWordCount],
    size_t word_count,
    uint8_t* entropy_out,
    size_t entropy_size)
{
    if (word_indices == nullptr || word_count != kBip39MnemonicWordCount ||
        entropy_out == nullptr || entropy_size != kBip39EntropyBytes) {
        return Bip39EntropyDecodeResult::invalid_output;
    }
    for (size_t index = 0; index < word_count; ++index) {
        if (word_indices[index] >= sizeof(kWords) / sizeof(kWords[0])) {
            return Bip39EntropyDecodeResult::invalid_word_index;
        }
    }
    memset(entropy_out, 0x42, entropy_size);
    return Bip39EntropyDecodeResult::ok;
}

bool is_valid_local_pin(const char* pin)
{
    if (pin == nullptr || strlen(pin) != kLocalPinDigits) {
        return false;
    }
    for (size_t index = 0; index < kLocalPinDigits; ++index) {
        if (!isdigit(static_cast<unsigned char>(pin[index]))) {
            return false;
        }
    }
    return true;
}

bool local_auth_worker_submit_prepare_verifier(
    AgentQLocalAuthWorkerOwner,
    const char* pin,
    uint32_t* job_id)
{
    if (!g_test_worker_accepts_jobs || !is_valid_local_pin(pin) || job_id == nullptr) {
        return false;
    }
    *job_id = 7;
    g_last_worker_job_id = *job_id;
    return true;
}

bool local_auth_worker_submit_verify(
    AgentQLocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    return local_auth_worker_submit_prepare_verifier(owner, pin, job_id);
}

bool local_auth_worker_cancel_job(uint32_t)
{
    return true;
}

}  // namespace agent_q
CPP

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_provisioning_ui_flow.h"
#include "agent_q_provisioning_flow.h"

namespace agent_q {
extern uint32_t g_last_worker_job_id;
}

namespace {

int failures = 0;
TickType_t g_now = 10;
bool g_local_setup_allowed = true;
bool g_setup_app_action_allowed = true;
bool g_panel_active[12] = {};
bool g_draw_setup_choice = true;
bool g_draw_backup = true;
bool g_draw_import = true;
bool g_draw_pin = true;
bool g_draw_pin_processing = true;
int g_clear_overlay_calls = 0;
int g_show_message_calls = 0;
int g_log_info_calls = 0;
int g_log_warn_calls = 0;
int g_commit_calls = 0;
const char* g_last_message = nullptr;
const char* g_last_pin_notice = nullptr;
agent_q::AgentQMessageKind g_last_kind = agent_q::AgentQMessageKind::info;
agent_q::AgentQProvisioningFlowCommitResult g_commit_result =
    agent_q::AgentQProvisioningFlowCommitResult::ok;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_harness()
{
    agent_q::provisioning_flow_wipe();
    g_now = 10;
    g_local_setup_allowed = true;
    g_setup_app_action_allowed = true;
    memset(g_panel_active, 0, sizeof(g_panel_active));
    g_draw_setup_choice = true;
    g_draw_backup = true;
    g_draw_import = true;
    g_draw_pin = true;
    g_draw_pin_processing = true;
    g_clear_overlay_calls = 0;
    g_show_message_calls = 0;
    g_log_info_calls = 0;
    g_log_warn_calls = 0;
    g_commit_calls = 0;
    g_last_message = nullptr;
    g_last_pin_notice = nullptr;
    g_last_kind = agent_q::AgentQMessageKind::info;
    g_commit_result = agent_q::AgentQProvisioningFlowCommitResult::ok;
}

TickType_t now()
{
    return g_now;
}

bool local_setup_allowed()
{
    return g_local_setup_allowed;
}

bool setup_app_action_allowed()
{
    return g_setup_app_action_allowed;
}

bool panel_active(agent_q::AgentQUiPanelKind kind)
{
    return g_panel_active[static_cast<int>(kind)];
}

bool clear_panel(agent_q::AgentQUiPanelKind kind, agent_q::SensitiveUiClearPolicy)
{
    g_panel_active[static_cast<int>(kind)] = false;
    return true;
}

bool draw_setup_choice()
{
    g_panel_active[static_cast<int>(agent_q::AgentQUiPanelKind::setup_choice)] = g_draw_setup_choice;
    return g_draw_setup_choice;
}

bool draw_backup(const char* phrase)
{
    expect(phrase != nullptr && phrase[0] != '\0', "backup phrase passed to display");
    g_panel_active[static_cast<int>(agent_q::AgentQUiPanelKind::backup_phrase_display)] = g_draw_backup;
    return g_draw_backup;
}

bool draw_import(const char*)
{
    g_panel_active[static_cast<int>(agent_q::AgentQUiPanelKind::import_word_entry)] = g_draw_import;
    return g_draw_import;
}

bool draw_pin(const char* notice)
{
    g_last_pin_notice = notice;
    g_panel_active[static_cast<int>(agent_q::AgentQUiPanelKind::pin_entry)] = g_draw_pin;
    return g_draw_pin;
}

bool draw_pin_processing()
{
    g_panel_active[static_cast<int>(agent_q::AgentQUiPanelKind::pin_entry)] = g_draw_pin_processing;
    return g_draw_pin_processing;
}

void clear_overlay()
{
    g_clear_overlay_calls += 1;
}

void show_message(const char* message, agent_q::AgentQMessageKind kind)
{
    g_show_message_calls += 1;
    g_last_message = message;
    g_last_kind = kind;
}

agent_q::AgentQProvisioningFlowCommitResult commit_setup(
    const uint8_t* root_material,
    size_t root_material_size,
    const agent_q::AgentQLocalAuthPreparedRecord* prepared_auth)
{
    g_commit_calls += 1;
    expect(root_material != nullptr, "commit has root material");
    expect(root_material_size == agent_q::kBip39EntropyBytes, "commit root material size");
    expect(prepared_auth != nullptr, "commit has prepared auth");
    return g_commit_result;
}

void log_info(const char*)
{
    g_log_info_calls += 1;
}

void log_warn(const char*)
{
    g_log_warn_calls += 1;
}

const agent_q::AgentQProvisioningUiFlowOps& ops()
{
    static const agent_q::AgentQProvisioningUiFlowOps value = {
        now,
        local_setup_allowed,
        setup_app_action_allowed,
        panel_active,
        clear_panel,
        draw_setup_choice,
        draw_backup,
        draw_import,
        draw_pin,
        draw_pin_processing,
        clear_overlay,
        show_message,
        commit_setup,
        log_info,
        log_warn,
        100,
        100,
        100,
        5,
        20,
    };
    return value;
}

void enter_pin(const char* pin)
{
    for (size_t index = 0; pin[index] != '\0'; ++index) {
        agent_q::provisioning_ui_handle_pin_digit(pin[index], ops());
    }
}

void complete_generated_setup_with_commit_result(
    agent_q::AgentQProvisioningFlowCommitResult commit_result,
    const char* expected_message,
    agent_q::AgentQMessageKind expected_kind,
    const char* label)
{
    reset_harness();
    agent_q::provisioning_ui_show_setup_choice_from_touch(ops());
    agent_q::provisioning_ui_start_generate_from_setup_choice(ops());
    agent_q::provisioning_ui_confirm_backup_phrase(ops());
    enter_pin("123456");
    agent_q::provisioning_ui_handle_pin_submit(ops());
    enter_pin("123456");
    agent_q::provisioning_ui_handle_pin_submit(ops());
    expect(agent_q::provisioning_flow_stage_is(
               agent_q::AgentQProvisioningFlowStage::pin_committing),
           "matching PIN starts commit before result");
    expect(agent_q::g_last_worker_job_id == 7, "worker job submitted before result");

    agent_q::AgentQLocalAuthWorkerResult result = {};
    result.owner = agent_q::AgentQLocalAuthWorkerOwner::provisioning_setup;
    result.operation = agent_q::AgentQLocalAuthWorkerOperation::prepare_verifier_record;
    result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    result.job_id = agent_q::g_last_worker_job_id;
    memset(result.prepared_record.bytes, 0x42, sizeof(result.prepared_record.bytes));

    g_commit_result = commit_result;
    agent_q::provisioning_ui_handle_setup_auth_worker_result(result, ops());
    expect(g_commit_calls == 1, "commit called once");
    expect(!agent_q::provisioning_flow_active(), "commit result clears flow");
    expect(g_last_kind == expected_kind && strcmp(g_last_message, expected_message) == 0,
           label);
}

}  // namespace

int main()
{
    using Stage = agent_q::AgentQProvisioningFlowStage;
    using Kind = agent_q::AgentQMessageKind;
    using Commit = agent_q::AgentQProvisioningFlowCommitResult;

    reset_harness();
    g_local_setup_allowed = false;
    agent_q::provisioning_ui_show_setup_choice_from_touch(ops());
    expect(g_clear_overlay_calls == 1, "unavailable setup clears overlay");
    expect(g_show_message_calls == 1 && strcmp(g_last_message, "Setup unavailable") == 0,
           "unavailable setup reports error");
    expect(!agent_q::provisioning_flow_active(), "unavailable setup does not start flow");

    reset_harness();
    g_draw_setup_choice = false;
    agent_q::provisioning_ui_show_setup_choice_from_touch(ops());
    expect(!agent_q::provisioning_flow_active(), "setup choice display failure wipes flow");
    expect(strcmp(g_last_message, "Display error") == 0, "setup choice display failure reports display error");

    reset_harness();
    agent_q::provisioning_ui_start_generate_from_setup_choice(ops());
    expect(!agent_q::provisioning_flow_active(), "stale generate UI action does not start flow");
    expect(!g_panel_active[static_cast<int>(agent_q::AgentQUiPanelKind::backup_phrase_display)],
           "stale generate UI action does not draw backup phrase");
    agent_q::provisioning_ui_start_import_from_setup_choice(ops());
    expect(!agent_q::provisioning_flow_active(), "stale import UI action does not start flow");
    expect(!g_panel_active[static_cast<int>(agent_q::AgentQUiPanelKind::import_word_entry)],
           "stale import UI action does not draw import panel");

    reset_harness();
    agent_q::provisioning_ui_show_setup_choice_from_touch(ops());
    agent_q::provisioning_ui_start_generate_from_setup_choice(ops());
    expect(agent_q::provisioning_flow_stage_is(Stage::backup_phrase_displayed),
           "generate enters backup phrase display");
    agent_q::provisioning_ui_return_to_setup_choice(ops());
    expect(agent_q::provisioning_flow_stage_is(Stage::setup_choice),
           "back-to-choice returns to setup choice");

    reset_harness();
    agent_q::provisioning_ui_show_setup_choice_from_touch(ops());
    agent_q::provisioning_ui_start_generate_from_setup_choice(ops());
    g_draw_pin = true;
    agent_q::provisioning_ui_confirm_backup_phrase(ops());
    enter_pin("123456");
    agent_q::provisioning_ui_handle_pin_submit(ops());
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_repeat_entry),
           "first PIN submit advances to repeat");
    enter_pin("654321");
    agent_q::provisioning_ui_handle_pin_submit(ops());
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_first_entry),
           "mismatched PIN returns to first entry");
    expect(g_last_pin_notice != nullptr && strcmp(g_last_pin_notice, "PINs did not match.") == 0,
           "mismatched PIN redraw message");

    complete_generated_setup_with_commit_result(
        Commit::ok,
        "Provisioned",
        Kind::success,
        "successful commit message");
    complete_generated_setup_with_commit_result(
        Commit::missing_input,
        "Setup unavailable",
        Kind::error,
        "missing input commit message");
    complete_generated_setup_with_commit_result(
        Commit::storage_error,
        "Storage error",
        Kind::error,
        "storage failure commit message");

    reset_harness();
    agent_q::provisioning_ui_show_setup_choice_from_touch(ops());
    agent_q::provisioning_ui_start_import_from_setup_choice(ops());
    g_draw_import = false;
    agent_q::provisioning_ui_handle_import_letter('a', ops());
    expect(!agent_q::provisioning_flow_active(), "import redraw failure wipes flow");
    expect(g_last_kind == Kind::error && strcmp(g_last_message, "Display error") == 0,
           "import redraw failure reports display error");

    if (failures != 0) {
        return 1;
    }
    printf("Provisioning UI flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}/stubs/lvgl" \
  -I"${TMP_DIR}" \
  -I"${REPO_ROOT}/firmware/src/common" \
  -I"${COMMON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/stubs.cpp" \
  "${AGENT_Q_DIR}/agent_q_provisioning_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_provisioning_ui_flow.cpp" \
  "${TMP_DIR}/test.cpp" \
  -o "${TMP_DIR}/provisioning_ui_flow_test"

"${TMP_DIR}/provisioning_ui_flow_test"
