#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_provisioning_flow.sh

Compiles the StackChan CoreS3 provisioning-flow state machine against host
stubs and verifies setup/import stage transitions, scratch lifetime, panel
loss cleanup, and PIN setup commit readiness. This test uses only a host C++
compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"

for required in \
  "${AGENT_Q_DIR}/agent_q_provisioning_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_provisioning_flow.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-provisioning-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos"

cat >"${TMP_DIR}/stubs/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
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
uint32_t g_last_cancelled_worker_job_id = 0;

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
    const uint8_t entropy[kBip39EntropyBytes], char* output, size_t output_size)
{
    if (entropy == nullptr || output == nullptr || output_size < 96) {
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
    if (word_indices == nullptr || word_count != kBip39MnemonicWordCount) {
        return Bip39EntropyDecodeResult::invalid_word_count;
    }
    if (entropy_out == nullptr || entropy_size != kBip39EntropyBytes) {
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
    *job_id = 1;
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
    g_last_cancelled_worker_job_id = g_last_worker_job_id;
    return true;
}

}  // namespace agent_q
CPP

cat >"${TMP_DIR}/provisioning_flow_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_provisioning_flow.h"

namespace agent_q {
extern bool g_test_worker_accepts_jobs;
extern uint32_t g_last_worker_job_id;
extern uint32_t g_last_cancelled_worker_job_id;
}

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQTimeoutWindow pin_window(TickType_t started_at, TickType_t deadline)
{
    return agent_q::timeout_window_from_deadline(started_at, deadline);
}

void enter_pin(const char* pin, agent_q::AgentQTimeoutWindow input_window)
{
    for (size_t index = 0; pin[index] != '\0'; ++index) {
        expect(agent_q::provisioning_flow_add_pin_digit(pin[index], input_window), "PIN digit accepted");
    }
}

void enter_setup_choice(agent_q::AgentQTimeoutWindow input_window)
{
    expect(agent_q::provisioning_flow_begin_setup_choice(input_window), "setup choice starts");
}

int g_commit_calls = 0;
bool g_commit_root_shape = false;
bool g_commit_prepared_shape = false;

agent_q::AgentQProvisioningFlowCommitResult commit_setup(
    const uint8_t* root_material,
    size_t root_material_size,
    const agent_q::AgentQLocalAuthPreparedRecord* prepared_auth)
{
    ++g_commit_calls;
    g_commit_root_shape =
        root_material != nullptr && root_material_size == agent_q::kBip39EntropyBytes;
    g_commit_prepared_shape = prepared_auth != nullptr;
    return agent_q::AgentQProvisioningFlowCommitResult::ok;
}

}  // namespace

int main()
{
    using Stage = agent_q::AgentQProvisioningFlowStage;
    using Panel = agent_q::AgentQProvisioningFlowPanel;
    using GenerateResult = agent_q::AgentQProvisioningFlowGenerateResult;
    using ImportStartResult = agent_q::AgentQProvisioningFlowImportStartResult;
    using PinSubmitResult = agent_q::AgentQProvisioningFlowPinSubmitResult;
    using ConfirmBackupResult = agent_q::AgentQProvisioningFlowConfirmBackupResult;
    using PanelLifetimeResult = agent_q::AgentQProvisioningFlowPanelLifetimeResult;
    using ReturnToChoiceResult = agent_q::AgentQProvisioningFlowReturnToChoiceResult;
    using ImportNextResult = agent_q::AgentQProvisioningFlowImportNextResult;
    using CommitFinishStatus = agent_q::AgentQProvisioningFlowCommitFinishStatus;

    expect(agent_q::provisioning_flow_begin_generate(1, pin_window(1, 100)) == GenerateResult::stale,
           "generate without setup choice is stale");
    expect(!agent_q::provisioning_flow_active(), "stale generate does not start flow");
    expect(agent_q::provisioning_flow_begin_import_phrase(1, pin_window(1, 100)) == ImportStartResult::stale,
           "import without setup choice is stale");
    expect(!agent_q::provisioning_flow_active(), "stale import does not start flow");

    enter_setup_choice(pin_window(1, 100));
    expect(!agent_q::provisioning_flow_setup_choice_action_allowed(0), "setup choice unavailable before start");
    expect(agent_q::provisioning_flow_setup_choice_action_allowed(50), "setup choice active before deadline");
    expect(!agent_q::provisioning_flow_setup_choice_action_allowed(100), "setup choice expires at deadline");

    enter_setup_choice(pin_window(100, 200));
    expect(agent_q::provisioning_flow_begin_generate(150, agent_q::kAgentQTimeoutWindowNone) ==
               GenerateResult::generation_error,
           "invalid generate target window fails after source gate");
    expect(!agent_q::provisioning_flow_active(),
           "invalid generate target window clears setup choice");

    enter_setup_choice(pin_window(100, 200));
    expect(agent_q::provisioning_flow_begin_import_phrase(150, agent_q::kAgentQTimeoutWindowNone) ==
               ImportStartResult::failed,
           "invalid import target window fails after source gate");
    expect(!agent_q::provisioning_flow_active(),
           "invalid import target window clears setup choice");

    enter_setup_choice(pin_window(100, 200));
    expect(agent_q::provisioning_flow_begin_generate(150, pin_window(150, 250)) == GenerateResult::ok, "generate starts phrase display");
    expect(agent_q::provisioning_flow_stage_is(Stage::backup_phrase_displayed), "phrase stage");
    expect(strcmp(agent_q::provisioning_flow_backup_phrase_prefix_cell(0), "aban") == 0, "prefix cell 1");
    expect(strcmp(agent_q::provisioning_flow_backup_phrase_prefix_cell(11), "acci") == 0, "prefix cell 12");
    expect(agent_q::provisioning_flow_return_to_setup_choice(agent_q::kAgentQTimeoutWindowNone) ==
               ReturnToChoiceResult::failed,
           "invalid back-to-choice fails after cleanup");
    expect(!agent_q::provisioning_flow_active(), "invalid back-to-choice wipes active setup");
    expect(agent_q::provisioning_flow_backup_phrase()[0] == '\0',
           "invalid back-to-choice wipes backup phrase scratch");

    enter_setup_choice(pin_window(100, 200));
    expect(agent_q::provisioning_flow_begin_generate(150, pin_window(150, 250)) == GenerateResult::ok,
           "generate restarts phrase display after cleanup");
    expect(agent_q::provisioning_flow_confirm_backup_phrase(pin_window(200, 300)) ==
               ConfirmBackupResult::started,
           "confirm enters PIN setup");
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_first_entry), "first PIN stage");
    expect(agent_q::provisioning_flow_backup_phrase()[0] == '\0', "phrase text wiped before PIN");

    enter_pin("123456", pin_window(300, 310));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(310, 320), 400, 420) == PinSubmitResult::advanced_to_repeat,
           "first PIN advances to repeat");
    enter_pin("000000", pin_window(320, 330));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(330, 340), 400, 420) == PinSubmitResult::mismatch_restart,
           "mismatch restarts first PIN");
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_first_entry), "mismatch stage");

    enter_pin("123456", pin_window(340, 350));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(350, 360), 450, 480) == PinSubmitResult::advanced_to_repeat,
           "first PIN accepted after mismatch");
    enter_pin("123456", pin_window(360, 370));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(370, 380), 450, 480) == PinSubmitResult::commit_started,
           "matching repeat starts commit");
    expect(agent_q::provisioning_flow_commit_job_active(1), "commit waits for worker result");
    agent_q::AgentQLocalAuthWorkerResult worker_result = {};
    worker_result.job_id = 1;
    worker_result.owner = agent_q::AgentQLocalAuthWorkerOwner::provisioning_setup;
    worker_result.operation = agent_q::AgentQLocalAuthWorkerOperation::prepare_verifier_record;
    worker_result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    const agent_q::AgentQProvisioningFlowCommitFinishResult commit_finish =
        agent_q::provisioning_flow_finish_commit_worker_result(worker_result, commit_setup);
    expect(commit_finish.status == CommitFinishStatus::committed, "commit worker result commits setup");
    expect(g_commit_calls == 1, "commit callback called once");
    expect(g_commit_root_shape, "root input shape");
    expect(g_commit_prepared_shape, "prepared auth input shape");

    enter_setup_choice(pin_window(280, 330));
    expect(agent_q::provisioning_flow_begin_generate(290, pin_window(290, 340)) == GenerateResult::ok,
           "generate before missing commit callback");
    expect(agent_q::provisioning_flow_confirm_backup_phrase(pin_window(340, 350)) ==
               ConfirmBackupResult::started,
           "confirm before missing commit callback");
    enter_pin("123456", pin_window(350, 360));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(360, 370), 380, 420) == PinSubmitResult::advanced_to_repeat,
           "first PIN accepted before missing commit callback");
    enter_pin("123456", pin_window(380, 390));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(390, 400), 410, 420) == PinSubmitResult::commit_started,
           "matching repeat starts commit before missing commit callback");
    expect(agent_q::provisioning_flow_finish_commit_worker_result(worker_result, nullptr).status ==
               CommitFinishStatus::failed,
           "missing commit callback fails closed");
    expect(!agent_q::provisioning_flow_active(),
           "missing commit callback clears provisioning flow");
    expect(g_commit_calls == 1,
           "missing commit callback does not call commit callback");

    agent_q::provisioning_flow_wipe();
    enter_setup_choice(pin_window(390, 450));
    expect(agent_q::provisioning_flow_begin_generate(400, pin_window(400, 500)) == GenerateResult::ok, "generate before worker busy");
    expect(agent_q::provisioning_flow_confirm_backup_phrase(pin_window(500, 510)) ==
               ConfirmBackupResult::started,
           "confirm before worker busy");
    enter_pin("123456", pin_window(510, 520));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(520, 530), 540, 590) == PinSubmitResult::advanced_to_repeat,
           "first PIN accepted before worker busy");
    enter_pin("123456", pin_window(540, 550));
    agent_q::g_test_worker_accepts_jobs = false;
    expect(agent_q::provisioning_flow_submit_pin(pin_window(550, 560), 570, 590) == PinSubmitResult::worker_unavailable,
           "worker failure is not reported as invalid PIN");
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_repeat_entry),
           "worker failure keeps repeat stage for retry");
    agent_q::g_test_worker_accepts_jobs = true;
    agent_q::provisioning_flow_wipe();

    enter_setup_choice(pin_window(490, 550));
    expect(agent_q::provisioning_flow_begin_generate(500, pin_window(500, 600)) == GenerateResult::ok,
           "generate before commit panel loss");
    expect(agent_q::provisioning_flow_confirm_backup_phrase(pin_window(600, 610)) ==
               ConfirmBackupResult::started,
           "confirm before commit panel loss");
    enter_pin("123456", pin_window(610, 620));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(620, 630), 640, 690) == PinSubmitResult::advanced_to_repeat,
           "first PIN accepted before commit panel loss");
    enter_pin("123456", pin_window(640, 650));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(650, 660), 670, 690) == PinSubmitResult::commit_started,
           "matching repeat starts commit before panel loss");
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_committing),
           "panel loss scenario reaches commit stage");
    expect(agent_q::provisioning_flow_handle_panel_deleted(Panel::pin_entry),
           "panel delete wipes setup PIN commit");
    expect(agent_q::g_last_cancelled_worker_job_id == agent_q::g_last_worker_job_id,
           "PIN commit panel delete cancels worker job");
    expect(!agent_q::provisioning_flow_active(),
           "PIN commit panel delete clears provisioning flow");
    const int commit_calls_after_panel_delete = g_commit_calls;
    expect(agent_q::provisioning_flow_finish_commit_worker_result(worker_result, commit_setup).status ==
               CommitFinishStatus::stale,
           "stale PIN commit worker result ignored after panel delete");
    expect(g_commit_calls == commit_calls_after_panel_delete,
           "stale worker result does not commit after panel delete");

    enter_setup_choice(pin_window(590, 650));
    expect(agent_q::provisioning_flow_begin_generate(600, pin_window(600, 700)) == GenerateResult::ok,
           "generate before commit timeout");
    expect(agent_q::provisioning_flow_confirm_backup_phrase(pin_window(700, 710)) ==
               ConfirmBackupResult::started,
           "confirm before commit timeout");
    enter_pin("123456", pin_window(710, 720));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(720, 730), 740, 760) == PinSubmitResult::advanced_to_repeat,
           "first PIN accepted before commit timeout");
    enter_pin("123456", pin_window(740, 750));
    expect(agent_q::provisioning_flow_submit_pin(pin_window(750, 755), 780, 790) == PinSubmitResult::commit_started,
           "matching repeat starts commit before timeout");
    expect(agent_q::provisioning_flow_handle_pin_setup_lifetime(true, 789) ==
               PanelLifetimeResult::unchanged,
           "PIN commit stays active before worker deadline");
    expect(agent_q::provisioning_flow_handle_pin_setup_lifetime(true, 790) ==
               PanelLifetimeResult::clear_panel_preserve_timeout,
           "PIN commit timeout wipes flow");
    expect(agent_q::g_last_cancelled_worker_job_id == agent_q::g_last_worker_job_id,
           "PIN commit timeout cancels worker job");
    expect(!agent_q::provisioning_flow_active(),
           "PIN commit timeout clears provisioning flow");

    enter_setup_choice(pin_window(390, 450));
    expect(agent_q::provisioning_flow_begin_import_phrase(400, pin_window(400, 500)) == ImportStartResult::started,
           "import starts from setup choice");
    expect(agent_q::provisioning_flow_stage_is(Stage::import_word_entry), "import stage");
    expect(!agent_q::provisioning_flow_import_current_page_complete(), "empty page incomplete");
    for (uint16_t word = 0; word < 3; ++word) {
        expect(agent_q::provisioning_flow_import_select_slot(word, pin_window(500, 510)), "slot select");
        expect(agent_q::provisioning_flow_import_add_letter('a', pin_window(510, 520)), "letter entry");
        expect(agent_q::provisioning_flow_import_select_candidate(word, pin_window(520, 530)), "candidate select");
    }
    expect(agent_q::provisioning_flow_import_current_page_complete(), "page complete");
    expect(agent_q::provisioning_flow_handle_import_next(
               pin_window(530, 540),
               pin_window(570, 600)) == ImportNextResult::page_advanced,
           "next page");
    for (uint16_t word = 3; word < 12; ++word) {
        expect(agent_q::provisioning_flow_import_select_slot((word - 3) % 3, pin_window(540, 550)), "slot select later");
        expect(agent_q::provisioning_flow_import_select_candidate(word, pin_window(550, 560)), "candidate select later");
        if ((word + 1) % 3 == 0 && word + 1 < 12) {
            expect(agent_q::provisioning_flow_handle_import_next(
                       pin_window(560, 570),
                       pin_window(570, 600)) == ImportNextResult::page_advanced,
                   "next later page");
        }
    }
    expect(agent_q::provisioning_flow_import_all_words_complete(), "all words complete");
    expect(agent_q::provisioning_flow_handle_import_next(
               pin_window(570, 580),
               pin_window(570, 600)) == ImportNextResult::pin_setup_started,
           "decode imported entropy and enter PIN setup");
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_first_entry), "import enters PIN setup");
    expect(agent_q::provisioning_flow_handle_panel_deleted(Panel::pin_entry), "panel delete wipes setup PIN");
    expect(!agent_q::provisioning_flow_active(), "panel delete clears flow");

    if (failures != 0) {
        return 1;
    }
    puts("Provisioning flow tests passed.");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  -I"${TMP_DIR}/stubs" \
  "${TMP_DIR}/stubs.cpp" \
  "${AGENT_Q_DIR}/agent_q_provisioning_flow.cpp" \
  "${TMP_DIR}/provisioning_flow_test.cpp" \
  -o "${TMP_DIR}/provisioning_flow_test"

"${TMP_DIR}/provisioning_flow_test"
