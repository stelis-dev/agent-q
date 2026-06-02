#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_provisioning_flow.sh

Compiles the StackChan CoreS3 provisioning-flow state machine against host
stubs and verifies setup/recover stage transitions, scratch lifetime, panel
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

Bip39EntropyRecoveryResult recover_bip39_entropy_12_words(
    const uint16_t word_indices[kBip39MnemonicWordCount],
    size_t word_count,
    uint8_t* entropy_out,
    size_t entropy_size)
{
    if (word_indices == nullptr || word_count != kBip39MnemonicWordCount) {
        return Bip39EntropyRecoveryResult::invalid_word_count;
    }
    if (entropy_out == nullptr || entropy_size != kBip39EntropyBytes) {
        return Bip39EntropyRecoveryResult::invalid_output;
    }
    for (size_t index = 0; index < word_count; ++index) {
        if (word_indices[index] >= sizeof(kWords) / sizeof(kWords[0])) {
            return Bip39EntropyRecoveryResult::invalid_word_index;
        }
    }
    memset(entropy_out, 0x42, entropy_size);
    return Bip39EntropyRecoveryResult::ok;
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

void enter_pin(const char* pin, TickType_t deadline)
{
    for (size_t index = 0; pin[index] != '\0'; ++index) {
        expect(agent_q::provisioning_flow_add_pin_digit(pin[index], deadline), "PIN digit accepted");
    }
}

}  // namespace

int main()
{
    using Stage = agent_q::AgentQProvisioningFlowStage;
    using Panel = agent_q::AgentQProvisioningFlowPanel;
    using GenerateResult = agent_q::AgentQProvisioningFlowGenerateResult;
    using PinSubmitResult = agent_q::AgentQProvisioningFlowPinSubmitResult;

    agent_q::provisioning_flow_begin_setup_choice(100);
    expect(agent_q::provisioning_flow_setup_choice_action_allowed(50), "setup choice active before deadline");
    expect(!agent_q::provisioning_flow_setup_choice_action_allowed(100), "setup choice expires at deadline");

    expect(agent_q::provisioning_flow_begin_generate(200) == GenerateResult::ok, "generate starts phrase display");
    expect(agent_q::provisioning_flow_stage_is(Stage::recovery_phrase_displayed), "phrase stage");
    expect(strcmp(agent_q::provisioning_flow_recovery_phrase_prefix_cell(0), "aban") == 0, "prefix cell 1");
    expect(strcmp(agent_q::provisioning_flow_recovery_phrase_prefix_cell(11), "acci") == 0, "prefix cell 12");
    expect(agent_q::provisioning_flow_begin_pin_setup_from_displayed_phrase(300), "confirm enters PIN setup");
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_first_entry), "first PIN stage");
    expect(agent_q::provisioning_flow_recovery_phrase()[0] == '\0', "phrase text wiped before PIN");

    enter_pin("123456", 310);
    expect(agent_q::provisioning_flow_submit_pin(320, 400, 420) == PinSubmitResult::advanced_to_repeat,
           "first PIN advances to repeat");
    enter_pin("000000", 330);
    expect(agent_q::provisioning_flow_submit_pin(340, 400, 420) == PinSubmitResult::mismatch_restart,
           "mismatch restarts first PIN");
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_first_entry), "mismatch stage");

    enter_pin("123456", 350);
    expect(agent_q::provisioning_flow_submit_pin(360, 450, 480) == PinSubmitResult::advanced_to_repeat,
           "first PIN accepted after mismatch");
    enter_pin("123456", 370);
    expect(agent_q::provisioning_flow_submit_pin(380, 450, 480) == PinSubmitResult::commit_started,
           "matching repeat starts commit");
    expect(agent_q::provisioning_flow_commit_job_active(1), "commit waits for worker result");
    const uint8_t* root = nullptr;
    size_t root_size = 0;
    const agent_q::AgentQLocalAuthPreparedRecord* prepared = nullptr;
    agent_q::AgentQLocalAuthWorkerResult worker_result = {};
    worker_result.job_id = 1;
    worker_result.owner = agent_q::AgentQLocalAuthWorkerOwner::provisioning_setup;
    worker_result.operation = agent_q::AgentQLocalAuthWorkerOperation::prepare_verifier_record;
    worker_result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    expect(agent_q::provisioning_flow_commit_worker_result(
               worker_result,
               &root,
               &root_size,
               &prepared),
           "commit worker result exposes inputs");
    expect(root != nullptr && root_size == agent_q::kBip39EntropyBytes, "root input shape");

    agent_q::provisioning_flow_wipe();
    expect(agent_q::provisioning_flow_begin_generate(500) == GenerateResult::ok, "generate before worker busy");
    expect(agent_q::provisioning_flow_begin_pin_setup_from_displayed_phrase(510), "confirm before worker busy");
    enter_pin("123456", 520);
    expect(agent_q::provisioning_flow_submit_pin(530, 540, 590) == PinSubmitResult::advanced_to_repeat,
           "first PIN accepted before worker busy");
    enter_pin("123456", 550);
    agent_q::g_test_worker_accepts_jobs = false;
    expect(agent_q::provisioning_flow_submit_pin(560, 570, 590) == PinSubmitResult::worker_unavailable,
           "worker failure is not reported as invalid PIN");
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_repeat_entry),
           "worker failure keeps repeat stage for retry");
    agent_q::g_test_worker_accepts_jobs = true;
    expect(prepared != nullptr, "prepared auth input shape");
    agent_q::provisioning_flow_wipe();

    expect(agent_q::provisioning_flow_begin_generate(700) == GenerateResult::ok,
           "generate before commit timeout");
    expect(agent_q::provisioning_flow_begin_pin_setup_from_displayed_phrase(710),
           "confirm before commit timeout");
    enter_pin("123456", 720);
    expect(agent_q::provisioning_flow_submit_pin(730, 740, 760) == PinSubmitResult::advanced_to_repeat,
           "first PIN accepted before commit timeout");
    enter_pin("123456", 750);
    expect(agent_q::provisioning_flow_submit_pin(755, 780, 790) == PinSubmitResult::commit_started,
           "matching repeat starts commit before timeout");
    expect(!agent_q::provisioning_flow_fail_pin_commit_if_expired(789),
           "PIN commit stays active before worker deadline");
    expect(agent_q::provisioning_flow_fail_pin_commit_if_expired(790),
           "PIN commit timeout wipes flow");
    expect(agent_q::g_last_cancelled_worker_job_id == agent_q::g_last_worker_job_id,
           "PIN commit timeout cancels worker job");
    expect(!agent_q::provisioning_flow_active(),
           "PIN commit timeout clears provisioning flow");

    agent_q::provisioning_flow_begin_recover(500);
    expect(agent_q::provisioning_flow_stage_is(Stage::recover_word_entry), "recover stage");
    expect(!agent_q::provisioning_flow_recover_current_page_complete(), "empty page incomplete");
    for (uint16_t word = 0; word < 3; ++word) {
        expect(agent_q::provisioning_flow_recover_select_slot(word, 510), "slot select");
        expect(agent_q::provisioning_flow_recover_add_letter('a', 520), "letter entry");
        expect(agent_q::provisioning_flow_recover_select_candidate(word, 530), "candidate select");
    }
    expect(agent_q::provisioning_flow_recover_current_page_complete(), "page complete");
    expect(agent_q::provisioning_flow_recover_next_page(540), "next page");
    for (uint16_t word = 3; word < 12; ++word) {
        expect(agent_q::provisioning_flow_recover_select_slot((word - 3) % 3, 550), "slot select later");
        expect(agent_q::provisioning_flow_recover_select_candidate(word, 560), "candidate select later");
        if ((word + 1) % 3 == 0 && word + 1 < 12) {
            expect(agent_q::provisioning_flow_recover_next_page(570), "next later page");
        }
    }
    expect(agent_q::provisioning_flow_recover_all_words_complete(), "all words complete");
    expect(agent_q::provisioning_flow_recover_entropy_from_words() ==
               agent_q::Bip39EntropyRecoveryResult::ok,
           "recover entropy");
    agent_q::provisioning_flow_begin_pin_setup_after_recovery(600);
    expect(agent_q::provisioning_flow_stage_is(Stage::pin_first_entry), "recovery enters PIN setup");
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
