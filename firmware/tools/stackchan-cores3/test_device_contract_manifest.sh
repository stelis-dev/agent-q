#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_device_contract_manifest.sh

Builds the Core contract manifest and compares it with the Firmware contract
manifest emitted from the Firmware contract source.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"

for required in \
  "${REPO_ROOT}/packages/core/package.json" \
  "${REPO_ROOT}/packages/core/src/device-contract.ts" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-device-contract-manifest.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

CXX_BIN="${CXX:-c++}"

cat >"${TMP_DIR}/firmware_manifest.cpp" <<'CPP'
#include <stdio.h>

#include "protocol/device_contract.h"
#include "protocol/protocol_constants.h"

namespace {

void print_fields(const char* group, const char* const* fields, size_t count)
{
    printf("RESPONSE\t%s", group);
    for (size_t i = 0; i < count; ++i) {
        printf("\t%s", fields[i]);
    }
    printf("\n");
}

}  // namespace

int main()
{
    printf("VERSION\t%d\n", signing::kProtocolVersion);

    size_t count = 0;
    const signing::DeviceMethodRow* methods = signing::device_method_rows(&count);
    for (size_t i = 0; i < count; ++i) {
        const signing::DeviceMethodRow& row = methods[i];
        printf(
            "METHOD\t%s\t%s\t%s\t%s\t%s\t%s\n",
            row.method,
            signing::device_session_rule_name(row.session_rule),
            signing::device_payload_rule_name(row.payload_rule),
            row.payload_schema_owner,
            row.result_schema_owner,
            row.firmware_gate);
    }

    const char* const* fields = signing::device_response_success_fields(&count);
    print_fields("success", fields, count);
    fields = signing::device_response_failure_fields(&count);
    print_fields("failure", fields, count);
    fields = signing::device_response_error_fields(&count);
    print_fields("error", fields, count);

    const signing::DeviceErrorRow* errors = signing::device_error_rows(&count);
    for (size_t i = 0; i < count; ++i) {
        const signing::DeviceErrorRow& row = errors[i];
        printf(
            "ERROR\t%s\t%s\t%s\t%s\n",
            row.code,
            row.retryable ? "true" : "false",
            row.message,
            row.meaning);
    }

    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/firmware_manifest.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  -o "${TMP_DIR}/firmware_manifest"

"${TMP_DIR}/firmware_manifest" >"${TMP_DIR}/firmware.tsv"

npm --workspace @stelis/agent-q-core run build:self >/dev/null

node --input-type=module >"${TMP_DIR}/core.tsv" <<'NODE'
import { createCoreContractManifest } from "./packages/core/dist/device-contract.js";

const manifest = createCoreContractManifest();
console.log(`VERSION\t${manifest.protocolVersion}`);
for (const row of manifest.methods) {
  console.log([
    "METHOD",
    row.method,
    row.sessionRule,
    row.payloadRule,
    row.payloadSchemaOwner,
    row.resultSchemaOwner,
    row.firmwareGate,
  ].join("\t"));
}
for (const [name, fields] of Object.entries(manifest.responseEnvelope)) {
  console.log(["RESPONSE", name, ...fields].join("\t"));
}
for (const row of manifest.errors) {
  console.log([
    "ERROR",
    row.code,
    String(row.retryable),
    row.message,
    row.meaning,
  ].join("\t"));
}
NODE

if ! cmp -s "${TMP_DIR}/firmware.tsv" "${TMP_DIR}/core.tsv"; then
  diff -u "${TMP_DIR}/firmware.tsv" "${TMP_DIR}/core.tsv" >&2 || true
  exit 1
fi

echo "Device contract manifest parity tests passed"
