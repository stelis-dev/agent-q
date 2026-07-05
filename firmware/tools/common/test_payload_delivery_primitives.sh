#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_payload_delivery_primitives.sh

Compiles shared payload delivery transport primitives with a host C++ compiler.
This test does not require ESP-IDF and does not depend on .WORK paths.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_TRANSPORT_DIR="${COMMON_ROOT}/transport"

for required in \
  "${COMMON_TRANSPORT_DIR}/payload_delivery_primitives.cpp" \
  "${COMMON_TRANSPORT_DIR}/payload_delivery_primitives.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-payload-delivery-primitives.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/payload_delivery_primitives_test.cpp" <<'CPP'
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "transport/payload_delivery_primitives.h"

int main()
{
    using namespace signing;

    static_assert(kPayloadDeliveryDigestSize == 72, "payload digest size");
    static_assert(kPayloadDeliveryTransferIdSize == 82, "transfer id size");
    static_assert(kPayloadDeliveryPayloadRefSize == 81, "payload ref size");
    static_assert(kPayloadDeliveryDefaultMaxBytes == 128 * 1024, "payload max bytes");
    static_assert(kPayloadDeliveryDefaultChunkMaxBytes == 2700, "chunk max bytes");

    char transfer_id[kPayloadDeliveryTransferIdSize] = {};
    char payload_ref[kPayloadDeliveryPayloadRefSize] = {};
    assert(payload_delivery_format_transfer_id(1, transfer_id, sizeof(transfer_id)));
    assert(strcmp(transfer_id, "transfer_0000000000000001") == 0);
    assert(payload_delivery_format_payload_ref(0x2a, payload_ref, sizeof(payload_ref)));
    assert(strcmp(payload_ref, "payload_000000000000002a") == 0);

    assert(payload_delivery_transfer_id_format_valid("transfer_0000000000000001"));
    assert(payload_delivery_transfer_id_format_valid("transfer_short"));
    assert(!payload_delivery_transfer_id_format_valid("transfer_"));
    assert(!payload_delivery_transfer_id_format_valid("payload_0000000000000001"));
    assert(!payload_delivery_transfer_id_format_valid("transfer_bad/slash"));
    assert(!payload_delivery_format_transfer_id(1, transfer_id, strlen("transfer_0000000000000001")));

    assert(payload_delivery_payload_ref_format_valid("payload_000000000000002a"));
    assert(payload_delivery_payload_ref_format_valid("payload_short"));
    assert(!payload_delivery_payload_ref_format_valid("payload_"));
    assert(!payload_delivery_payload_ref_format_valid("transfer_000000000000002a"));
    assert(!payload_delivery_payload_ref_format_valid("payload_bad/slash"));
    assert(!payload_delivery_format_payload_ref(1, payload_ref, strlen("payload_0000000000000001")));

    const char* valid_digest =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert(payload_delivery_payload_digest_format_valid(valid_digest));
    assert(!payload_delivery_payload_digest_format_valid("sha256:0123"));
    assert(!payload_delivery_payload_digest_format_valid(
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"));
    assert(!payload_delivery_payload_digest_format_valid(
        "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

    assert(payload_delivery_timeout_window_ms_for_size(0) == kPayloadDeliveryBaseWindowMs);
    assert(payload_delivery_timeout_window_ms_for_size(1) == 31000);
    assert(payload_delivery_timeout_window_ms_for_size(kPayloadDeliveryDefaultChunkMaxBytes) == 31000);
    assert(payload_delivery_timeout_window_ms_for_size(kPayloadDeliveryDefaultChunkMaxBytes + 1) == 32000);
    assert(payload_delivery_timeout_window_ms_for_size(static_cast<size_t>(1024) * 1024 * 1024) ==
           kPayloadDeliveryMaxWindowMs);

    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/payload_delivery_primitives_test.cpp" \
  "${COMMON_TRANSPORT_DIR}/payload_delivery_primitives.cpp" \
  -o "${TMP_DIR}/payload_delivery_primitives_test"

"${TMP_DIR}/payload_delivery_primitives_test"
echo "Common payload delivery primitive tests passed"
