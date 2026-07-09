#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_local_transport_optical_payload.sh

Compiles the current Agent-Q local transport optical payload builder with a
host C++ compiler. This test does not require ESP-IDF and does not depend on
.WORK paths.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_TRANSPORT_DIR="${REPO_ROOT}/firmware/src/common/transport"

for required in \
  "${COMMON_TRANSPORT_DIR}/local_transport_optical_payload.cpp" \
  "${COMMON_TRANSPORT_DIR}/local_transport_optical_payload.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/local-transport-optical.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/local_transport_optical_payload_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "local_transport_optical_payload.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

}  // namespace

int main()
{
    const uint8_t fingerprint[signing::kLocalTransportIdentityFingerprintBytes] = {
        0x00, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd,
    };
    const uint8_t nonce[signing::kLocalTransportPairingNonceBytes] = {
        0x90, 0x81, 0x72, 0x63, 0x54, 0x45, 0x36, 0x27,
    };
    char payload[signing::kLocalTransportOpticalPayloadMaxBytes] = {};
    char fingerprint_hex[signing::kLocalTransportFingerprintHexBytes] = {};
    const signing::LocalTransportOpticalPayloadFields fields = {
        signing::kLocalTransportKindBle,
        signing::kLocalTransportBleServiceUuidHex,
        fingerprint,
        sizeof(fingerprint),
        nonce,
        sizeof(nonce),
        120,
    };

    expect(
        signing::local_transport_build_optical_payload(
            fields,
            payload,
            sizeof(payload),
            fingerprint_hex,
            sizeof(fingerprint_hex)),
        "valid BLE optical payload builds");
    expect(
        strcmp(payload,
               "aqlt:1?k=ble&svc=a6e31d1051a14f7a9b0a0a1c00000001&"
               "idfp=00112233aabbccdd&non=9081726354453627&exp=120") == 0,
        "canonical payload string");
    expect(strcmp(fingerprint_hex, "00112233aabbccdd") == 0, "fingerprint hex");

    signing::LocalTransportParsedOpticalPayload parsed = {};
    expect(
        signing::local_transport_parse_optical_payload(payload, &parsed) ==
            signing::LocalTransportOpticalPayloadStatus::ok,
        "canonical payload parses");
    const uint8_t expected_service_uuid[signing::kLocalTransportBleServiceUuidBytes] = {
        0xa6, 0xe3, 0x1d, 0x10,
        0x51, 0xa1, 0x4f, 0x7a,
        0x9b, 0x0a, 0x0a, 0x1c,
        0x00, 0x00, 0x00, 0x01,
    };
    expect(
        memcmp(parsed.service_uuid, expected_service_uuid, sizeof(expected_service_uuid)) == 0,
        "parsed service uuid");
    expect(
        memcmp(parsed.identity_fingerprint, fingerprint, sizeof(fingerprint)) == 0,
        "parsed identity fingerprint");
    expect(memcmp(parsed.nonce, nonce, sizeof(nonce)) == 0, "parsed nonce");
    expect(parsed.expiry_seconds == 120, "parsed expiry seconds");

    expect(
        signing::local_transport_parse_optical_payload(
            "aqlt:1?k=iroh&svc=a6e31d1051a14f7a9b0a0a1c00000001&"
            "idfp=00112233aabbccdd&non=9081726354453627&exp=120",
            &parsed) == signing::LocalTransportOpticalPayloadStatus::unsupported_transport,
        "unsupported transport rejected");
    expect(
        signing::local_transport_parse_optical_payload(
            "aqlt:1?k=ble&svc=a6e31d1051a14f7a9b0a0a1c00000002&"
            "idfp=00112233aabbccdd&non=9081726354453627&exp=120",
            &parsed) == signing::LocalTransportOpticalPayloadStatus::unsupported_endpoint,
        "unsupported BLE endpoint rejected");
    expect(
        signing::local_transport_parse_optical_payload(
            "aqlt:1?k=ble&svc=a6e31d1051a14f7a9b0a0a1c00000001&"
            "idfp=00112233AABBCCDD&non=9081726354453627&exp=120",
            &parsed) == signing::LocalTransportOpticalPayloadStatus::invalid_hex,
        "non-canonical uppercase hex rejected");
    expect(
        signing::local_transport_parse_optical_payload(
            "aqlt:1?k=ble&svc=a6e31d1051a14f7a9b0a0a1c00000001&"
            "idfp=00112233aabbccdd&non=9081726354453627&exp=0120",
            &parsed) == signing::LocalTransportOpticalPayloadStatus::invalid_expiry,
        "non-canonical expiry rejected");

    char tiny_payload[8] = {};
    char tiny_fingerprint[8] = {};
    expect(
        !signing::local_transport_build_optical_payload(
            fields,
            tiny_payload,
            sizeof(tiny_payload),
            tiny_fingerprint,
            sizeof(tiny_fingerprint)),
        "small output buffers fail closed");
    expect(tiny_payload[0] == '\0', "failed payload cleared");
    expect(tiny_fingerprint[0] == '\0', "failed fingerprint cleared");

    signing::LocalTransportOpticalPayloadFields invalid = fields;
    invalid.nonce_size = sizeof(nonce) - 1;
    expect(
        !signing::local_transport_build_optical_payload(
            invalid,
            payload,
            sizeof(payload),
            fingerprint_hex,
            sizeof(fingerprint_hex)),
        "wrong nonce size rejected");

    return failures == 0 ? 0 : 1;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_TRANSPORT_DIR}" \
  "${COMMON_TRANSPORT_DIR}/local_transport_optical_payload.cpp" \
  "${TMP_DIR}/local_transport_optical_payload_test.cpp" \
  -o "${TMP_DIR}/local_transport_optical_payload_test"

"${TMP_DIR}/local_transport_optical_payload_test"
