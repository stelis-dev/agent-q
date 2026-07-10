#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src}"
CXX_BIN="${CXX:-c++}"

if [[ ! -f "${ARDUINOJSON_ROOT}/ArduinoJson.h" ]]; then
  echo "Missing ArduinoJson source: ${ARDUINOJSON_ROOT}/ArduinoJson.h" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/local-transport-pairing-state.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/freertos"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (static_cast<TickType_t>(ms))
#define pdTICKS_TO_MS(ticks) (static_cast<uint32_t>(ticks))
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "protocol/device_response.h"
#include "transport/local_transport_pairing_session.h"

namespace {

struct FakeRuntime {
    bool identity_available = true;
    bool random_available = true;
    bool advertising_start_succeeds = true;
    bool advertising = false;
    bool connected = false;
    int identity_loads = 0;
    int secret_loads = 0;
    int stop_calls = 0;
    int disconnect_calls = 0;
    int poll_calls = 0;
    int event_count = 0;
    signing::LocalTransportPairingEvent last_event =
        signing::LocalTransportPairingEvent::unavailable;
};

FakeRuntime g_runtime;
uint8_t g_request_line[signing::kLocalTransportGatewayRequestLineCapBytes + 1];
uint8_t g_plain_frame[signing::kLocalTransportMaximumPlainFrameBytes];
char g_response_line[signing::kLocalTransportFirmwareResponseLineCapBytes + 1];

void expect(bool condition, const char* message)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", message);
        _Exit(1);
    }
}

bool fake_random(uint8_t* output, size_t output_len, void* context)
{
    auto* runtime = static_cast<FakeRuntime*>(context);
    if (!runtime->random_available || output == nullptr) {
        return false;
    }
    for (size_t index = 0; index < output_len; ++index) {
        output[index] = static_cast<uint8_t>(0x40U + index);
    }
    return true;
}

bool fake_public_key(uint8_t* output, const uint8_t* secret, void*)
{
    if (output == nullptr || secret == nullptr) {
        return false;
    }
    memcpy(output, secret, signing::kLocalTransportCryptoKeyBytes);
    return true;
}

bool fake_shared_secret(uint8_t* output, const uint8_t* secret, const uint8_t* public_key, void*)
{
    if (output == nullptr || secret == nullptr || public_key == nullptr) {
        return false;
    }
    for (size_t index = 0; index < signing::kLocalTransportCryptoKeyBytes; ++index) {
        output[index] = static_cast<uint8_t>(secret[index] ^ public_key[index]);
    }
    return true;
}

bool fake_hash(
    const signing::LocalTransportCryptoBuffer*,
    size_t,
    uint8_t* output,
    void*)
{
    if (output == nullptr) {
        return false;
    }
    memset(output, 0x5a, signing::kLocalTransportCryptoHashBytes);
    return true;
}

bool fake_hmac(
    const uint8_t*,
    size_t,
    const signing::LocalTransportCryptoBuffer*,
    size_t,
    uint8_t* output,
    void*)
{
    return fake_hash(nullptr, 0, output, nullptr);
}

bool fake_encrypt(
    const uint8_t*,
    const uint8_t*,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t,
    uint8_t*,
    uint8_t*,
    void*)
{
    return false;
}

bool fake_decrypt(
    const uint8_t*,
    const uint8_t*,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t,
    const uint8_t*,
    uint8_t*,
    void*)
{
    return false;
}

const signing::LocalTransportCryptoOps& crypto_ops()
{
    static const signing::LocalTransportCryptoOps ops{
        fake_random,
        fake_public_key,
        fake_shared_secret,
        fake_hash,
        fake_hmac,
        fake_encrypt,
        fake_decrypt,
        &g_runtime,
    };
    return ops;
}

bool load_identity(signing::LocalTransportPairingIdentity* identity, void*)
{
    ++g_runtime.identity_loads;
    if (!g_runtime.identity_available || identity == nullptr) {
        return false;
    }
    memset(identity, 0, sizeof(*identity));
    for (size_t index = 0; index < sizeof(identity->public_key); ++index) {
        identity->public_key[index] = static_cast<uint8_t>(0x20U + index);
    }
    for (size_t index = 0; index < sizeof(identity->fingerprint); ++index) {
        identity->fingerprint[index] = static_cast<uint8_t>(index + 1U);
    }
    return true;
}

bool load_secret(signing::LocalTransportPairingIdentitySecret* identity, void*)
{
    ++g_runtime.secret_loads;
    return identity != nullptr;
}

bool start_advertising(const uint8_t* fingerprint, void*)
{
    expect(fingerprint != nullptr, "advertising receives the identity fingerprint");
    if (!g_runtime.advertising_start_succeeds) {
        return false;
    }
    g_runtime.advertising = true;
    return true;
}

void stop_advertising(void*)
{
    ++g_runtime.stop_calls;
    g_runtime.advertising = false;
}

void poll_carrier(void*)
{
    ++g_runtime.poll_calls;
}

bool advertising_active(void*) { return g_runtime.advertising; }
bool connected(void*) { return g_runtime.connected; }

void disconnect(void*)
{
    ++g_runtime.disconnect_calls;
    g_runtime.connected = false;
}

uint16_t current_att_mtu(void*) { return 509; }
bool receive(signing::LocalTransportPairingInboundFrame*, void*) { return false; }

bool send_acknowledged(
    signing::LocalTransportPairingChannel,
    const uint8_t*,
    size_t,
    void*)
{
    return true;
}

void notify(signing::LocalTransportPairingEvent event, void*)
{
    ++g_runtime.event_count;
    g_runtime.last_event = event;
}

void handle_request_line(
    const char*,
    const signing::ProtocolTransportRoute&,
    void*)
{
}

signing::LocalTransportPairingSessionOps session_ops()
{
    return signing::LocalTransportPairingSessionOps{
        "ble",
        signing::kLocalTransportBleServiceUuidHex,
        signing::kLocalTransportPairingAdvertiseMs / 1000U,
        load_identity,
        load_secret,
        start_advertising,
        stop_advertising,
        poll_carrier,
        advertising_active,
        connected,
        disconnect,
        current_att_mtu,
        receive,
        send_acknowledged,
        notify,
        handle_request_line,
        &crypto_ops(),
        signing::LocalTransportPairingScratchBuffers{
            g_request_line,
            sizeof(g_request_line),
            g_plain_frame,
            sizeof(g_plain_frame),
            g_response_line,
            sizeof(g_response_line),
        },
        nullptr,
    };
}

void reset_runtime()
{
    signing::local_transport_pairing_session_cancel(session_ops());
    g_runtime = {};
    memset(g_request_line, 0xa5, sizeof(g_request_line));
    memset(g_plain_frame, 0xa5, sizeof(g_plain_frame));
    memset(g_response_line, 0xa5, sizeof(g_response_line));
}

bool all_zero(const uint8_t* bytes, size_t length)
{
    for (size_t index = 0; index < length; ++index) {
        if (bytes[index] != 0) {
            return false;
        }
    }
    return true;
}

void expect_cleared(const char* message)
{
    const signing::LocalTransportPairingSnapshot snapshot =
        signing::local_transport_pairing_session_snapshot();
    expect(!snapshot.active, message);
    expect(snapshot.payload[0] == '\0', "cleared state removes the optical payload");
    expect(snapshot.fingerprint_hex[0] == '\0', "cleared state removes the fingerprint projection");
    expect(snapshot.deadline == 0, "cleared state removes the deadline");
    expect(!signing::local_transport_pairing_session_active(), "cleared state is not active");
    expect(!signing::local_transport_pairing_session_established(), "cleared state is not established");
    expect(all_zero(g_request_line, sizeof(g_request_line)), "cleared state wipes request scratch");
    expect(all_zero(g_plain_frame, sizeof(g_plain_frame)), "cleared state wipes frame scratch");
    expect(all_zero(reinterpret_cast<uint8_t*>(g_response_line), sizeof(g_response_line)),
           "cleared state wipes response scratch");
}

}  // namespace

namespace signing {

bool device_response_prepare_success_result(JsonDocument&, const char*, const char*, JsonObjectConst)
{
    return false;
}

bool device_response_prepare_transport_success_result(JsonDocument&, const char*, JsonObjectConst)
{
    return false;
}

bool device_response_prepare_method_error(JsonDocument&, const char*, const char*, const char*)
{
    return false;
}

}  // namespace signing

int main()
{
    reset_runtime();
    expect(signing::local_transport_pairing_session_begin(100, session_ops()),
           "begin enters the pairing window");
    signing::LocalTransportPairingSnapshot snapshot =
        signing::local_transport_pairing_session_snapshot();
    expect(snapshot.active, "pairing window projects active");
    expect(snapshot.payload[0] != '\0', "pairing window projects an optical payload");
    expect(strcmp(snapshot.fingerprint_hex, "0102030405060708") == 0,
           "pairing window projects the advertised fingerprint");
    expect(snapshot.deadline == 120100, "pairing window owns the fixed expiry deadline");
    expect(signing::local_transport_pairing_session_active(), "pairing window is active");
    expect(!signing::local_transport_pairing_session_established(),
           "advertising does not create an encrypted session");
    expect(g_runtime.secret_loads == 0,
           "begin does not read private identity material before a Noise message");

    signing::local_transport_pairing_session_handle_display_loss(session_ops());
    expect(g_runtime.last_event == signing::LocalTransportPairingEvent::display_failed,
           "display loss is an explicit pairing-state event");
    expect_cleared("display loss clears pairing state");

    reset_runtime();
    expect(signing::local_transport_pairing_session_begin(200, session_ops()),
           "pairing restarts after display loss");
    snapshot = signing::local_transport_pairing_session_snapshot();
    signing::local_transport_pairing_session_poll(snapshot.deadline, session_ops());
    expect(g_runtime.last_event == signing::LocalTransportPairingEvent::expired,
           "deadline transition emits expired");
    expect(g_runtime.secret_loads == 0,
           "expiry does not read private identity material");
    expect_cleared("expiry clears pairing state");

    reset_runtime();
    expect(signing::local_transport_pairing_session_begin(300, session_ops()),
           "pairing starts before physical cancel");
    signing::local_transport_pairing_session_cancel(session_ops());
    expect(g_runtime.event_count == 0, "physical cancel is silent at the common state boundary");
    expect(g_runtime.secret_loads == 0,
           "physical cancel does not read private identity material");
    expect_cleared("physical cancel clears pairing state");

    reset_runtime();
    g_runtime.advertising_start_succeeds = false;
    expect(!signing::local_transport_pairing_session_begin(400, session_ops()),
           "advertising failure rejects begin");
    expect(g_runtime.last_event == signing::LocalTransportPairingEvent::unavailable,
           "advertising failure emits unavailable");
    expect_cleared("advertising failure leaves no pairing state");

    reset_runtime();
    g_runtime.identity_available = false;
    expect(!signing::local_transport_pairing_session_begin(500, session_ops()),
           "identity failure rejects begin");
    expect(g_runtime.last_event == signing::LocalTransportPairingEvent::unavailable,
           "identity failure emits unavailable");
    expect_cleared("identity failure leaves no pairing state");

    printf("Local transport pairing state tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/transport/local_transport_pairing_session.cpp" \
  "${COMMON_ROOT}/transport/local_transport_crypto.cpp" \
  "${COMMON_ROOT}/transport/local_transport_frame.cpp" \
  "${COMMON_ROOT}/transport/local_transport_noise.cpp" \
  "${COMMON_ROOT}/transport/local_transport_optical_payload.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
