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
#include "local_transport_noise.cpp"
#include "transport/local_transport_pairing_session.h"

namespace {

struct FakeRuntime {
    bool identity_available = true;
    bool random_available = true;
    bool advertising_start_succeeds = true;
    bool advertising = false;
    bool connected = false;
    int public_identity_reads = 0;
    int secret_identity_reads = 0;
    int identity_writes = 0;
    int identity_erases = 0;
    uint8_t identity_secret[signing::kLocalTransportStaticKeyBytes] = {};
    uint8_t identity_public[signing::kLocalTransportStaticKeyBytes] = {};
    bool inbound_ready = false;
    signing::LocalTransportPairingInboundFrame inbound = {};
    int outbound_count = 0;
    signing::LocalTransportPairingChannel outbound_channel =
        signing::LocalTransportPairingChannel::control;
    size_t outbound_length = 0;
    uint8_t outbound[signing::kLocalTransportMaximumEncryptedFrameBytes] = {};
    int request_count = 0;
    char last_request[128] = {};
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

void fake_tag(
    const uint8_t* key,
    const uint8_t* nonce,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* body,
    size_t body_len,
    uint8_t* tag)
{
    for (size_t index = 0; index < signing::kLocalTransportCryptoTagBytes; ++index) {
        uint8_t value = static_cast<uint8_t>(
            key[index] ^ nonce[index % signing::kLocalTransportCryptoNonceBytes] ^ 0xc3U);
        if (aad_len > 0) {
            value ^= aad[(index * 5U) % aad_len];
        }
        if (body_len > 0) {
            value ^= body[(index * 3U) % body_len];
        }
        tag[index] = value;
    }
}

bool fake_encrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t* tag,
    void*)
{
    if (key == nullptr || nonce == nullptr || tag == nullptr ||
        (aad_len > 0 && aad == nullptr) ||
        (plaintext_len > 0 && (plaintext == nullptr || ciphertext == nullptr))) {
        return false;
    }
    for (size_t index = 0; index < plaintext_len; ++index) {
        const uint8_t aad_byte = aad_len > 0 ? aad[index % aad_len] : 0;
        ciphertext[index] = static_cast<uint8_t>(
            plaintext[index] ^ key[index % signing::kLocalTransportCryptoKeyBytes] ^
            nonce[index % signing::kLocalTransportCryptoNonceBytes] ^ aad_byte);
    }
    fake_tag(key, nonce, aad, aad_len, ciphertext, plaintext_len, tag);
    return true;
}

bool fake_decrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    uint8_t* plaintext,
    void*)
{
    if (key == nullptr || nonce == nullptr || tag == nullptr ||
        (aad_len > 0 && aad == nullptr) ||
        (ciphertext_len > 0 && (ciphertext == nullptr || plaintext == nullptr))) {
        return false;
    }
    uint8_t expected[signing::kLocalTransportCryptoTagBytes] = {};
    fake_tag(key, nonce, aad, aad_len, ciphertext, ciphertext_len, expected);
    if (memcmp(expected, tag, sizeof(expected)) != 0) {
        return false;
    }
    for (size_t index = 0; index < ciphertext_len; ++index) {
        const uint8_t aad_byte = aad_len > 0 ? aad[index % aad_len] : 0;
        plaintext[index] = static_cast<uint8_t>(
            ciphertext[index] ^ key[index % signing::kLocalTransportCryptoKeyBytes] ^
            nonce[index % signing::kLocalTransportCryptoNonceBytes] ^ aad_byte);
    }
    return true;
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

signing::LocalTransportIdentityRecordReadStatus read_public_identity(
    uint8_t* public_key,
    void*)
{
    ++g_runtime.public_identity_reads;
    if (public_key == nullptr) {
        return signing::LocalTransportIdentityRecordReadStatus::error;
    }
    memset(public_key, 0, signing::kLocalTransportStaticKeyBytes);
    if (!g_runtime.identity_available) {
        return signing::LocalTransportIdentityRecordReadStatus::error;
    }
    memcpy(public_key, g_runtime.identity_public, sizeof(g_runtime.identity_public));
    return signing::LocalTransportIdentityRecordReadStatus::found;
}

signing::LocalTransportIdentityRecordReadStatus read_identity_pair(
    uint8_t* secret_key,
    uint8_t* public_key,
    void*)
{
    ++g_runtime.secret_identity_reads;
    if (secret_key == nullptr || public_key == nullptr) {
        return signing::LocalTransportIdentityRecordReadStatus::error;
    }
    memset(secret_key, 0, signing::kLocalTransportStaticKeyBytes);
    memset(public_key, 0, signing::kLocalTransportStaticKeyBytes);
    if (!g_runtime.identity_available) {
        return signing::LocalTransportIdentityRecordReadStatus::error;
    }
    memcpy(secret_key, g_runtime.identity_secret, sizeof(g_runtime.identity_secret));
    memcpy(public_key, g_runtime.identity_public, sizeof(g_runtime.identity_public));
    return signing::LocalTransportIdentityRecordReadStatus::found;
}

bool write_identity_pair(const uint8_t* secret_key, const uint8_t* public_key, void*)
{
    ++g_runtime.identity_writes;
    if (secret_key == nullptr || public_key == nullptr) {
        return false;
    }
    memcpy(g_runtime.identity_secret, secret_key, sizeof(g_runtime.identity_secret));
    memcpy(g_runtime.identity_public, public_key, sizeof(g_runtime.identity_public));
    g_runtime.identity_available = true;
    return true;
}

bool erase_identity_pair(void*)
{
    ++g_runtime.identity_erases;
    memset(g_runtime.identity_secret, 0, sizeof(g_runtime.identity_secret));
    memset(g_runtime.identity_public, 0, sizeof(g_runtime.identity_public));
    g_runtime.identity_available = false;
    return true;
}

const signing::LocalTransportIdentityStoreOps& identity_store_ops()
{
    static const signing::LocalTransportIdentityStoreOps ops{
        signing::LocalTransportIdentityStorageOps{
            read_public_identity,
            read_identity_pair,
            write_identity_pair,
            erase_identity_pair,
            nullptr,
        },
        &crypto_ops(),
    };
    return ops;
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
bool receive(signing::LocalTransportPairingInboundFrame* frame, void*)
{
    if (frame == nullptr || !g_runtime.inbound_ready) {
        return false;
    }
    *frame = g_runtime.inbound;
    g_runtime.inbound_ready = false;
    memset(&g_runtime.inbound, 0, sizeof(g_runtime.inbound));
    return true;
}

bool send_acknowledged(
    signing::LocalTransportPairingChannel channel,
    const uint8_t* payload,
    size_t payload_len,
    void*)
{
    expect(payload != nullptr, "outbound indication has payload");
    expect(payload_len <= sizeof(g_runtime.outbound), "outbound indication is bounded");
    ++g_runtime.outbound_count;
    g_runtime.outbound_channel = channel;
    g_runtime.outbound_length = payload_len;
    memset(g_runtime.outbound, 0, sizeof(g_runtime.outbound));
    memcpy(g_runtime.outbound, payload, payload_len);
    return true;
}

void notify(signing::LocalTransportPairingEvent event, void*)
{
    ++g_runtime.event_count;
    g_runtime.last_event = event;
}

void handle_request_line(
    const char* line,
    const signing::ProtocolTransportRoute& route,
    void*)
{
    expect(line != nullptr, "request handler receives a line");
    expect(route.bound(), "request handler receives the local transport route");
    ++g_runtime.request_count;
    strncpy(g_runtime.last_request, line, sizeof(g_runtime.last_request) - 1);
    constexpr char kResponse[] = "{\"success\":true}";
    expect(route.json_response_write_ops().write_bytes(
               kResponse,
               sizeof(kResponse) - 1,
               route.json_response_write_ops().context),
           "request handler writes a response through the bound route");
}

signing::LocalTransportPairingSessionOps session_ops()
{
    return signing::LocalTransportPairingSessionOps{
        "ble",
        signing::kLocalTransportBleServiceUuidHex,
        signing::kLocalTransportPairingAdvertiseMs / 1000U,
        &identity_store_ops(),
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
    for (size_t index = 0; index < sizeof(g_runtime.identity_secret); ++index) {
        g_runtime.identity_secret[index] = static_cast<uint8_t>(0x20U + index);
        g_runtime.identity_public[index] = g_runtime.identity_secret[index];
    }
    memset(g_request_line, 0xa5, sizeof(g_request_line));
    memset(g_plain_frame, 0xa5, sizeof(g_plain_frame));
    memset(g_response_line, 0xa5, sizeof(g_response_line));
}

void queue_inbound(
    signing::LocalTransportPairingChannel channel,
    const uint8_t* payload,
    size_t payload_len)
{
    expect(!g_runtime.inbound_ready, "only one inbound frame is queued");
    expect(payload != nullptr && payload_len <= sizeof(g_runtime.inbound.payload),
           "queued inbound frame is bounded");
    g_runtime.inbound = {};
    g_runtime.inbound.channel = channel;
    g_runtime.inbound.att_mtu = 509;
    g_runtime.inbound.length = payload_len;
    memcpy(g_runtime.inbound.payload, payload, payload_len);
    g_runtime.inbound_ready = true;
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

void fill_incrementing(uint8_t* output, size_t output_len, uint8_t first)
{
    for (size_t index = 0; index < output_len; ++index) {
        output[index] = static_cast<uint8_t>(first + index);
    }
}

void complete_handshake(
    TickType_t now,
    const signing::LocalTransportPairingSnapshot& open_snapshot,
    signing::LocalTransportNoiseSessionKeys* session_keys)
{
    expect(session_keys != nullptr, "handshake returns session keys");

    uint8_t message1[signing::kLocalTransportNoiseMessage1Bytes] = {};
    fill_incrementing(message1, sizeof(message1), 0x11);
    g_runtime.connected = true;
    queue_inbound(signing::LocalTransportPairingChannel::control, message1, sizeof(message1));
    signing::local_transport_pairing_session_poll(now, session_ops());
    expect(g_runtime.secret_identity_reads == 1,
           "Noise message1 performs the first private identity read");
    expect(g_runtime.outbound_channel == signing::LocalTransportPairingChannel::control,
           "Noise message2 uses the control channel");
    expect(g_runtime.outbound_length == signing::kLocalTransportNoiseMessage2Bytes,
           "Noise message2 has the fixed length");
    uint8_t actual_message2[signing::kLocalTransportNoiseMessage2Bytes] = {};
    memcpy(actual_message2, g_runtime.outbound, sizeof(actual_message2));

    uint8_t prologue[
        signing::kLocalTransportNoisePairingProloguePrefixBytes +
        signing::kLocalTransportOpticalPayloadMaxBytes] = {};
    const size_t payload_len = strlen(open_snapshot.payload);
    const size_t prologue_len =
        signing::kLocalTransportNoisePairingProloguePrefixBytes + payload_len;
    memcpy(
        prologue,
        signing::kLocalTransportNoisePairingProloguePrefix,
        signing::kLocalTransportNoisePairingProloguePrefixBytes);
    memcpy(
        prologue + signing::kLocalTransportNoisePairingProloguePrefixBytes,
        open_snapshot.payload,
        payload_len);

    uint8_t fingerprint[signing::kLocalTransportIdentityFingerprintBytes] = {};
    memset(fingerprint, 0x5a, sizeof(fingerprint));
    signing::LocalTransportNoiseResponderState builder = {};
    uint8_t reproduced_message2[signing::kLocalTransportNoiseMessage2Bytes] = {};
    size_t reproduced_message2_len = 0;
    expect(signing::local_transport_noise_responder_write_message2(
               &builder,
               prologue,
               prologue_len,
               g_runtime.identity_secret,
               g_runtime.identity_public,
               fingerprint,
               message1,
               sizeof(message1),
               reproduced_message2,
               sizeof(reproduced_message2),
               &reproduced_message2_len,
               crypto_ops()) == signing::LocalTransportNoiseStatus::ok,
           "test initiator reproduces the production message2 state");
    expect(reproduced_message2_len == sizeof(reproduced_message2) &&
               memcmp(reproduced_message2, actual_message2, sizeof(actual_message2)) == 0,
           "test initiator and pairing state agree on message2");

    uint8_t gateway_static_secret[signing::kLocalTransportNoiseStaticKeyBytes] = {};
    uint8_t gateway_static_public[signing::kLocalTransportNoiseStaticKeyBytes] = {};
    fill_incrementing(gateway_static_secret, sizeof(gateway_static_secret), 0x70);
    expect(fake_public_key(gateway_static_public, gateway_static_secret, nullptr),
           "gateway static public key is constructed");

    uint8_t message3[signing::kLocalTransportNoiseMessage3Bytes] = {};
    size_t message3_offset = 0;
    size_t written = 0;
    expect(signing::encrypt_and_hash(
               crypto_ops(),
               &builder,
               gateway_static_public,
               sizeof(gateway_static_public),
               message3,
               sizeof(message3),
               &written),
           "test initiator encrypts the gateway static key");
    message3_offset += written;
    uint8_t dh[signing::kLocalTransportCryptoKeyBytes] = {};
    expect(fake_shared_secret(
               dh,
               builder.device_ephemeral_secret,
               gateway_static_public,
               nullptr) &&
               signing::mix_key(crypto_ops(), &builder, dh),
           "test initiator mixes the final Noise key");
    signing::local_transport_wipe_bytes(dh, sizeof(dh));
    uint8_t empty = 0;
    expect(signing::encrypt_and_hash(
               crypto_ops(),
               &builder,
               &empty,
               0,
               message3 + message3_offset,
               sizeof(message3) - message3_offset,
               &written),
           "test initiator writes the final Noise tag");
    message3_offset += written;
    expect(message3_offset == sizeof(message3), "Noise message3 has the fixed length");

    signing::LocalTransportNoiseResponderState verifier = {};
    reproduced_message2_len = 0;
    expect(signing::local_transport_noise_responder_write_message2(
               &verifier,
               prologue,
               prologue_len,
               g_runtime.identity_secret,
               g_runtime.identity_public,
               fingerprint,
               message1,
               sizeof(message1),
               reproduced_message2,
               sizeof(reproduced_message2),
               &reproduced_message2_len,
               crypto_ops()) == signing::LocalTransportNoiseStatus::ok,
           "test verifier recreates the production responder state");
    uint8_t gateway_static_result[signing::kLocalTransportNoiseStaticKeyBytes] = {};
    expect(signing::local_transport_noise_responder_read_message3(
               &verifier,
               message3,
               sizeof(message3),
               gateway_static_result,
               session_keys,
               crypto_ops()) == signing::LocalTransportNoiseStatus::ok,
           "test verifier derives the established session keys");

    queue_inbound(signing::LocalTransportPairingChannel::control, message3, sizeof(message3));
    signing::local_transport_pairing_session_poll(now + 1, session_ops());
    expect(signing::local_transport_pairing_session_established(),
           "Noise message3 establishes the encrypted session");
    const signing::LocalTransportPairingSnapshot ready_snapshot =
        signing::local_transport_pairing_session_snapshot();
    expect(!ready_snapshot.active, "ready state removes the pairing UI state");
    expect(ready_snapshot.payload[0] == '\0', "ready state wipes the optical payload");
    expect(ready_snapshot.fingerprint_hex[0] == '\0',
           "ready state wipes the fingerprint projection");
    expect(ready_snapshot.deadline == 0, "ready state wipes the pairing deadline");
    expect(g_runtime.outbound_channel == signing::LocalTransportPairingChannel::control &&
               g_runtime.outbound_length == 1 &&
               g_runtime.outbound[0] == signing::kLocalTransportHandshakeReadySignal,
           "ready state sends the fixed handshake-ready signal");
}

void exercise_established_request(
    TickType_t now,
    const signing::LocalTransportNoiseSessionKeys& session_keys)
{
    constexpr char kRequest[] = "{\"id\":\"request-1\"}";
    const signing::LocalTransportPlainFrame request_frame{
        signing::kLocalTransportFrameTypeProtocolLineFragment,
        signing::kLocalTransportFrameFlagLast,
        0,
        sizeof(kRequest) - 1,
        reinterpret_cast<const uint8_t*>(kRequest),
        sizeof(kRequest) - 1,
    };
    uint8_t encrypted[signing::kLocalTransportMaximumEncryptedFrameBytes] = {};
    size_t encrypted_len = 0;
    expect(signing::local_transport_encrypt_frame(
               session_keys.gateway_to_device,
               signing::LocalTransportFrameDirection::gateway_to_device,
               0,
               request_frame,
               encrypted,
               sizeof(encrypted),
               &encrypted_len,
               crypto_ops()) == signing::LocalTransportFrameAeadStatus::ok,
           "gateway request is encrypted with the established key");
    queue_inbound(signing::LocalTransportPairingChannel::data, encrypted, encrypted_len);
    signing::local_transport_pairing_session_poll(now, session_ops());
    expect(g_runtime.request_count == 1 && strcmp(g_runtime.last_request, kRequest) == 0,
           "established session dispatches one reassembled request");
    expect(g_runtime.outbound_channel == signing::LocalTransportPairingChannel::data,
           "response uses the encrypted data channel");

    uint8_t plain_bytes[signing::kLocalTransportMaximumPlainFrameBytes] = {};
    signing::LocalTransportPlainFrame response_frame = {};
    expect(signing::local_transport_decrypt_frame(
               session_keys.device_to_gateway,
               signing::LocalTransportFrameDirection::device_to_gateway,
               0,
               g_runtime.outbound,
               g_runtime.outbound_length,
               plain_bytes,
               sizeof(plain_bytes),
               &response_frame,
               crypto_ops()) == signing::LocalTransportFrameAeadStatus::ok,
           "gateway decrypts the response with the established key");
    constexpr char kResponse[] = "{\"success\":true}";
    expect(response_frame.type == signing::kLocalTransportFrameTypeProtocolLineFragment &&
               response_frame.flags == signing::kLocalTransportFrameFlagLast &&
               response_frame.payload_len == sizeof(kResponse) - 1 &&
               memcmp(response_frame.payload, kResponse, sizeof(kResponse) - 1) == 0,
           "established session returns the response through the same process");
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
    expect(strcmp(snapshot.fingerprint_hex, "5a5a5a5a5a5a5a5a") == 0,
           "pairing window projects the advertised fingerprint");
    expect(snapshot.deadline == 120100, "pairing window owns the fixed expiry deadline");
    expect(signing::local_transport_pairing_session_active(), "pairing window is active");
    expect(!signing::local_transport_pairing_session_established(),
           "advertising does not create an encrypted session");
    expect(g_runtime.public_identity_reads == 1,
           "begin reads the public identity projection once");
    expect(g_runtime.secret_identity_reads == 0,
           "begin does not read private identity material before a Noise message");
    const int identity_loads_after_begin = g_runtime.public_identity_reads;
    const signing::LocalTransportPairingSnapshot first_snapshot = snapshot;
    expect(!signing::local_transport_pairing_session_begin(101, session_ops()),
           "begin rejects a second transition while pairing is active");
    snapshot = signing::local_transport_pairing_session_snapshot();
    expect(g_runtime.public_identity_reads == identity_loads_after_begin,
           "rejected begin does not load or rotate identity state");
    expect(strcmp(snapshot.payload, first_snapshot.payload) == 0,
           "rejected begin preserves the active optical payload");
    expect(snapshot.deadline == first_snapshot.deadline,
           "rejected begin preserves the active deadline");

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
    expect(g_runtime.secret_identity_reads == 0,
           "expiry does not read private identity material");
    expect_cleared("expiry clears pairing state");

    reset_runtime();
    expect(signing::local_transport_pairing_session_begin(300, session_ops()),
           "pairing starts before physical cancel");
    signing::local_transport_pairing_session_cancel(session_ops());
    expect(g_runtime.event_count == 0, "physical cancel is silent at the common state boundary");
    expect(g_runtime.secret_identity_reads == 0,
           "physical cancel does not read private identity material");
    expect_cleared("physical cancel clears pairing state");

    reset_runtime();
    expect(signing::local_transport_pairing_session_begin(350, session_ops()),
           "pairing starts before the complete handshake");
    const signing::LocalTransportPairingSnapshot open_snapshot =
        signing::local_transport_pairing_session_snapshot();
    signing::LocalTransportNoiseSessionKeys session_keys = {};
    complete_handshake(351, open_snapshot, &session_keys);
    expect(!signing::local_transport_pairing_session_begin(353, session_ops()),
           "ready session rejects a replacement pairing begin");
    expect(g_runtime.public_identity_reads == 1 &&
               g_runtime.secret_identity_reads == 1,
           "rejected ready-state begin performs no additional identity read");
    exercise_established_request(354, session_keys);
    g_runtime.connected = false;
    signing::local_transport_pairing_session_poll(355, session_ops());
    expect_cleared("carrier loss wipes the established session and scratch");

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
  -I"${COMMON_ROOT}/transport" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/transport/local_transport_pairing_session.cpp" \
  "${COMMON_ROOT}/transport/local_transport_crypto.cpp" \
  "${COMMON_ROOT}/transport/local_transport_frame.cpp" \
  "${COMMON_ROOT}/transport/local_transport_identity_store.cpp" \
  "${COMMON_ROOT}/transport/local_transport_optical_payload.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
