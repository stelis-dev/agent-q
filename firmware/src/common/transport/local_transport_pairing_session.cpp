#include "transport/local_transport_pairing_session.h"

#include <ArduinoJson.h>
#include <string.h>

#include "protocol/device_response.h"
#include "transport/local_transport_noise.h"

namespace signing {
namespace {

enum class PairingStage {
    idle,
    advertising_pending,
    advertised,
    challenge_pending,
    established,
};

struct LocalTransportPairingState {
    PairingStage stage = PairingStage::idle;
    char payload[kLocalTransportOpticalPayloadMaxBytes] = {};
    char fingerprint_hex[kLocalTransportFingerprintHexBytes] = {};
    uint8_t nonce[kLocalTransportPairingNonceBytes] = {};
    TickType_t deadline = 0;
    LocalTransportPairingIdentitySecret identity = {};
    LocalTransportNoiseResponderState noise = {};
    LocalTransportNoiseSessionKeys pending_keys = {};
    LocalTransportNoiseSessionKeys session_keys = {};
    uint8_t pending_gateway_static_public[kLocalTransportStaticKeyBytes] = {};
    uint64_t rx_counter = 0;
    uint64_t tx_counter = 0;
    LocalTransportReassemblyState reassembly = {};

    void clear()
    {
        stage = PairingStage::idle;
        memset(payload, 0, sizeof(payload));
        memset(fingerprint_hex, 0, sizeof(fingerprint_hex));
        local_transport_wipe_bytes(nonce, sizeof(nonce));
        deadline = 0;
        local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(&identity), sizeof(identity));
        local_transport_noise_clear_responder_state(&noise);
        local_transport_noise_clear_session_keys(&pending_keys);
        local_transport_noise_clear_session_keys(&session_keys);
        local_transport_wipe_bytes(
            pending_gateway_static_public,
            sizeof(pending_gateway_static_public));
        rx_counter = 0;
        tx_counter = 0;
        local_transport_reassembly_reset(&reassembly);
    }
};

LocalTransportPairingState g_pairing;

bool scratch_valid(const LocalTransportPairingScratchBuffers& scratch)
{
    return scratch.request_line != nullptr &&
           scratch.request_line_size >= kLocalTransportGatewayRequestLineCapBytes + 1 &&
           scratch.plain_frame != nullptr &&
           scratch.plain_frame_size >= kLocalTransportMaximumPlainFrameBytes &&
           scratch.response_line != nullptr &&
           scratch.response_line_size >= kLocalTransportFirmwareResponseLineCapBytes + 1;
}

void wipe_transport_buffers(const LocalTransportPairingSessionOps& ops)
{
    if (scratch_valid(ops.scratch)) {
        local_transport_wipe_bytes(ops.scratch.request_line, ops.scratch.request_line_size);
        local_transport_wipe_bytes(ops.scratch.plain_frame, ops.scratch.plain_frame_size);
        local_transport_wipe_bytes(
            reinterpret_cast<uint8_t*>(ops.scratch.response_line),
            ops.scratch.response_line_size);
    }
}

bool ops_valid(const LocalTransportPairingSessionOps& ops)
{
    return ops.load_or_create_identity_secret != nullptr &&
           ops.store_paired_peer != nullptr &&
           ops.start_advertising != nullptr &&
           ops.stop_advertising != nullptr &&
           ops.advertising_active != nullptr &&
           ops.connected != nullptr &&
           ops.current_att_mtu != nullptr &&
           ops.receive != nullptr &&
           ops.send != nullptr &&
           ops.draw_pairing_panel != nullptr &&
           ops.notify != nullptr &&
           ops.handle_request_line != nullptr &&
           ops.transport_kind != nullptr &&
           ops.endpoint_descriptor_hex != nullptr &&
           ops.optical_payload_exp_seconds > 0 &&
           ops.crypto_ops != nullptr &&
           local_transport_crypto_ops_valid(*ops.crypto_ops) &&
           scratch_valid(ops.scratch);
}

void notify(const LocalTransportPairingSessionOps& ops, LocalTransportPairingEvent event)
{
    if (ops.notify != nullptr) {
        ops.notify(event, ops.context);
    }
}

bool build_optical_payload(
    const LocalTransportPairingSessionOps& ops,
    const LocalTransportPairingIdentity& identity,
    const uint8_t nonce[kLocalTransportPairingNonceBytes],
    char* payload,
    size_t payload_size,
    char* fingerprint_hex,
    size_t fingerprint_hex_size)
{
    const LocalTransportOpticalPayloadFields fields = {
        ops.transport_kind,
        ops.endpoint_descriptor_hex,
        identity.fingerprint,
        sizeof(identity.fingerprint),
        nonce,
        kLocalTransportPairingNonceBytes,
        ops.optical_payload_exp_seconds,
    };
    return local_transport_build_optical_payload(
        fields,
        payload,
        payload_size,
        fingerprint_hex,
        fingerprint_hex_size);
}

bool draw_pairing_panel(const LocalTransportPairingSessionOps& ops)
{
    return ops.draw_pairing_panel(
        g_pairing.payload,
        g_pairing.fingerprint_hex,
        g_pairing.deadline,
        ops.context);
}

bool stage_has_pairing_ui(PairingStage stage)
{
    return stage == PairingStage::advertised ||
           stage == PairingStage::challenge_pending;
}

bool stage_is_pairing_open(PairingStage stage)
{
    return stage == PairingStage::advertising_pending ||
           stage_has_pairing_ui(stage);
}

void clear_noise_and_pending_peer()
{
    local_transport_noise_clear_responder_state(&g_pairing.noise);
    local_transport_noise_clear_session_keys(&g_pairing.pending_keys);
    local_transport_wipe_bytes(
        g_pairing.pending_gateway_static_public,
        sizeof(g_pairing.pending_gateway_static_public));
}

void clear_established_session(const LocalTransportPairingSessionOps& ops)
{
    local_transport_noise_clear_session_keys(&g_pairing.session_keys);
    g_pairing.rx_counter = 0;
    g_pairing.tx_counter = 0;
    local_transport_reassembly_reset(&g_pairing.reassembly);
    wipe_transport_buffers(ops);
}

void close_established_session(const LocalTransportPairingSessionOps& ops)
{
    clear_established_session(ops);
    g_pairing.stage = PairingStage::idle;
}

void fail_pairing(const LocalTransportPairingSessionOps& ops, LocalTransportPairingEvent event)
{
    ops.stop_advertising(ops.context);
    g_pairing.clear();
    wipe_transport_buffers(ops);
    notify(ops, event);
}

bool send_control_indication(const LocalTransportPairingSessionOps& ops, const uint8_t* payload, size_t payload_len)
{
    return ops.send(LocalTransportPairingChannel::control, payload, payload_len, ops.context);
}

bool send_protocol_line(const LocalTransportPairingSessionOps& ops, const char* line, size_t line_len)
{
    if (line == nullptr || line_len == 0 ||
        line_len > kLocalTransportFirmwareResponseLineCapBytes ||
        g_pairing.stage != PairingStage::established) {
        return false;
    }

    size_t fragment_limit = 0;
    if (!local_transport_fragment_payload_limit(
            ops.current_att_mtu(ops.context),
            &fragment_limit)) {
        close_established_session(ops);
        return false;
    }

    size_t offset = 0;
    uint16_t sequence = 0;
    while (offset < line_len) {
        const size_t remaining = line_len - offset;
        const size_t chunk = remaining > fragment_limit ? fragment_limit : remaining;
        const bool last = offset + chunk == line_len;
        const LocalTransportPlainFrame frame = {
            kLocalTransportFrameTypeProtocolLineFragment,
            static_cast<uint8_t>(last ? kLocalTransportFrameFlagLast : 0),
            sequence,
            static_cast<uint32_t>(line_len),
            reinterpret_cast<const uint8_t*>(line) + offset,
            chunk,
        };
        uint8_t encrypted[kLocalTransportMaximumEncryptedFrameBytes] = {};
        size_t encrypted_size = 0;
        const LocalTransportFrameAeadStatus encrypted_status =
            local_transport_encrypt_frame(
                g_pairing.session_keys.device_to_gateway,
                LocalTransportFrameDirection::device_to_gateway,
                g_pairing.tx_counter,
                frame,
                encrypted,
                sizeof(encrypted),
                &encrypted_size,
                *ops.crypto_ops);
        if (encrypted_status != LocalTransportFrameAeadStatus::ok ||
            !ops.send(
                LocalTransportPairingChannel::data,
                encrypted,
                encrypted_size,
                ops.context)) {
            local_transport_wipe_bytes(encrypted, sizeof(encrypted));
            close_established_session(ops);
            return false;
        }
        local_transport_wipe_bytes(encrypted, sizeof(encrypted));
        ++g_pairing.tx_counter;
        ++sequence;
        offset += chunk;
    }
    return true;
}

bool write_response_json(const LocalTransportPairingSessionOps& ops, JsonDocument& response)
{
    if (response.overflowed()) {
        return false;
    }
    const size_t measured = measureJson(response);
    if (measured == 0 || measured > kLocalTransportFirmwareResponseLineCapBytes) {
        return false;
    }
    memset(ops.scratch.response_line, 0, ops.scratch.response_line_size);
    const size_t written = serializeJson(
        response,
        ops.scratch.response_line,
        ops.scratch.response_line_size);
    if (written == 0 || written != measured || written >= ops.scratch.response_line_size) {
        local_transport_wipe_bytes(
            reinterpret_cast<uint8_t*>(ops.scratch.response_line),
            ops.scratch.response_line_size);
        return false;
    }
    const bool ok = send_protocol_line(ops, ops.scratch.response_line, written);
    local_transport_wipe_bytes(
        reinterpret_cast<uint8_t*>(ops.scratch.response_line),
        ops.scratch.response_line_size);
    return ok;
}

LocalTransportPairingSessionOps g_writer_ops = {};
bool g_writer_ops_active = false;

bool write_local_transport_success_result(const char* id, const char* method, JsonObjectConst result)
{
    if (!g_writer_ops_active) {
        return false;
    }
    JsonDocument response;
    if (!device_response_prepare_success_result(response, id, method, result)) {
        return false;
    }
    return write_response_json(g_writer_ops, response);
}

bool write_local_transport_transport_success_result(const char* id, JsonObjectConst result)
{
    if (!g_writer_ops_active) {
        return false;
    }
    JsonDocument response;
    if (!device_response_prepare_transport_success_result(response, id, result)) {
        return false;
    }
    return write_response_json(g_writer_ops, response);
}

bool write_local_transport_method_error(const char* id, const char* method, const char* code)
{
    if (!g_writer_ops_active) {
        return false;
    }
    JsonDocument response;
    if (!device_response_prepare_method_error(response, id, method, code)) {
        return false;
    }
    return write_response_json(g_writer_ops, response);
}

void log_local_transport_write_failure(const char*, const char*) {}

const UsbOperationResponseWriter& local_transport_response_writer()
{
    static const UsbOperationResponseWriter writer = {
        write_local_transport_method_error,
        write_local_transport_success_result,
        write_local_transport_transport_success_result,
        log_local_transport_write_failure,
    };
    return writer;
}

bool build_pairing_prologue(uint8_t* output, size_t output_size, size_t* output_len)
{
    if (output == nullptr || output_len == nullptr) {
        return false;
    }
    *output_len = 0;
    const size_t payload_len = strlen(g_pairing.payload);
    const size_t required_len =
        kLocalTransportNoisePairingProloguePrefixBytes + payload_len;
    if (payload_len == 0 || required_len > output_size) {
        return false;
    }
    memcpy(output,
           kLocalTransportNoisePairingProloguePrefix,
           kLocalTransportNoisePairingProloguePrefixBytes);
    memcpy(output + kLocalTransportNoisePairingProloguePrefixBytes,
           g_pairing.payload,
           payload_len);
    *output_len = required_len;
    return true;
}

void process_control_frame(
    const LocalTransportPairingInboundFrame& frame,
    const LocalTransportPairingSessionOps& ops)
{
    if (g_pairing.stage == PairingStage::advertised &&
        frame.length == kLocalTransportNoiseMessage1Bytes) {
        uint8_t message2[kLocalTransportNoiseMessage2Bytes] = {};
        uint8_t prologue[
            kLocalTransportNoisePairingProloguePrefixBytes +
            kLocalTransportOpticalPayloadMaxBytes] = {};
        size_t prologue_len = 0;
        size_t message2_len = 0;
        if (!build_pairing_prologue(prologue, sizeof(prologue), &prologue_len)) {
            fail_pairing(ops, LocalTransportPairingEvent::failed);
            return;
        }
        const LocalTransportNoiseStatus status =
            local_transport_noise_responder_write_message2(
                &g_pairing.noise,
                prologue,
                prologue_len,
                g_pairing.identity.secret_key,
                g_pairing.identity.public_key,
                g_pairing.identity.fingerprint,
                frame.payload,
                frame.length,
                message2,
                sizeof(message2),
                &message2_len,
                *ops.crypto_ops);
        local_transport_wipe_bytes(prologue, sizeof(prologue));
        local_transport_wipe_bytes(g_pairing.identity.secret_key, sizeof(g_pairing.identity.secret_key));
        if (status != LocalTransportNoiseStatus::ok ||
            !send_control_indication(ops, message2, message2_len)) {
            local_transport_wipe_bytes(message2, sizeof(message2));
            fail_pairing(ops, LocalTransportPairingEvent::failed);
            return;
        }
        local_transport_wipe_bytes(message2, sizeof(message2));
        g_pairing.stage = PairingStage::challenge_pending;
        return;
    }

    if (g_pairing.stage == PairingStage::challenge_pending &&
        frame.length == kLocalTransportNoiseMessage3Bytes) {
        const LocalTransportNoiseStatus status =
            local_transport_noise_responder_read_message3(
                &g_pairing.noise,
                frame.payload,
                frame.length,
                g_pairing.pending_gateway_static_public,
                &g_pairing.pending_keys,
                *ops.crypto_ops);
        if (status != LocalTransportNoiseStatus::ok) {
            fail_pairing(ops, LocalTransportPairingEvent::failed);
            return;
        }
        if (!ops.store_paired_peer(g_pairing.pending_gateway_static_public, ops.context)) {
            fail_pairing(ops, LocalTransportPairingEvent::store_full);
            return;
        }
        ops.stop_advertising(ops.context);
        g_pairing.session_keys = g_pairing.pending_keys;
        local_transport_noise_clear_session_keys(&g_pairing.pending_keys);
        local_transport_wipe_bytes(
            g_pairing.pending_gateway_static_public,
            sizeof(g_pairing.pending_gateway_static_public));
        g_pairing.rx_counter = 0;
        g_pairing.tx_counter = 0;
        local_transport_reassembly_reset(&g_pairing.reassembly);
        g_pairing.stage = PairingStage::established;
        notify(ops, LocalTransportPairingEvent::connected);
        return;
    }

    fail_pairing(ops, LocalTransportPairingEvent::failed);
}

void process_data_frame(
    const LocalTransportPairingInboundFrame& frame,
    const LocalTransportPairingSessionOps& ops)
{
    if (g_pairing.stage != PairingStage::established) {
        close_established_session(ops);
        return;
    }

    LocalTransportPlainFrame plain = {};
    const LocalTransportFrameAeadStatus decrypted_status =
        local_transport_decrypt_frame(
            g_pairing.session_keys.gateway_to_device,
            LocalTransportFrameDirection::gateway_to_device,
            g_pairing.rx_counter,
            frame.payload,
            frame.length,
            ops.scratch.plain_frame,
            ops.scratch.plain_frame_size,
            &plain,
            *ops.crypto_ops);
    if (decrypted_status != LocalTransportFrameAeadStatus::ok) {
        close_established_session(ops);
        return;
    }
    ++g_pairing.rx_counter;

    if (plain.type == kLocalTransportFrameTypeTransportClose) {
        close_established_session(ops);
        return;
    }

    size_t line_size = 0;
    const LocalTransportReassemblyStatus reassembly_status =
        local_transport_reassembly_accept(&g_pairing.reassembly, plain, &line_size);
    if (reassembly_status == LocalTransportReassemblyStatus::in_progress) {
        return;
    }
    if (reassembly_status != LocalTransportReassemblyStatus::complete ||
        line_size == 0 ||
        line_size > kLocalTransportGatewayRequestLineCapBytes) {
        close_established_session(ops);
        return;
    }
    ops.scratch.request_line[line_size] = '\0';
    g_writer_ops = ops;
    g_writer_ops_active = true;
    ops.handle_request_line(
        reinterpret_cast<const char*>(ops.scratch.request_line),
        local_transport_response_writer(),
        ops.context);
    g_writer_ops_active = false;
    g_writer_ops = {};
    local_transport_wipe_bytes(ops.scratch.request_line, ops.scratch.request_line_size);
}

}  // namespace

bool local_transport_pairing_session_begin(
    TickType_t now,
    const LocalTransportPairingSessionOps& ops)
{
    if (!ops_valid(ops)) {
        return false;
    }
    g_pairing.clear();
    wipe_transport_buffers(ops);

    LocalTransportPairingIdentitySecret identity = {};
    if (!ops.load_or_create_identity_secret(&identity, ops.context)) {
        notify(ops, LocalTransportPairingEvent::unavailable);
        return false;
    }

    uint8_t nonce[kLocalTransportPairingNonceBytes] = {};
    if (!ops.crypto_ops->random_bytes(nonce, sizeof(nonce), ops.crypto_ops->context)) {
        local_transport_wipe_bytes(nonce, sizeof(nonce));
        local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(&identity), sizeof(identity));
        notify(ops, LocalTransportPairingEvent::unavailable);
        return false;
    }

    LocalTransportPairingState next;
    next.stage = PairingStage::advertising_pending;
    next.deadline = now + pdMS_TO_TICKS(kLocalTransportPairingAdvertiseMs);
    memcpy(&next.identity, &identity, sizeof(next.identity));
    memcpy(next.nonce, nonce, sizeof(next.nonce));
    uint8_t advertised_fingerprint[kLocalTransportIdentityFingerprintBytes] = {};
    memcpy(advertised_fingerprint, identity.fingerprint, sizeof(advertised_fingerprint));
    local_transport_reassembly_init(
        &next.reassembly,
        ops.scratch.request_line,
        kLocalTransportGatewayRequestLineCapBytes,
        kLocalTransportGatewayRequestLineCapBytes);
    LocalTransportPairingIdentity public_identity = {};
    memcpy(public_identity.public_key, identity.public_key, sizeof(public_identity.public_key));
    memcpy(public_identity.fingerprint, identity.fingerprint, sizeof(public_identity.fingerprint));
    const bool payload_ok = build_optical_payload(
        ops,
        public_identity,
        nonce,
        next.payload,
        sizeof(next.payload),
        next.fingerprint_hex,
        sizeof(next.fingerprint_hex));
    local_transport_wipe_bytes(nonce, sizeof(nonce));
    local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(&public_identity), sizeof(public_identity));
    local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(&identity), sizeof(identity));
    if (!payload_ok) {
        next.clear();
        local_transport_wipe_bytes(advertised_fingerprint, sizeof(advertised_fingerprint));
        notify(ops, LocalTransportPairingEvent::unavailable);
        return false;
    }
    if (!ops.start_advertising(advertised_fingerprint, ops.context)) {
        ops.stop_advertising(ops.context);
        next.clear();
        local_transport_wipe_bytes(advertised_fingerprint, sizeof(advertised_fingerprint));
        notify(ops, LocalTransportPairingEvent::unavailable);
        return false;
    }
    local_transport_wipe_bytes(advertised_fingerprint, sizeof(advertised_fingerprint));

    g_pairing = next;
    if (ops.advertising_active(ops.context)) {
        g_pairing.stage = PairingStage::advertised;
        if (!draw_pairing_panel(ops)) {
            ops.stop_advertising(ops.context);
            g_pairing.clear();
            notify(ops, LocalTransportPairingEvent::display_failed);
            return false;
        }
    }
    return true;
}

void local_transport_pairing_session_cancel(const LocalTransportPairingSessionOps& ops)
{
    if (ops.stop_advertising != nullptr) {
        ops.stop_advertising(ops.context);
    }
    g_pairing.clear();
    if (ops_valid(ops)) {
        wipe_transport_buffers(ops);
    }
}

void local_transport_pairing_session_poll(
    TickType_t,
    const LocalTransportPairingSessionOps& ops)
{
    if (!ops_valid(ops)) {
        g_pairing.clear();
        return;
    }
    if (!ops.connected(ops.context)) {
        if (g_pairing.stage == PairingStage::advertising_pending &&
            ops.advertising_active(ops.context)) {
            g_pairing.stage = PairingStage::advertised;
            if (!draw_pairing_panel(ops)) {
                fail_pairing(ops, LocalTransportPairingEvent::display_failed);
                return;
            }
        }
        if (g_pairing.stage == PairingStage::challenge_pending) {
            clear_noise_and_pending_peer();
            g_pairing.stage = PairingStage::advertised;
            draw_pairing_panel(ops);
        } else if (g_pairing.stage == PairingStage::established) {
            close_established_session(ops);
        }
    }

    LocalTransportPairingInboundFrame frame = {};
    if (!ops.receive(&frame, ops.context)) {
        return;
    }
    if (frame.channel == LocalTransportPairingChannel::control) {
        process_control_frame(frame, ops);
    } else {
        process_data_frame(frame, ops);
    }
    local_transport_wipe_bytes(frame.payload, sizeof(frame.payload));
}

bool local_transport_pairing_session_expired(TickType_t now)
{
    if (!stage_is_pairing_open(g_pairing.stage)) {
        return false;
    }
    return static_cast<int32_t>(now - g_pairing.deadline) >= 0;
}

LocalTransportPairingSnapshot local_transport_pairing_session_snapshot()
{
    LocalTransportPairingSnapshot snapshot = {};
    snapshot.active = stage_has_pairing_ui(g_pairing.stage);
    memcpy(snapshot.payload, g_pairing.payload, sizeof(snapshot.payload));
    memcpy(snapshot.fingerprint_hex, g_pairing.fingerprint_hex, sizeof(snapshot.fingerprint_hex));
    snapshot.deadline = g_pairing.deadline;
    return snapshot;
}

bool local_transport_pairing_session_active()
{
    return stage_is_pairing_open(g_pairing.stage);
}

bool local_transport_pairing_session_established()
{
    return g_pairing.stage == PairingStage::established;
}

bool local_transport_pairing_session_write_response(
    const LocalTransportPairingSessionOps& ops,
    LocalTransportPairingResponseCallback callback,
    void* context)
{
    if (!ops_valid(ops) ||
        callback == nullptr ||
        g_pairing.stage != PairingStage::established) {
        return false;
    }
    g_writer_ops = ops;
    g_writer_ops_active = true;
    const bool written = callback(local_transport_response_writer(), context);
    g_writer_ops_active = false;
    g_writer_ops = {};
    return written;
}

}  // namespace signing
