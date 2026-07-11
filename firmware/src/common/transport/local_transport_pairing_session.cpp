#include "transport/local_transport_pairing_session.h"

#include <ArduinoJson.h>
#include <string.h>

#include "protocol/device_response.h"
#include "transport/local_transport_noise.h"

namespace signing {
namespace {

enum class LocalTransportSessionState {
    idle,
    pairing_starting,
    pairing_window,
    pairing_handshake,
    ready,
    receiving_request,
    awaiting_response,
    sending_response,
    closing,
};

struct LocalTransportPairingState {
    LocalTransportSessionState state = LocalTransportSessionState::idle;
    char payload[kLocalTransportOpticalPayloadMaxBytes] = {};
    char fingerprint_hex[kLocalTransportFingerprintHexBytes] = {};
    uint8_t nonce[kLocalTransportPairingNonceBytes] = {};
    TickType_t pairing_deadline = 0;
    TickType_t phase_deadline = 0;
    LocalTransportPairingIdentity identity = {};
    LocalTransportNoiseResponderState noise = {};
    LocalTransportNoiseSessionKeys pending_keys = {};
    LocalTransportNoiseSessionKeys session_keys = {};
    uint64_t rx_counter = 0;
    uint64_t tx_counter = 0;
    LocalTransportReassemblyState reassembly = {};

    void clear_pairing_material()
    {
        memset(payload, 0, sizeof(payload));
        memset(fingerprint_hex, 0, sizeof(fingerprint_hex));
        local_transport_wipe_bytes(nonce, sizeof(nonce));
        pairing_deadline = 0;
        memset(&identity, 0, sizeof(identity));
        local_transport_noise_clear_responder_state(&noise);
        local_transport_noise_clear_session_keys(&pending_keys);
    }

    void clear()
    {
        state = LocalTransportSessionState::idle;
        clear_pairing_material();
        phase_deadline = 0;
        local_transport_noise_clear_session_keys(&session_keys);
        rx_counter = 0;
        tx_counter = 0;
        local_transport_reassembly_reset(&reassembly);
    }
};

LocalTransportPairingState g_pairing;
LocalTransportPairingSessionOps g_writer_ops = {};
bool g_writer_ops_active = false;

void clear_response_writer()
{
    g_writer_ops_active = false;
    g_writer_ops = {};
}

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
    return ops.identity_store != nullptr &&
           ops.start_advertising != nullptr &&
           ops.stop_advertising != nullptr &&
           ops.poll_carrier != nullptr &&
           ops.advertising_active != nullptr &&
           ops.connected != nullptr &&
           ops.disconnect != nullptr &&
           ops.current_att_mtu != nullptr &&
           ops.receive != nullptr &&
           ops.send_acknowledged != nullptr &&
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

bool deadline_reached(TickType_t now, TickType_t deadline)
{
    return deadline != 0 && static_cast<int32_t>(now - deadline) >= 0;
}

bool state_has_pairing_ui(LocalTransportSessionState state)
{
    return state == LocalTransportSessionState::pairing_window ||
           state == LocalTransportSessionState::pairing_handshake;
}

bool state_is_pairing_open(LocalTransportSessionState state)
{
    return state == LocalTransportSessionState::pairing_starting ||
           state_has_pairing_ui(state);
}

bool state_has_encrypted_session(LocalTransportSessionState state)
{
    return state == LocalTransportSessionState::ready ||
           state == LocalTransportSessionState::receiving_request ||
           state == LocalTransportSessionState::awaiting_response ||
           state == LocalTransportSessionState::sending_response;
}

void clear_established_session(const LocalTransportPairingSessionOps& ops)
{
    local_transport_noise_clear_session_keys(&g_pairing.session_keys);
    g_pairing.rx_counter = 0;
    g_pairing.tx_counter = 0;
    local_transport_reassembly_reset(&g_pairing.reassembly);
    wipe_transport_buffers(ops);
}

void clear_pairing_session_state(const LocalTransportPairingSessionOps& ops)
{
    clear_established_session(ops);
    g_pairing.clear();
    clear_response_writer();
}

void close_session(const LocalTransportPairingSessionOps& ops)
{
    g_pairing.state = LocalTransportSessionState::closing;
    if (ops.connected != nullptr &&
        ops.disconnect != nullptr &&
        ops.connected(ops.context)) {
        ops.disconnect(ops.context);
    }
    clear_pairing_session_state(ops);
}

void fail_pairing(const LocalTransportPairingSessionOps& ops, LocalTransportPairingEvent event)
{
    ops.stop_advertising(ops.context);
    if (ops.connected(ops.context)) {
        ops.disconnect(ops.context);
    }
    clear_pairing_session_state(ops);
    notify(ops, event);
}

bool send_control_indication(const LocalTransportPairingSessionOps& ops, const uint8_t* payload, size_t payload_len)
{
    return ops.send_acknowledged(
        LocalTransportPairingChannel::control,
        payload,
        payload_len,
        ops.context);
}

bool send_protocol_line(const LocalTransportPairingSessionOps& ops, const char* line, size_t line_len)
{
    if (line == nullptr || line_len == 0 ||
        line_len > kLocalTransportFirmwareResponseLineCapBytes ||
        g_pairing.state != LocalTransportSessionState::awaiting_response) {
        return false;
    }

    g_pairing.state = LocalTransportSessionState::sending_response;

    size_t fragment_limit = 0;
    if (!local_transport_fragment_payload_limit(
            ops.current_att_mtu(ops.context),
            &fragment_limit)) {
        close_session(ops);
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
            !ops.send_acknowledged(
                LocalTransportPairingChannel::data,
                encrypted,
                encrypted_size,
                ops.context)) {
            local_transport_wipe_bytes(encrypted, sizeof(encrypted));
            close_session(ops);
            return false;
        }
        local_transport_wipe_bytes(encrypted, sizeof(encrypted));
        ++g_pairing.tx_counter;
        ++sequence;
        offset += chunk;
    }
    g_pairing.phase_deadline = 0;
    g_pairing.state = LocalTransportSessionState::ready;
    return true;
}

bool write_response_json(const LocalTransportPairingSessionOps& ops, JsonDocument& response)
{
    if (response.overflowed()) {
        close_session(ops);
        return false;
    }
    const size_t measured = measureJson(response);
    if (measured == 0 || measured > kLocalTransportFirmwareResponseLineCapBytes) {
        close_session(ops);
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
        close_session(ops);
        return false;
    }
    const bool ok = send_protocol_line(ops, ops.scratch.response_line, written);
    local_transport_wipe_bytes(
        reinterpret_cast<uint8_t*>(ops.scratch.response_line),
        ops.scratch.response_line_size);
    return ok;
}

bool write_local_transport_success_result(const char* id, const char* method, JsonObjectConst result)
{
    if (!g_writer_ops_active) {
        return false;
    }
    JsonDocument response;
    if (!device_response_prepare_success_result(response, id, method, result)) {
        close_session(g_writer_ops);
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
        close_session(g_writer_ops);
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
        close_session(g_writer_ops);
        return false;
    }
    return write_response_json(g_writer_ops, response);
}

void log_local_transport_write_failure(const char*, const char*) {}

const ResponseWriter& local_transport_response_writer()
{
    static const ResponseWriter writer = {
        write_local_transport_method_error,
        write_local_transport_success_result,
        write_local_transport_transport_success_result,
        log_local_transport_write_failure,
    };
    return writer;
}

bool write_local_transport_response_bytes(const char* data, size_t length, void*)
{
    if (data != nullptr && length == 1 && data[0] == '\n') {
        return true;
    }
    return g_writer_ops_active &&
           send_protocol_line(g_writer_ops, data, length);
}

const ProtocolTransportEndpoint& local_transport_endpoint()
{
    static const ProtocolTransportEndpoint endpoint{
        ProtocolTransport::local_transport,
        local_transport_response_writer(),
        JsonResponseWriteOps{
            write_local_transport_response_bytes,
            nullptr,
            nullptr,
        },
    };
    return endpoint;
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
    TickType_t now,
    const LocalTransportPairingInboundFrame& frame,
    const LocalTransportPairingSessionOps& ops)
{
    if (g_pairing.state == LocalTransportSessionState::pairing_window &&
        frame.length == kLocalTransportNoiseMessage1Bytes) {
        LocalTransportPairingIdentitySecret identity = {};
        uint8_t message2[kLocalTransportNoiseMessage2Bytes] = {};
        uint8_t prologue[
            kLocalTransportNoisePairingProloguePrefixBytes +
            kLocalTransportOpticalPayloadMaxBytes] = {};
        size_t prologue_len = 0;
        size_t message2_len = 0;
        if (!local_transport_identity_load_secret(*ops.identity_store, &identity) ||
            memcmp(identity.public_key, g_pairing.identity.public_key, sizeof(identity.public_key)) != 0 ||
            memcmp(identity.fingerprint, g_pairing.identity.fingerprint, sizeof(identity.fingerprint)) != 0 ||
            !build_pairing_prologue(prologue, sizeof(prologue), &prologue_len)) {
            local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(&identity), sizeof(identity));
            fail_pairing(ops, LocalTransportPairingEvent::failed);
            return;
        }
        const LocalTransportNoiseStatus status =
            local_transport_noise_responder_write_message2(
                &g_pairing.noise,
                prologue,
                prologue_len,
                identity.secret_key,
                identity.public_key,
                identity.fingerprint,
                frame.payload,
                frame.length,
                message2,
                sizeof(message2),
                &message2_len,
                *ops.crypto_ops);
        local_transport_wipe_bytes(prologue, sizeof(prologue));
        local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(&identity), sizeof(identity));
        if (status != LocalTransportNoiseStatus::ok ||
            !send_control_indication(ops, message2, message2_len)) {
            local_transport_wipe_bytes(message2, sizeof(message2));
            fail_pairing(ops, LocalTransportPairingEvent::failed);
            return;
        }
        local_transport_wipe_bytes(message2, sizeof(message2));
        g_pairing.state = LocalTransportSessionState::pairing_handshake;
        g_pairing.phase_deadline =
            now + pdMS_TO_TICKS(kLocalTransportPairingHandshakeMs);
        return;
    }

    if (g_pairing.state == LocalTransportSessionState::pairing_handshake &&
        frame.length == kLocalTransportNoiseMessage3Bytes) {
        uint8_t gateway_static_public[kLocalTransportStaticKeyBytes] = {};
        const LocalTransportNoiseStatus status =
            local_transport_noise_responder_read_message3(
                &g_pairing.noise,
                frame.payload,
                frame.length,
                gateway_static_public,
                &g_pairing.pending_keys,
                *ops.crypto_ops);
        if (status != LocalTransportNoiseStatus::ok) {
            local_transport_wipe_bytes(
                gateway_static_public,
                sizeof(gateway_static_public));
            fail_pairing(ops, LocalTransportPairingEvent::failed);
            return;
        }
        local_transport_wipe_bytes(
            gateway_static_public,
            sizeof(gateway_static_public));
        ops.stop_advertising(ops.context);
        g_pairing.session_keys = g_pairing.pending_keys;
        g_pairing.clear_pairing_material();
        g_pairing.rx_counter = 0;
        g_pairing.tx_counter = 0;
        local_transport_reassembly_reset(&g_pairing.reassembly);
        g_pairing.phase_deadline = 0;
        g_pairing.state = LocalTransportSessionState::ready;
        g_writer_ops = ops;
        g_writer_ops_active = true;
        const uint8_t ready_signal = kLocalTransportHandshakeReadySignal;
        if (!send_control_indication(ops, &ready_signal, sizeof(ready_signal))) {
            close_session(ops);
            return;
        }
        notify(ops, LocalTransportPairingEvent::connected);
        return;
    }

    fail_pairing(ops, LocalTransportPairingEvent::failed);
}

void process_data_frame(
    TickType_t now,
    const LocalTransportPairingInboundFrame& frame,
    const LocalTransportPairingSessionOps& ops)
{
    if (g_pairing.state != LocalTransportSessionState::ready &&
        g_pairing.state != LocalTransportSessionState::receiving_request) {
        close_session(ops);
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
        close_session(ops);
        return;
    }
    ++g_pairing.rx_counter;

    if (plain.type == kLocalTransportFrameTypeTransportClose) {
        close_session(ops);
        return;
    }

    size_t line_size = 0;
    const LocalTransportReassemblyStatus reassembly_status =
        local_transport_reassembly_accept(&g_pairing.reassembly, plain, &line_size);
    if (reassembly_status == LocalTransportReassemblyStatus::in_progress) {
        if (g_pairing.state == LocalTransportSessionState::ready) {
            g_pairing.phase_deadline =
                now + pdMS_TO_TICKS(kLocalTransportRequestReassemblyMs);
        }
        g_pairing.state = LocalTransportSessionState::receiving_request;
        return;
    }
    if (reassembly_status != LocalTransportReassemblyStatus::complete ||
        line_size == 0 ||
        line_size > kLocalTransportGatewayRequestLineCapBytes) {
        close_session(ops);
        return;
    }
    g_pairing.phase_deadline =
        now + pdMS_TO_TICKS(kLocalTransportResponseMs);
    g_pairing.state = LocalTransportSessionState::awaiting_response;
    ops.scratch.request_line[line_size] = '\0';
    const ProtocolTransportRoute route(local_transport_endpoint());
    ops.handle_request_line(
        reinterpret_cast<const char*>(ops.scratch.request_line),
        route,
        ops.context);
    local_transport_wipe_bytes(ops.scratch.request_line, ops.scratch.request_line_size);
}

}  // namespace

bool local_transport_pairing_session_begin(
    TickType_t now,
    const LocalTransportPairingSessionOps& ops)
{
    if (!ops_valid(ops) || g_pairing.state != LocalTransportSessionState::idle) {
        return false;
    }
    clear_pairing_session_state(ops);

    LocalTransportPairingIdentity identity = {};
    if (!local_transport_identity_load_or_create(*ops.identity_store, &identity)) {
        notify(ops, LocalTransportPairingEvent::unavailable);
        return false;
    }

    uint8_t nonce[kLocalTransportPairingNonceBytes] = {};
    if (!ops.crypto_ops->random_bytes(nonce, sizeof(nonce), ops.crypto_ops->context)) {
        local_transport_wipe_bytes(nonce, sizeof(nonce));
        memset(&identity, 0, sizeof(identity));
        notify(ops, LocalTransportPairingEvent::unavailable);
        return false;
    }

    LocalTransportPairingState next;
    next.state = LocalTransportSessionState::pairing_starting;
    next.pairing_deadline = now + pdMS_TO_TICKS(kLocalTransportPairingAdvertiseMs);
    memcpy(&next.identity, &identity, sizeof(next.identity));
    memcpy(next.nonce, nonce, sizeof(next.nonce));
    uint8_t advertised_fingerprint[kLocalTransportIdentityFingerprintBytes] = {};
    memcpy(advertised_fingerprint, identity.fingerprint, sizeof(advertised_fingerprint));
    local_transport_reassembly_init(
        &next.reassembly,
        ops.scratch.request_line,
        kLocalTransportGatewayRequestLineCapBytes,
        kLocalTransportGatewayRequestLineCapBytes);
    const bool payload_ok = build_optical_payload(
        ops,
        identity,
        nonce,
        next.payload,
        sizeof(next.payload),
        next.fingerprint_hex,
        sizeof(next.fingerprint_hex));
    local_transport_wipe_bytes(nonce, sizeof(nonce));
    memset(&identity, 0, sizeof(identity));
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
        g_pairing.state = LocalTransportSessionState::pairing_window;
    }
    return true;
}

void local_transport_pairing_session_cancel(const LocalTransportPairingSessionOps& ops)
{
    if (ops.stop_advertising != nullptr) {
        ops.stop_advertising(ops.context);
    }
    if (ops_valid(ops)) {
        if (ops.connected(ops.context)) {
            ops.disconnect(ops.context);
        }
        g_pairing.state = LocalTransportSessionState::closing;
        clear_pairing_session_state(ops);
        return;
    }
    g_pairing.clear();
    clear_response_writer();
}

void local_transport_pairing_session_handle_display_loss(
    const LocalTransportPairingSessionOps& ops)
{
    if (!ops_valid(ops) || !state_has_pairing_ui(g_pairing.state)) {
        return;
    }
    fail_pairing(ops, LocalTransportPairingEvent::display_failed);
}

void local_transport_pairing_session_poll(
    TickType_t now,
    const LocalTransportPairingSessionOps& ops)
{
    if (!ops_valid(ops)) {
        g_pairing.clear();
        clear_response_writer();
        return;
    }
    ops.poll_carrier(ops.context);
    if (state_is_pairing_open(g_pairing.state) &&
        deadline_reached(now, g_pairing.pairing_deadline)) {
        fail_pairing(ops, LocalTransportPairingEvent::expired);
        return;
    }
    if (!ops.connected(ops.context)) {
        if (g_pairing.state == LocalTransportSessionState::pairing_starting &&
            ops.advertising_active(ops.context)) {
            g_pairing.state = LocalTransportSessionState::pairing_window;
        }
        if (g_pairing.state == LocalTransportSessionState::pairing_handshake) {
            fail_pairing(ops, LocalTransportPairingEvent::failed);
            return;
        } else if (state_has_encrypted_session(g_pairing.state)) {
            clear_pairing_session_state(ops);
            return;
        }
    }

    if (g_pairing.state == LocalTransportSessionState::pairing_handshake &&
        deadline_reached(now, g_pairing.phase_deadline)) {
        fail_pairing(ops, LocalTransportPairingEvent::failed);
        return;
    }
    if (g_pairing.state == LocalTransportSessionState::receiving_request &&
        deadline_reached(now, g_pairing.phase_deadline)) {
        close_session(ops);
        return;
    }
    if (g_pairing.state == LocalTransportSessionState::awaiting_response &&
        deadline_reached(now, g_pairing.phase_deadline)) {
        close_session(ops);
        return;
    }

    LocalTransportPairingInboundFrame frame = {};
    if (!ops.receive(&frame, ops.context)) {
        return;
    }
    if (frame.channel == LocalTransportPairingChannel::control) {
        process_control_frame(now, frame, ops);
    } else {
        process_data_frame(now, frame, ops);
    }
    local_transport_wipe_bytes(frame.payload, sizeof(frame.payload));
}

LocalTransportPairingSnapshot local_transport_pairing_session_snapshot()
{
    LocalTransportPairingSnapshot snapshot = {};
    snapshot.active = state_has_pairing_ui(g_pairing.state);
    memcpy(snapshot.payload, g_pairing.payload, sizeof(snapshot.payload));
    memcpy(snapshot.fingerprint_hex, g_pairing.fingerprint_hex, sizeof(snapshot.fingerprint_hex));
    snapshot.deadline = g_pairing.pairing_deadline;
    return snapshot;
}

bool local_transport_pairing_session_active()
{
    return state_is_pairing_open(g_pairing.state);
}

bool local_transport_pairing_session_established()
{
    return state_has_encrypted_session(g_pairing.state);
}

}  // namespace signing
