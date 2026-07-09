#pragma once

#include <stddef.h>
#include <stdint.h>

#include "transport/local_transport_crypto.h"

namespace signing {

constexpr size_t kLocalTransportFrameHeaderBytes = 10;
constexpr size_t kLocalTransportAeadTagBytes = 16;
constexpr size_t kLocalTransportMinimumFragmentPayloadBytes = 20;
constexpr size_t kLocalTransportMaximumAttMtuBytes = 527;
constexpr size_t kLocalTransportMaximumFragmentPayloadBytes =
    kLocalTransportMaximumAttMtuBytes - 3 - kLocalTransportFrameHeaderBytes -
    kLocalTransportAeadTagBytes;
constexpr size_t kLocalTransportMaximumPlainFrameBytes =
    kLocalTransportFrameHeaderBytes + kLocalTransportMaximumFragmentPayloadBytes;
constexpr size_t kLocalTransportMaximumEncryptedFrameBytes =
    kLocalTransportMaximumPlainFrameBytes + kLocalTransportAeadTagBytes;
constexpr size_t kLocalTransportFrameNonceBytes = 12;
constexpr size_t kLocalTransportFrameAadBytes = 42;
constexpr size_t kLocalTransportGatewayRequestLineCapBytes = 4096;
constexpr size_t kLocalTransportFirmwareResponseLineCapBytes = 16 * 1024;

constexpr uint8_t kLocalTransportFrameTypeProtocolLineFragment = 0x01;
constexpr uint8_t kLocalTransportFrameTypeTransportClose = 0x02;
constexpr uint8_t kLocalTransportFrameFlagLast = 0x01;

enum class LocalTransportFrameStatus {
    ok,
    invalid_argument,
    invalid_type,
    invalid_flags,
    invalid_length,
    payload_too_large,
    output_too_small,
};

enum class LocalTransportFrameAeadStatus {
    ok,
    invalid_argument,
    invalid_counter,
    invalid_frame,
    crypto_error,
    output_too_small,
};

enum class LocalTransportReassemblyStatus {
    in_progress,
    complete,
    invalid_argument,
    invalid_frame,
    line_too_large,
    sequence_mismatch,
    total_length_mismatch,
    payload_length_mismatch,
};

enum class LocalTransportFrameDirection : uint8_t {
    gateway_to_device = 0x01,
    device_to_gateway = 0x02,
};

struct LocalTransportPlainFrame {
    uint8_t type;
    uint8_t flags;
    uint16_t sequence;
    uint32_t total_len;
    const uint8_t* payload;
    size_t payload_len;
};

struct LocalTransportReassemblyState {
    uint8_t* buffer;
    size_t buffer_capacity;
    size_t line_cap;
    uint32_t total_len;
    uint32_t received_len;
    uint16_t next_sequence;
    bool active;
};

bool local_transport_fragment_payload_limit(uint16_t att_mtu, size_t* out_limit);

bool local_transport_frame_nonce(uint64_t frame_counter, uint8_t output[kLocalTransportFrameNonceBytes]);

bool local_transport_frame_aad(
    LocalTransportFrameDirection direction,
    uint64_t frame_counter,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

LocalTransportFrameStatus local_transport_encode_plain_frame(
    const LocalTransportPlainFrame& frame,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

LocalTransportFrameStatus local_transport_decode_plain_frame(
    const uint8_t* input,
    size_t input_size,
    LocalTransportPlainFrame* frame);

LocalTransportFrameAeadStatus local_transport_encrypt_frame(
    const uint8_t key[kLocalTransportCryptoKeyBytes],
    LocalTransportFrameDirection direction,
    uint64_t frame_counter,
    const LocalTransportPlainFrame& frame,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size,
    const LocalTransportCryptoOps& ops);

LocalTransportFrameAeadStatus local_transport_decrypt_frame(
    const uint8_t key[kLocalTransportCryptoKeyBytes],
    LocalTransportFrameDirection direction,
    uint64_t frame_counter,
    const uint8_t* input,
    size_t input_size,
    uint8_t* plain_output,
    size_t plain_output_capacity,
    LocalTransportPlainFrame* frame,
    const LocalTransportCryptoOps& ops);

bool local_transport_reassembly_init(
    LocalTransportReassemblyState* state,
    uint8_t* buffer,
    size_t buffer_capacity,
    size_t line_cap);

void local_transport_reassembly_reset(LocalTransportReassemblyState* state);

LocalTransportReassemblyStatus local_transport_reassembly_accept(
    LocalTransportReassemblyState* state,
    const LocalTransportPlainFrame& frame,
    size_t* out_line_size);

}  // namespace signing
