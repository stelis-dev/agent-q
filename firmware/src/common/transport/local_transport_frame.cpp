#include "local_transport_frame.h"

namespace signing {
namespace {

constexpr size_t kLocalTransportAttHeaderBytes = 3;
constexpr char kLocalTransportFrameAadLabel[] = "Agent-Q local transport frame v1";
constexpr size_t kLocalTransportFrameAadLabelBytes =
    sizeof(kLocalTransportFrameAadLabel) - 1;

static_assert(
    kLocalTransportFrameAadBytes ==
        kLocalTransportFrameAadLabelBytes + 1 + 1 + sizeof(uint64_t),
    "local transport frame AAD size must match the contract");

bool valid_type(uint8_t type)
{
    return type == kLocalTransportFrameTypeProtocolLineFragment ||
           type == kLocalTransportFrameTypeTransportClose;
}

bool valid_flags(uint8_t flags)
{
    return (flags & static_cast<uint8_t>(~kLocalTransportFrameFlagLast)) == 0;
}

bool valid_direction(LocalTransportFrameDirection direction)
{
    return direction == LocalTransportFrameDirection::gateway_to_device ||
           direction == LocalTransportFrameDirection::device_to_gateway;
}

void write_u16_be(uint16_t value, uint8_t output[2])
{
    output[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    output[1] = static_cast<uint8_t>(value & 0xFF);
}

void write_u32_be(uint32_t value, uint8_t output[4])
{
    output[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    output[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    output[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    output[3] = static_cast<uint8_t>(value & 0xFF);
}

void write_u64_be(uint64_t value, uint8_t output[8])
{
    output[0] = static_cast<uint8_t>((value >> 56) & 0xFF);
    output[1] = static_cast<uint8_t>((value >> 48) & 0xFF);
    output[2] = static_cast<uint8_t>((value >> 40) & 0xFF);
    output[3] = static_cast<uint8_t>((value >> 32) & 0xFF);
    output[4] = static_cast<uint8_t>((value >> 24) & 0xFF);
    output[5] = static_cast<uint8_t>((value >> 16) & 0xFF);
    output[6] = static_cast<uint8_t>((value >> 8) & 0xFF);
    output[7] = static_cast<uint8_t>(value & 0xFF);
}

uint16_t read_u16_be(const uint8_t input[2])
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(input[0]) << 8) |
        static_cast<uint16_t>(input[1]));
}

uint32_t read_u32_be(const uint8_t input[4])
{
    return (static_cast<uint32_t>(input[0]) << 24) |
           (static_cast<uint32_t>(input[1]) << 16) |
           (static_cast<uint32_t>(input[2]) << 8) |
           static_cast<uint32_t>(input[3]);
}

LocalTransportFrameStatus validate_plain_frame(const LocalTransportPlainFrame& frame)
{
    if (!valid_type(frame.type)) {
        return LocalTransportFrameStatus::invalid_type;
    }
    if (!valid_flags(frame.flags)) {
        return LocalTransportFrameStatus::invalid_flags;
    }
    if (frame.payload_len > 0 && frame.payload == nullptr) {
        return LocalTransportFrameStatus::invalid_argument;
    }
    if (frame.payload_len > UINT16_MAX) {
        return LocalTransportFrameStatus::payload_too_large;
    }
    if (frame.total_len == 0 || frame.payload_len > frame.total_len) {
        return LocalTransportFrameStatus::invalid_length;
    }
    if (frame.type == kLocalTransportFrameTypeTransportClose &&
        (frame.payload_len != 0 ||
         frame.total_len != 1 ||
         frame.sequence != 0 ||
         (frame.flags & kLocalTransportFrameFlagLast) == 0)) {
        return LocalTransportFrameStatus::invalid_length;
    }
    return LocalTransportFrameStatus::ok;
}

}  // namespace

bool local_transport_fragment_payload_limit(uint16_t att_mtu, size_t* out_limit)
{
    if (out_limit == nullptr) {
        return false;
    }
    *out_limit = 0;

    const size_t mtu = att_mtu;
    const size_t overhead =
        kLocalTransportAttHeaderBytes +
        kLocalTransportFrameHeaderBytes +
        kLocalTransportAeadTagBytes;
    if (mtu <= overhead) {
        return false;
    }

    const size_t limit = mtu - overhead;
    if (limit < kLocalTransportMinimumFragmentPayloadBytes ||
        limit > kLocalTransportMaximumFragmentPayloadBytes) {
        return false;
    }

    *out_limit = limit;
    return true;
}

bool local_transport_frame_nonce(uint64_t frame_counter, uint8_t output[kLocalTransportFrameNonceBytes])
{
    if (output == nullptr) {
        return false;
    }
    output[0] = 0;
    output[1] = 0;
    output[2] = 0;
    output[3] = 0;
    write_u64_be(frame_counter, &output[4]);
    return true;
}

bool local_transport_frame_aad(
    LocalTransportFrameDirection direction,
    uint64_t frame_counter,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output == nullptr || output_size == nullptr ||
        output_capacity < kLocalTransportFrameAadBytes ||
        !valid_direction(direction)) {
        return false;
    }

    size_t offset = 0;
    for (size_t index = 0; index < kLocalTransportFrameAadLabelBytes; ++index) {
        output[offset++] = static_cast<uint8_t>(kLocalTransportFrameAadLabel[index]);
    }
    output[offset++] = 0x00;
    output[offset++] = static_cast<uint8_t>(direction);
    write_u64_be(frame_counter, &output[offset]);
    offset += sizeof(uint64_t);
    *output_size = offset;
    return true;
}

LocalTransportFrameStatus local_transport_encode_plain_frame(
    const LocalTransportPlainFrame& frame,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output == nullptr || output_size == nullptr) {
        return LocalTransportFrameStatus::invalid_argument;
    }

    const LocalTransportFrameStatus validation = validate_plain_frame(frame);
    if (validation != LocalTransportFrameStatus::ok) {
        return validation;
    }

    const size_t required = kLocalTransportFrameHeaderBytes + frame.payload_len;
    if (output_capacity < required) {
        return LocalTransportFrameStatus::output_too_small;
    }

    output[0] = frame.type;
    output[1] = frame.flags;
    write_u16_be(frame.sequence, &output[2]);
    write_u32_be(frame.total_len, &output[4]);
    write_u16_be(static_cast<uint16_t>(frame.payload_len), &output[8]);
    for (size_t index = 0; index < frame.payload_len; ++index) {
        output[kLocalTransportFrameHeaderBytes + index] = frame.payload[index];
    }
    *output_size = required;
    return LocalTransportFrameStatus::ok;
}

LocalTransportFrameStatus local_transport_decode_plain_frame(
    const uint8_t* input,
    size_t input_size,
    LocalTransportPlainFrame* frame)
{
    if (frame != nullptr) {
        *frame = {};
    }
    if (input == nullptr || frame == nullptr) {
        return LocalTransportFrameStatus::invalid_argument;
    }
    if (input_size < kLocalTransportFrameHeaderBytes) {
        return LocalTransportFrameStatus::invalid_length;
    }

    LocalTransportPlainFrame parsed = {};
    parsed.type = input[0];
    parsed.flags = input[1];
    parsed.sequence = read_u16_be(&input[2]);
    parsed.total_len = read_u32_be(&input[4]);
    parsed.payload_len = read_u16_be(&input[8]);
    if (input_size != kLocalTransportFrameHeaderBytes + parsed.payload_len) {
        return LocalTransportFrameStatus::invalid_length;
    }
    parsed.payload = parsed.payload_len == 0
        ? nullptr
        : &input[kLocalTransportFrameHeaderBytes];

    const LocalTransportFrameStatus validation = validate_plain_frame(parsed);
    if (validation != LocalTransportFrameStatus::ok) {
        return validation;
    }

    *frame = parsed;
    return LocalTransportFrameStatus::ok;
}

LocalTransportFrameAeadStatus local_transport_encrypt_frame(
    const uint8_t key[kLocalTransportCryptoKeyBytes],
    LocalTransportFrameDirection direction,
    uint64_t frame_counter,
    const LocalTransportPlainFrame& frame,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size,
    const LocalTransportCryptoOps& ops)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (frame_counter == UINT64_MAX) {
        return LocalTransportFrameAeadStatus::invalid_counter;
    }
    if (key == nullptr || output == nullptr || output_size == nullptr ||
        !local_transport_crypto_ops_valid(ops)) {
        return LocalTransportFrameAeadStatus::invalid_argument;
    }

    uint8_t plain[kLocalTransportMaximumPlainFrameBytes] = {};
    size_t plain_size = 0;
    const LocalTransportFrameStatus encoded =
        local_transport_encode_plain_frame(frame, plain, sizeof(plain), &plain_size);
    if (encoded != LocalTransportFrameStatus::ok) {
        local_transport_wipe_bytes(plain, sizeof(plain));
        return LocalTransportFrameAeadStatus::invalid_frame;
    }
    if (output_capacity < plain_size + kLocalTransportAeadTagBytes) {
        local_transport_wipe_bytes(plain, sizeof(plain));
        return LocalTransportFrameAeadStatus::output_too_small;
    }

    uint8_t nonce[kLocalTransportFrameNonceBytes] = {};
    uint8_t aad[kLocalTransportFrameAadBytes] = {};
    size_t aad_size = 0;
    const bool encrypted =
        local_transport_frame_nonce(frame_counter, nonce) &&
        local_transport_frame_aad(direction, frame_counter, aad, sizeof(aad), &aad_size) &&
        ops.aes256_gcm_encrypt(
            key,
            nonce,
            aad,
            aad_size,
            plain,
            plain_size,
            output,
            output + plain_size,
            ops.context);
    local_transport_wipe_bytes(plain, sizeof(plain));
    local_transport_wipe_bytes(nonce, sizeof(nonce));
    local_transport_wipe_bytes(aad, sizeof(aad));
    if (!encrypted) {
        return LocalTransportFrameAeadStatus::crypto_error;
    }
    *output_size = plain_size + kLocalTransportAeadTagBytes;
    return LocalTransportFrameAeadStatus::ok;
}

LocalTransportFrameAeadStatus local_transport_decrypt_frame(
    const uint8_t key[kLocalTransportCryptoKeyBytes],
    LocalTransportFrameDirection direction,
    uint64_t frame_counter,
    const uint8_t* input,
    size_t input_size,
    uint8_t* plain_output,
    size_t plain_output_capacity,
    LocalTransportPlainFrame* frame,
    const LocalTransportCryptoOps& ops)
{
    if (frame != nullptr) {
        *frame = {};
    }
    if (frame_counter == UINT64_MAX) {
        return LocalTransportFrameAeadStatus::invalid_counter;
    }
    if (key == nullptr || input == nullptr || plain_output == nullptr ||
        frame == nullptr || !local_transport_crypto_ops_valid(ops)) {
        return LocalTransportFrameAeadStatus::invalid_argument;
    }
    if (input_size < kLocalTransportAeadTagBytes ||
        input_size > kLocalTransportMaximumEncryptedFrameBytes) {
        return LocalTransportFrameAeadStatus::invalid_frame;
    }
    const size_t plain_size = input_size - kLocalTransportAeadTagBytes;
    if (plain_size > plain_output_capacity) {
        return LocalTransportFrameAeadStatus::output_too_small;
    }

    uint8_t nonce[kLocalTransportFrameNonceBytes] = {};
    uint8_t aad[kLocalTransportFrameAadBytes] = {};
    size_t aad_size = 0;
    const bool decrypted =
        local_transport_frame_nonce(frame_counter, nonce) &&
        local_transport_frame_aad(direction, frame_counter, aad, sizeof(aad), &aad_size) &&
        ops.aes256_gcm_decrypt(
            key,
            nonce,
            aad,
            aad_size,
            input,
            plain_size,
            input + plain_size,
            plain_output,
            ops.context);
    local_transport_wipe_bytes(nonce, sizeof(nonce));
    local_transport_wipe_bytes(aad, sizeof(aad));
    if (!decrypted) {
        local_transport_wipe_bytes(plain_output, plain_output_capacity);
        return LocalTransportFrameAeadStatus::crypto_error;
    }

    const LocalTransportFrameStatus decoded =
        local_transport_decode_plain_frame(plain_output, plain_size, frame);
    if (decoded != LocalTransportFrameStatus::ok) {
        local_transport_wipe_bytes(plain_output, plain_output_capacity);
        *frame = {};
        return LocalTransportFrameAeadStatus::invalid_frame;
    }
    return LocalTransportFrameAeadStatus::ok;
}

bool local_transport_reassembly_init(
    LocalTransportReassemblyState* state,
    uint8_t* buffer,
    size_t buffer_capacity,
    size_t line_cap)
{
    if (state == nullptr || buffer == nullptr || buffer_capacity == 0 || line_cap == 0) {
        return false;
    }
    *state = {};
    state->buffer = buffer;
    state->buffer_capacity = buffer_capacity;
    state->line_cap = line_cap;
    local_transport_wipe_bytes(buffer, buffer_capacity);
    return true;
}

void local_transport_reassembly_reset(LocalTransportReassemblyState* state)
{
    if (state == nullptr) {
        return;
    }
    uint8_t* const buffer = state->buffer;
    const size_t buffer_capacity = state->buffer_capacity;
    const size_t line_cap = state->line_cap;
    local_transport_wipe_bytes(buffer, buffer_capacity);
    *state = {};
    state->buffer = buffer;
    state->buffer_capacity = buffer_capacity;
    state->line_cap = line_cap;
}

LocalTransportReassemblyStatus local_transport_reassembly_accept(
    LocalTransportReassemblyState* state,
    const LocalTransportPlainFrame& frame,
    size_t* out_line_size)
{
    if (out_line_size != nullptr) {
        *out_line_size = 0;
    }
    if (state == nullptr || out_line_size == nullptr ||
        state->buffer == nullptr || state->buffer_capacity == 0 ||
        state->line_cap == 0) {
        return LocalTransportReassemblyStatus::invalid_argument;
    }

    if (validate_plain_frame(frame) != LocalTransportFrameStatus::ok ||
        frame.type != kLocalTransportFrameTypeProtocolLineFragment) {
        local_transport_reassembly_reset(state);
        return LocalTransportReassemblyStatus::invalid_frame;
    }

    if (frame.total_len == 0 ||
        frame.total_len > state->line_cap ||
        frame.total_len > state->buffer_capacity) {
        local_transport_reassembly_reset(state);
        return LocalTransportReassemblyStatus::line_too_large;
    }

    if (!state->active) {
        if (frame.sequence != 0) {
            local_transport_reassembly_reset(state);
            return LocalTransportReassemblyStatus::sequence_mismatch;
        }
        state->active = true;
        state->total_len = frame.total_len;
        state->received_len = 0;
        state->next_sequence = 0;
    } else if (frame.total_len != state->total_len) {
        local_transport_reassembly_reset(state);
        return LocalTransportReassemblyStatus::total_length_mismatch;
    }

    if (frame.sequence != state->next_sequence) {
        local_transport_reassembly_reset(state);
        return LocalTransportReassemblyStatus::sequence_mismatch;
    }
    if (frame.payload_len > state->total_len - state->received_len) {
        local_transport_reassembly_reset(state);
        return LocalTransportReassemblyStatus::payload_length_mismatch;
    }

    for (size_t index = 0; index < frame.payload_len; ++index) {
        state->buffer[state->received_len + index] = frame.payload[index];
    }
    state->received_len += static_cast<uint32_t>(frame.payload_len);
    if (state->next_sequence == UINT16_MAX &&
        (state->received_len < state->total_len ||
         (frame.flags & kLocalTransportFrameFlagLast) == 0)) {
        local_transport_reassembly_reset(state);
        return LocalTransportReassemblyStatus::sequence_mismatch;
    }
    ++state->next_sequence;

    if ((frame.flags & kLocalTransportFrameFlagLast) == 0) {
        return LocalTransportReassemblyStatus::in_progress;
    }

    if (state->received_len != state->total_len) {
        local_transport_reassembly_reset(state);
        return LocalTransportReassemblyStatus::payload_length_mismatch;
    }

    *out_line_size = state->received_len;
    state->active = false;
    state->total_len = 0;
    state->received_len = 0;
    state->next_sequence = 0;
    return LocalTransportReassemblyStatus::complete;
}

}  // namespace signing
