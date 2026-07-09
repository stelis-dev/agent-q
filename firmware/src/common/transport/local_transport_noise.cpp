#include "transport/local_transport_noise.h"

#include <string.h>

namespace signing {
namespace {

constexpr char kNoiseProtocolName[] = "Noise_XX_25519_AESGCM_SHA256";
constexpr size_t kNoiseProtocolNameBytes = sizeof(kNoiseProtocolName) - 1;

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

bool is_all_zero(const uint8_t* bytes, size_t bytes_len)
{
    if (bytes == nullptr) {
        return true;
    }
    uint8_t accumulator = 0;
    for (size_t index = 0; index < bytes_len; ++index) {
        accumulator |= bytes[index];
    }
    return accumulator == 0;
}

bool hash_parts(
    const LocalTransportCryptoOps& ops,
    const LocalTransportCryptoBuffer* parts,
    size_t part_count,
    uint8_t output[kLocalTransportCryptoHashBytes])
{
    return ops.sha256 != nullptr &&
           ops.sha256(parts, part_count, output, ops.context);
}

bool hmac_parts(
    const LocalTransportCryptoOps& ops,
    const uint8_t* key,
    size_t key_len,
    const LocalTransportCryptoBuffer* parts,
    size_t part_count,
    uint8_t output[kLocalTransportCryptoHashBytes])
{
    return ops.hmac_sha256 != nullptr &&
           ops.hmac_sha256(key, key_len, parts, part_count, output, ops.context);
}

bool hkdf2(
    const LocalTransportCryptoOps& ops,
    const uint8_t salt[kLocalTransportCryptoHashBytes],
    const uint8_t* input_key_material,
    size_t input_key_material_len,
    uint8_t output1[kLocalTransportCryptoHashBytes],
    uint8_t output2[kLocalTransportCryptoHashBytes])
{
    uint8_t temp_key[kLocalTransportCryptoHashBytes] = {};
    const LocalTransportCryptoBuffer ikm_part{input_key_material, input_key_material_len};
    if (!hmac_parts(ops, salt, kLocalTransportCryptoHashBytes, &ikm_part, 1, temp_key)) {
        local_transport_wipe_bytes(temp_key, sizeof(temp_key));
        return false;
    }

    const uint8_t one = 0x01;
    const LocalTransportCryptoBuffer output1_parts[] = {
        {&one, 1},
    };
    if (!hmac_parts(ops, temp_key, sizeof(temp_key), output1_parts, 1, output1)) {
        local_transport_wipe_bytes(temp_key, sizeof(temp_key));
        return false;
    }

    const uint8_t two = 0x02;
    const LocalTransportCryptoBuffer output2_parts[] = {
        {output1, kLocalTransportCryptoHashBytes},
        {&two, 1},
    };
    const bool ok =
        hmac_parts(ops, temp_key, sizeof(temp_key), output2_parts, 2, output2);
    local_transport_wipe_bytes(temp_key, sizeof(temp_key));
    return ok;
}

bool mix_hash(
    const LocalTransportCryptoOps& ops,
    uint8_t handshake_hash[kLocalTransportCryptoHashBytes],
    const uint8_t* data,
    size_t data_len)
{
    uint8_t next[kLocalTransportCryptoHashBytes] = {};
    const LocalTransportCryptoBuffer parts[] = {
        {handshake_hash, kLocalTransportCryptoHashBytes},
        {data, data_len},
    };
    if (!hash_parts(ops, parts, 2, next)) {
        local_transport_wipe_bytes(next, sizeof(next));
        return false;
    }
    memcpy(handshake_hash, next, kLocalTransportCryptoHashBytes);
    local_transport_wipe_bytes(next, sizeof(next));
    return true;
}

bool mix_key(
    const LocalTransportCryptoOps& ops,
    LocalTransportNoiseResponderState* state,
    const uint8_t input_key_material[kLocalTransportCryptoKeyBytes])
{
    uint8_t next_chaining_key[kLocalTransportCryptoHashBytes] = {};
    uint8_t temp_key[kLocalTransportCryptoHashBytes] = {};
    if (!hkdf2(
            ops,
            state->chaining_key,
            input_key_material,
            kLocalTransportCryptoKeyBytes,
            next_chaining_key,
            temp_key)) {
        local_transport_wipe_bytes(next_chaining_key, sizeof(next_chaining_key));
        local_transport_wipe_bytes(temp_key, sizeof(temp_key));
        return false;
    }
    memcpy(state->chaining_key, next_chaining_key, kLocalTransportCryptoHashBytes);
    memcpy(state->cipher_key, temp_key, kLocalTransportCryptoKeyBytes);
    state->has_key = true;
    state->nonce = 0;
    local_transport_wipe_bytes(next_chaining_key, sizeof(next_chaining_key));
    local_transport_wipe_bytes(temp_key, sizeof(temp_key));
    return true;
}

bool noise_nonce(uint64_t nonce_value, uint8_t output[kLocalTransportCryptoNonceBytes])
{
    if (nonce_value == UINT64_MAX) {
        return false;
    }
    output[0] = 0;
    output[1] = 0;
    output[2] = 0;
    output[3] = 0;
    write_u64_be(nonce_value, &output[4]);
    return true;
}

bool encrypt_and_hash(
    const LocalTransportCryptoOps& ops,
    LocalTransportNoiseResponderState* state,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_len)
{
    if (output_len != nullptr) {
        *output_len = 0;
    }
    if (state == nullptr || output == nullptr || output_len == nullptr ||
        output_capacity < plaintext_len + kLocalTransportCryptoTagBytes ||
        plaintext == nullptr) {
        return false;
    }
    if (!state->has_key) {
        if (output_capacity < plaintext_len) {
            return false;
        }
        memcpy(output, plaintext, plaintext_len);
        *output_len = plaintext_len;
        return mix_hash(ops, state->handshake_hash, output, *output_len);
    }

    uint8_t nonce[kLocalTransportCryptoNonceBytes] = {};
    if (!noise_nonce(state->nonce, nonce)) {
        local_transport_wipe_bytes(nonce, sizeof(nonce));
        return false;
    }
    if (!ops.aes256_gcm_encrypt(
            state->cipher_key,
            nonce,
            state->handshake_hash,
            kLocalTransportCryptoHashBytes,
            plaintext,
            plaintext_len,
            output,
            output + plaintext_len,
            ops.context)) {
        local_transport_wipe_bytes(nonce, sizeof(nonce));
        return false;
    }
    ++state->nonce;
    *output_len = plaintext_len + kLocalTransportCryptoTagBytes;
    const bool ok = mix_hash(ops, state->handshake_hash, output, *output_len);
    local_transport_wipe_bytes(nonce, sizeof(nonce));
    return ok;
}

bool decrypt_and_hash(
    const LocalTransportCryptoOps& ops,
    LocalTransportNoiseResponderState* state,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t plaintext_capacity,
    size_t* plaintext_len)
{
    if (plaintext_len != nullptr) {
        *plaintext_len = 0;
    }
    if (state == nullptr || ciphertext == nullptr || plaintext_len == nullptr) {
        return false;
    }
    if (!state->has_key) {
        if (plaintext == nullptr || plaintext_capacity < ciphertext_len) {
            return false;
        }
        memcpy(plaintext, ciphertext, ciphertext_len);
        *plaintext_len = ciphertext_len;
        return mix_hash(ops, state->handshake_hash, ciphertext, ciphertext_len);
    }
    if (ciphertext_len < kLocalTransportCryptoTagBytes) {
        return false;
    }
    const size_t body_len = ciphertext_len - kLocalTransportCryptoTagBytes;
    if ((body_len > 0 && plaintext == nullptr) || plaintext_capacity < body_len) {
        return false;
    }

    uint8_t nonce[kLocalTransportCryptoNonceBytes] = {};
    if (!noise_nonce(state->nonce, nonce)) {
        local_transport_wipe_bytes(nonce, sizeof(nonce));
        return false;
    }
    const bool decrypted = ops.aes256_gcm_decrypt(
        state->cipher_key,
        nonce,
        state->handshake_hash,
        kLocalTransportCryptoHashBytes,
        ciphertext,
        body_len,
        ciphertext + body_len,
        plaintext,
        ops.context);
    if (!decrypted) {
        local_transport_wipe_bytes(nonce, sizeof(nonce));
        if (plaintext != nullptr) {
            local_transport_wipe_bytes(plaintext, plaintext_capacity);
        }
        return false;
    }
    ++state->nonce;
    *plaintext_len = body_len;
    const bool ok = mix_hash(ops, state->handshake_hash, ciphertext, ciphertext_len);
    local_transport_wipe_bytes(nonce, sizeof(nonce));
    return ok;
}

bool initialize_xx(
    LocalTransportNoiseResponderState* state,
    const uint8_t* prologue,
    size_t prologue_len,
    const LocalTransportCryptoOps& ops)
{
    *state = {};
    if (kNoiseProtocolNameBytes <= kLocalTransportCryptoHashBytes) {
        memcpy(state->handshake_hash, kNoiseProtocolName, kNoiseProtocolNameBytes);
    } else {
        const LocalTransportCryptoBuffer protocol_part{
            reinterpret_cast<const uint8_t*>(kNoiseProtocolName),
            kNoiseProtocolNameBytes,
        };
        if (!hash_parts(ops, &protocol_part, 1, state->handshake_hash)) {
            return false;
        }
    }
    memcpy(state->chaining_key, state->handshake_hash, kLocalTransportCryptoHashBytes);
    state->has_key = false;
    state->nonce = 0;
    return mix_hash(ops, state->handshake_hash, prologue, prologue_len);
}

bool split_keys(
    const LocalTransportCryptoOps& ops,
    const LocalTransportNoiseResponderState* state,
    LocalTransportNoiseSessionKeys* session_keys)
{
    uint8_t empty = 0;
    const bool ok = hkdf2(
        ops,
        state->chaining_key,
        &empty,
        0,
        session_keys->gateway_to_device,
        session_keys->device_to_gateway);
    return ok;
}

}  // namespace

void local_transport_noise_clear_responder_state(LocalTransportNoiseResponderState* state)
{
    if (state == nullptr) {
        return;
    }
    local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(state), sizeof(*state));
}

LocalTransportNoiseStatus local_transport_noise_responder_write_message2(
    LocalTransportNoiseResponderState* state,
    const uint8_t* prologue,
    size_t prologue_len,
    const uint8_t device_static_secret[kLocalTransportNoiseStaticKeyBytes],
    const uint8_t device_static_public[kLocalTransportNoiseStaticKeyBytes],
    const uint8_t device_identity_fingerprint[kLocalTransportIdentityFingerprintBytes],
    const uint8_t* message1,
    size_t message1_len,
    uint8_t* message2,
    size_t message2_capacity,
    size_t* message2_len,
    const LocalTransportCryptoOps& ops)
{
    if (message2_len != nullptr) {
        *message2_len = 0;
    }
    if (state == nullptr || prologue == nullptr || prologue_len == 0 ||
        device_static_secret == nullptr || device_static_public == nullptr ||
        device_identity_fingerprint == nullptr || message1 == nullptr ||
        message2 == nullptr || message2_len == nullptr ||
        !local_transport_crypto_ops_valid(ops)) {
        return LocalTransportNoiseStatus::invalid_argument;
    }
    if (message1_len != kLocalTransportNoiseMessage1Bytes) {
        return LocalTransportNoiseStatus::invalid_length;
    }
    if (message2_capacity < kLocalTransportNoiseMessage2Bytes) {
        return LocalTransportNoiseStatus::output_too_small;
    }

    local_transport_noise_clear_responder_state(state);
    if (!initialize_xx(state, prologue, prologue_len, ops)) {
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::crypto_error;
    }

    memcpy(state->gateway_ephemeral_public, message1, kLocalTransportNoiseStaticKeyBytes);
    if (!mix_hash(
            ops,
            state->handshake_hash,
            state->gateway_ephemeral_public,
            sizeof(state->gateway_ephemeral_public))) {
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::crypto_error;
    }

    if (!ops.random_bytes(
            state->device_ephemeral_secret,
            sizeof(state->device_ephemeral_secret),
            ops.context) ||
        !ops.x25519_public_key(
            state->device_ephemeral_public,
            state->device_ephemeral_secret,
            ops.context)) {
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::crypto_error;
    }

    size_t offset = 0;
    memcpy(message2 + offset, state->device_ephemeral_public, sizeof(state->device_ephemeral_public));
    offset += sizeof(state->device_ephemeral_public);
    if (!mix_hash(
            ops,
            state->handshake_hash,
            state->device_ephemeral_public,
            sizeof(state->device_ephemeral_public))) {
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::crypto_error;
    }

    uint8_t dh[kLocalTransportCryptoKeyBytes] = {};
    if (!ops.x25519_shared_secret(
            dh,
            state->device_ephemeral_secret,
            state->gateway_ephemeral_public,
            ops.context) ||
        is_all_zero(dh, sizeof(dh)) ||
        !mix_key(ops, state, dh)) {
        local_transport_wipe_bytes(dh, sizeof(dh));
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::crypto_error;
    }
    local_transport_wipe_bytes(dh, sizeof(dh));

    size_t written = 0;
    if (!encrypt_and_hash(
            ops,
            state,
            device_static_public,
            kLocalTransportNoiseStaticKeyBytes,
            message2 + offset,
            message2_capacity - offset,
            &written)) {
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::crypto_error;
    }
    offset += written;

    if (!ops.x25519_shared_secret(
            dh,
            device_static_secret,
            state->gateway_ephemeral_public,
            ops.context) ||
        is_all_zero(dh, sizeof(dh)) ||
        !mix_key(ops, state, dh)) {
        local_transport_wipe_bytes(dh, sizeof(dh));
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::crypto_error;
    }
    local_transport_wipe_bytes(dh, sizeof(dh));

    if (!encrypt_and_hash(
            ops,
            state,
            device_identity_fingerprint,
            kLocalTransportIdentityFingerprintBytes,
            message2 + offset,
            message2_capacity - offset,
            &written)) {
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::crypto_error;
    }
    offset += written;

    state->active = true;
    *message2_len = offset;
    return offset == kLocalTransportNoiseMessage2Bytes
               ? LocalTransportNoiseStatus::ok
               : LocalTransportNoiseStatus::crypto_error;
}

LocalTransportNoiseStatus local_transport_noise_responder_read_message3(
    LocalTransportNoiseResponderState* state,
    const uint8_t* message3,
    size_t message3_len,
    uint8_t gateway_static_public[kLocalTransportNoiseStaticKeyBytes],
    LocalTransportNoiseSessionKeys* session_keys,
    const LocalTransportCryptoOps& ops)
{
    if (gateway_static_public != nullptr) {
        memset(gateway_static_public, 0, kLocalTransportNoiseStaticKeyBytes);
    }
    if (session_keys != nullptr) {
        local_transport_noise_clear_session_keys(session_keys);
    }
    if (state == nullptr || !state->active || message3 == nullptr ||
        gateway_static_public == nullptr || session_keys == nullptr ||
        !local_transport_crypto_ops_valid(ops)) {
        return LocalTransportNoiseStatus::invalid_argument;
    }
    if (message3_len != kLocalTransportNoiseMessage3Bytes) {
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::invalid_length;
    }

    size_t plaintext_len = 0;
    if (!decrypt_and_hash(
            ops,
            state,
            message3,
            kLocalTransportNoiseStaticKeyBytes + kLocalTransportCryptoTagBytes,
            gateway_static_public,
            kLocalTransportNoiseStaticKeyBytes,
            &plaintext_len) ||
        plaintext_len != kLocalTransportNoiseStaticKeyBytes) {
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::authentication_failed;
    }

    uint8_t dh[kLocalTransportCryptoKeyBytes] = {};
    if (!ops.x25519_shared_secret(
            dh,
            state->device_ephemeral_secret,
            gateway_static_public,
            ops.context) ||
        is_all_zero(dh, sizeof(dh)) ||
        !mix_key(ops, state, dh)) {
        local_transport_wipe_bytes(dh, sizeof(dh));
        local_transport_noise_clear_responder_state(state);
        return LocalTransportNoiseStatus::crypto_error;
    }
    local_transport_wipe_bytes(dh, sizeof(dh));

    uint8_t empty_plaintext[1] = {};
    if (!decrypt_and_hash(
            ops,
            state,
            message3 + kLocalTransportNoiseStaticKeyBytes + kLocalTransportCryptoTagBytes,
            kLocalTransportCryptoTagBytes,
            empty_plaintext,
            0,
            &plaintext_len) ||
        plaintext_len != 0) {
        local_transport_noise_clear_responder_state(state);
        local_transport_wipe_bytes(empty_plaintext, sizeof(empty_plaintext));
        return LocalTransportNoiseStatus::authentication_failed;
    }
    local_transport_wipe_bytes(empty_plaintext, sizeof(empty_plaintext));

    if (!split_keys(ops, state, session_keys)) {
        local_transport_noise_clear_responder_state(state);
        local_transport_noise_clear_session_keys(session_keys);
        return LocalTransportNoiseStatus::crypto_error;
    }
    memcpy(session_keys->handshake_hash, state->handshake_hash, kLocalTransportCryptoHashBytes);
    local_transport_noise_clear_responder_state(state);
    return LocalTransportNoiseStatus::ok;
}

void local_transport_noise_clear_session_keys(LocalTransportNoiseSessionKeys* keys)
{
    if (keys == nullptr) {
        return;
    }
    local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(keys), sizeof(*keys));
}

}  // namespace signing
