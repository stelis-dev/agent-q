#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_TRANSPORT_DIR="${COMMON_ROOT}/transport"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/local-transport-noise.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/local_transport_noise_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "local_transport_noise.cpp"

namespace {

struct FakeCryptoContext {
    uint8_t random_seed = 0xA0;
};

void expect(bool condition, const char* message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        _Exit(1);
    }
}

void dump_hex(const char* label, const uint8_t* bytes, size_t len)
{
    fprintf(stderr, "%s = ", label);
    for (size_t index = 0; index < len; ++index) {
        fprintf(stderr, "0x%02x%s", bytes[index], index + 1 == len ? "" : ", ");
    }
    fprintf(stderr, "\n");
}

void expect_bytes(
    const uint8_t* actual,
    const uint8_t* expected,
    size_t len,
    const char* label)
{
    if (memcmp(actual, expected, len) != 0) {
        dump_hex(label, actual, len);
        expect(false, label);
    }
}

void absorb(uint8_t output[signing::kLocalTransportCryptoHashBytes], const uint8_t* data, size_t len, size_t& cursor)
{
    for (size_t index = 0; index < len; ++index, ++cursor) {
        const uint8_t value = data[index];
        output[cursor % signing::kLocalTransportCryptoHashBytes] =
            static_cast<uint8_t>(
                output[cursor % signing::kLocalTransportCryptoHashBytes] + value + cursor);
        output[(cursor * 7) % signing::kLocalTransportCryptoHashBytes] ^=
            static_cast<uint8_t>(value + 0x5A);
    }
}

bool fake_random(uint8_t* output, size_t output_len, void* context)
{
    auto* fake = static_cast<FakeCryptoContext*>(context);
    if (output == nullptr || fake == nullptr) {
        return false;
    }
    for (size_t index = 0; index < output_len; ++index) {
        output[index] = static_cast<uint8_t>(fake->random_seed + index);
    }
    fake->random_seed = static_cast<uint8_t>(fake->random_seed + 0x31);
    return true;
}

bool fake_public_key(
    uint8_t output[signing::kLocalTransportCryptoKeyBytes],
    const uint8_t secret[signing::kLocalTransportCryptoKeyBytes],
    void*)
{
    if (output == nullptr || secret == nullptr) {
        return false;
    }
    for (size_t index = 0; index < signing::kLocalTransportCryptoKeyBytes; ++index) {
        output[index] = static_cast<uint8_t>(secret[index] ^ 0x55);
    }
    return true;
}

bool fake_shared_secret(
    uint8_t output[signing::kLocalTransportCryptoKeyBytes],
    const uint8_t secret[signing::kLocalTransportCryptoKeyBytes],
    const uint8_t public_key[signing::kLocalTransportCryptoKeyBytes],
    void*)
{
    if (output == nullptr || secret == nullptr || public_key == nullptr) {
        return false;
    }
    for (size_t index = 0; index < signing::kLocalTransportCryptoKeyBytes; ++index) {
        output[index] =
            static_cast<uint8_t>(secret[index] ^ public_key[31 - index] ^ 0xA5);
    }
    return true;
}

bool fake_sha256(
    const signing::LocalTransportCryptoBuffer* parts,
    size_t part_count,
    uint8_t output[signing::kLocalTransportCryptoHashBytes],
    void*)
{
    if (parts == nullptr || output == nullptr) {
        return false;
    }
    for (size_t index = 0; index < signing::kLocalTransportCryptoHashBytes; ++index) {
        output[index] = static_cast<uint8_t>(0x30 + index);
    }
    size_t cursor = 0;
    for (size_t part_index = 0; part_index < part_count; ++part_index) {
        if (parts[part_index].length > 0 && parts[part_index].data == nullptr) {
            return false;
        }
        absorb(output, parts[part_index].data, parts[part_index].length, cursor);
    }
    return true;
}

bool fake_hmac_sha256(
    const uint8_t* key,
    size_t key_len,
    const signing::LocalTransportCryptoBuffer* parts,
    size_t part_count,
    uint8_t output[signing::kLocalTransportCryptoHashBytes],
    void*)
{
    if ((key_len > 0 && key == nullptr) || parts == nullptr || output == nullptr) {
        return false;
    }
    for (size_t index = 0; index < signing::kLocalTransportCryptoHashBytes; ++index) {
        output[index] = static_cast<uint8_t>(0x90 + index);
    }
    size_t cursor = 0;
    absorb(output, key, key_len, cursor);
    for (size_t part_index = 0; part_index < part_count; ++part_index) {
        if (parts[part_index].length > 0 && parts[part_index].data == nullptr) {
            return false;
        }
        absorb(output, parts[part_index].data, parts[part_index].length, cursor);
    }
    return true;
}

void fake_tag(
    const uint8_t key[signing::kLocalTransportCryptoKeyBytes],
    const uint8_t nonce[signing::kLocalTransportCryptoNonceBytes],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* body,
    size_t body_len,
    uint8_t tag[signing::kLocalTransportCryptoTagBytes])
{
    for (size_t index = 0; index < signing::kLocalTransportCryptoTagBytes; ++index) {
        uint8_t value = static_cast<uint8_t>(key[index] ^ nonce[index % signing::kLocalTransportCryptoNonceBytes] ^ 0xC3);
        if (aad_len > 0) {
            value ^= aad[(index * 5) % aad_len];
        }
        if (body_len > 0) {
            value ^= body[(index * 3) % body_len];
        }
        tag[index] = value;
    }
}

bool fake_encrypt(
    const uint8_t key[signing::kLocalTransportCryptoKeyBytes],
    const uint8_t nonce[signing::kLocalTransportCryptoNonceBytes],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t tag[signing::kLocalTransportCryptoTagBytes],
    void*)
{
    if (key == nullptr || nonce == nullptr || (aad_len > 0 && aad == nullptr) ||
        (plaintext_len > 0 && plaintext == nullptr) ||
        (plaintext_len > 0 && ciphertext == nullptr) || tag == nullptr) {
        return false;
    }
    for (size_t index = 0; index < plaintext_len; ++index) {
        ciphertext[index] = static_cast<uint8_t>(
            plaintext[index] ^ key[index % signing::kLocalTransportCryptoKeyBytes] ^
            nonce[index % signing::kLocalTransportCryptoNonceBytes] ^
            aad[index % aad_len]);
    }
    fake_tag(key, nonce, aad, aad_len, ciphertext, plaintext_len, tag);
    return true;
}

bool fake_decrypt(
    const uint8_t key[signing::kLocalTransportCryptoKeyBytes],
    const uint8_t nonce[signing::kLocalTransportCryptoNonceBytes],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[signing::kLocalTransportCryptoTagBytes],
    uint8_t* plaintext,
    void*)
{
    if (key == nullptr || nonce == nullptr || (aad_len > 0 && aad == nullptr) ||
        (ciphertext_len > 0 && ciphertext == nullptr) ||
        (ciphertext_len > 0 && plaintext == nullptr) || tag == nullptr) {
        return false;
    }
    uint8_t expected[signing::kLocalTransportCryptoTagBytes] = {};
    fake_tag(key, nonce, aad, aad_len, ciphertext, ciphertext_len, expected);
    if (memcmp(expected, tag, sizeof(expected)) != 0) {
        return false;
    }
    for (size_t index = 0; index < ciphertext_len; ++index) {
        plaintext[index] = static_cast<uint8_t>(
            ciphertext[index] ^ key[index % signing::kLocalTransportCryptoKeyBytes] ^
            nonce[index % signing::kLocalTransportCryptoNonceBytes] ^
            aad[index % aad_len]);
    }
    return true;
}

signing::LocalTransportCryptoOps fake_ops(FakeCryptoContext* context)
{
    return {
        fake_random,
        fake_public_key,
        fake_shared_secret,
        fake_sha256,
        fake_hmac_sha256,
        fake_encrypt,
        fake_decrypt,
        context,
    };
}

void fill_incrementing(uint8_t* output, size_t output_len, uint8_t first)
{
    for (size_t index = 0; index < output_len; ++index) {
        output[index] = static_cast<uint8_t>(first + index);
    }
}

}  // namespace

int main()
{
    FakeCryptoContext context;
    const signing::LocalTransportCryptoOps ops = fake_ops(&context);

    const char prologue[] =
        "Agent-Q local transport pairing v1\0"
        "aqlt:1?k=ble&svc=a6e31d1051a14f7a9b0a0a1c00000001&idfp=0102030405060708&non=1112131415161718&exp=120";

    uint8_t gateway_ephemeral[signing::kLocalTransportNoiseStaticKeyBytes] = {};
    uint8_t gateway_static_secret[signing::kLocalTransportNoiseStaticKeyBytes] = {};
    uint8_t gateway_static_public[signing::kLocalTransportNoiseStaticKeyBytes] = {};
    uint8_t device_static_secret[signing::kLocalTransportNoiseStaticKeyBytes] = {};
    uint8_t device_static_public[signing::kLocalTransportNoiseStaticKeyBytes] = {};
    uint8_t idfp[signing::kLocalTransportIdentityFingerprintBytes] = {};
    fill_incrementing(gateway_ephemeral, sizeof(gateway_ephemeral), 0x11);
    fill_incrementing(gateway_static_secret, sizeof(gateway_static_secret), 0x21);
    expect(fake_public_key(gateway_static_public, gateway_static_secret, nullptr), "gateway static public");
    fill_incrementing(device_static_secret, sizeof(device_static_secret), 0x31);
    fill_incrementing(device_static_public, sizeof(device_static_public), 0x41);
    fill_incrementing(idfp, sizeof(idfp), 0x51);

    signing::LocalTransportNoiseResponderState responder = {};
    uint8_t message2[signing::kLocalTransportNoiseMessage2Bytes] = {};
    size_t message2_len = 0;
    expect(signing::local_transport_noise_responder_write_message2(
               &responder,
               reinterpret_cast<const uint8_t*>(prologue),
               sizeof(prologue) - 1,
               device_static_secret,
               device_static_public,
               idfp,
               gateway_ephemeral,
               sizeof(gateway_ephemeral),
               message2,
               sizeof(message2),
               &message2_len,
               ops) == signing::LocalTransportNoiseStatus::ok,
           "responder writes message2");
    expect(message2_len == signing::kLocalTransportNoiseMessage2Bytes, "message2 length");

    uint8_t expected_message2[signing::kLocalTransportNoiseMessage2Bytes] = {
        0xf5, 0xf4, 0xf7, 0xf6, 0xf1, 0xf0, 0xf3, 0xf2, 0xfd, 0xfc, 0xff, 0xfe,
        0xf9, 0xf8, 0xfb, 0xfa, 0xe5, 0xe4, 0xe7, 0xe6, 0xe1, 0xe0, 0xe3, 0xe2,
        0xed, 0xec, 0xef, 0xee, 0xe9, 0xe8, 0xeb, 0xea, 0x3f, 0x3a, 0x29, 0x51,
        0xd9, 0x85, 0xf3, 0x13, 0x09, 0x6b, 0xb7, 0x1c, 0xd3, 0xae, 0x5f, 0x28,
        0x81, 0x2c, 0x87, 0xc5, 0x59, 0x95, 0x0b, 0xe3, 0xf3, 0x6b, 0x0d, 0x7c,
        0x99, 0x68, 0x2b, 0x90, 0x82, 0x2b, 0x42, 0xae, 0x10, 0xe3, 0xae, 0x99,
        0x70, 0x53, 0xca, 0x35, 0xf8, 0x0f, 0xfc, 0xce, 0x11, 0x3e, 0xf1, 0x2a,
        0xb3, 0x1e, 0x19, 0xb3, 0x92, 0xcd, 0x22, 0xad, 0x24, 0x07, 0x5a, 0x6b,
        0x6a, 0xdc, 0xf0, 0xfd, 0x72, 0xb0, 0x08, 0x7f,
    };
    expect_bytes(message2, expected_message2, sizeof(expected_message2), "message2 vector");

    uint8_t message3[signing::kLocalTransportNoiseMessage3Bytes] = {};
    size_t offset = 0;
    size_t written = 0;
    expect(signing::encrypt_and_hash(
               ops,
               &responder,
               gateway_static_public,
               sizeof(gateway_static_public),
               message3 + offset,
               sizeof(message3) - offset,
               &written),
           "test constructs message3 static payload");
    offset += written;

    uint8_t dh[signing::kLocalTransportCryptoKeyBytes] = {};
    expect(fake_shared_secret(
               dh,
               responder.device_ephemeral_secret,
               gateway_static_public,
               nullptr),
           "test constructs se");
    expect(signing::mix_key(ops, &responder, dh), "test mixes se");
    signing::local_transport_wipe_bytes(dh, sizeof(dh));

    uint8_t empty = 0;
    expect(signing::encrypt_and_hash(
               ops,
               &responder,
               &empty,
               0,
               message3 + offset,
               sizeof(message3) - offset,
               &written),
           "test constructs message3 final tag");
    offset += written;
    expect(offset == sizeof(message3), "message3 length");

    uint8_t expected_message3[signing::kLocalTransportNoiseMessage3Bytes] = {
        0x96, 0x7c, 0xe3, 0xcb, 0x2d, 0xa4, 0xf7, 0xa7, 0x58, 0x68, 0x7b, 0x91,
        0x56, 0xa2, 0x0b, 0x79, 0x54, 0x70, 0xfa, 0x4e, 0x52, 0x53, 0x42, 0x46,
        0x0a, 0xb9, 0xb2, 0xb7, 0x7b, 0x99, 0xf2, 0x12, 0xb7, 0xb3, 0x41, 0xdf,
        0xf3, 0xb8, 0x45, 0xe2, 0xed, 0xc5, 0x41, 0x56, 0x99, 0xc3, 0x49, 0x46,
        0x8b, 0x06, 0x39, 0xf0, 0x64, 0xab, 0xdf, 0x1f, 0xf6, 0x88, 0x67, 0x8e,
        0x9e, 0x4e, 0xd3, 0xa5,
    };
    expect_bytes(message3, expected_message3, sizeof(expected_message3), "message3 vector");

    signing::LocalTransportNoiseResponderState verifier = {};
    message2_len = 0;
    context.random_seed = 0xA0;
    expect(signing::local_transport_noise_responder_write_message2(
               &verifier,
               reinterpret_cast<const uint8_t*>(prologue),
               sizeof(prologue) - 1,
               device_static_secret,
               device_static_public,
               idfp,
               gateway_ephemeral,
               sizeof(gateway_ephemeral),
               message2,
               sizeof(message2),
               &message2_len,
               ops) == signing::LocalTransportNoiseStatus::ok,
           "verifier writes message2");

    uint8_t returned_gateway_static[signing::kLocalTransportNoiseStaticKeyBytes] = {};
    signing::LocalTransportNoiseSessionKeys keys = {};
    expect(signing::local_transport_noise_responder_read_message3(
               &verifier,
               message3,
               sizeof(message3),
               returned_gateway_static,
               &keys,
               ops) == signing::LocalTransportNoiseStatus::ok,
           "verifier reads message3");
    expect(memcmp(returned_gateway_static, gateway_static_public, sizeof(returned_gateway_static)) == 0,
           "gateway static returned");

    uint8_t expected_handshake_hash[signing::kLocalTransportNoiseHandshakeHashBytes] = {
        0x64, 0xf1, 0x7e, 0xc3, 0xf0, 0x77, 0x2c, 0x7d, 0x1a, 0xc3, 0x1e, 0x1f,
        0xa2, 0xb8, 0x28, 0xf1, 0x0a, 0xb3, 0x6e, 0xef, 0x52, 0xc3, 0xfe, 0x65,
        0xde, 0x3b, 0xf6, 0x1a, 0x28, 0x5b, 0x76, 0x89,
    };
    uint8_t expected_gateway_to_device[signing::kLocalTransportCryptoKeyBytes] = {
        0xc4, 0x34, 0xb2, 0x98, 0xb6, 0xc4, 0xa2, 0x88, 0x96, 0x44, 0x32, 0xf0,
        0x36, 0x74, 0x9a, 0x58, 0xb6, 0x78, 0xf2, 0xa8, 0x16, 0x08, 0xf2, 0x88,
        0xb6, 0x6c, 0xc2, 0x08, 0x76, 0xdc, 0xba, 0x60,
    };
    uint8_t expected_device_to_gateway[signing::kLocalTransportCryptoKeyBytes] = {
        0xe2, 0x6b, 0x72, 0x4d, 0x40, 0xaf, 0xe6, 0xb5, 0x44, 0x03, 0x2a, 0x3d,
        0xe8, 0xdf, 0x5e, 0x19, 0x8c, 0x43, 0x02, 0xe1, 0xd0, 0x37, 0x06, 0x19,
        0x34, 0xab, 0x8a, 0x09, 0x18, 0xd7, 0xee, 0x9d,
    };
    expect_bytes(keys.handshake_hash, expected_handshake_hash, sizeof(expected_handshake_hash),
                 "handshake hash vector");
    expect_bytes(keys.gateway_to_device, expected_gateway_to_device, sizeof(expected_gateway_to_device),
                 "gateway-to-device key vector");
    expect_bytes(keys.device_to_gateway, expected_device_to_gateway, sizeof(expected_device_to_gateway),
                 "device-to-gateway key vector");
    return 0;
}
CPP

c++ -std=c++17 \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_TRANSPORT_DIR}" \
  "${COMMON_TRANSPORT_DIR}/local_transport_crypto.cpp" \
  "${TMP_DIR}/local_transport_noise_test.cpp" \
  -o "${TMP_DIR}/local_transport_noise_test"

"${TMP_DIR}/local_transport_noise_test"
