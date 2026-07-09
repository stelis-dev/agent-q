#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_local_transport_frame.sh

Compiles the current Agent-Q local transport plaintext frame codec with a host
C++ compiler. This test does not require ESP-IDF and does not depend on .WORK
paths.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_TRANSPORT_DIR="${REPO_ROOT}/firmware/src/common/transport"

for required in \
  "${COMMON_TRANSPORT_DIR}/local_transport_crypto.cpp" \
  "${COMMON_TRANSPORT_DIR}/local_transport_crypto.h" \
  "${COMMON_TRANSPORT_DIR}/local_transport_frame.cpp" \
  "${COMMON_TRANSPORT_DIR}/local_transport_frame.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/local-transport-frame.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/local_transport_frame_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "local_transport_frame.h"

namespace {

int failures = 0;
uint8_t last_aad[signing::kLocalTransportFrameAadBytes] = {};
size_t last_aad_len = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void expect_status(
    signing::LocalTransportFrameStatus actual,
    signing::LocalTransportFrameStatus expected,
    const char* label)
{
    if (actual != expected) {
        fprintf(
            stderr,
            "FAILED: %s (actual=%d expected=%d)\n",
            label,
            static_cast<int>(actual),
            static_cast<int>(expected));
        ++failures;
    }
}

void expect_reassembly_status(
    signing::LocalTransportReassemblyStatus actual,
    signing::LocalTransportReassemblyStatus expected,
    const char* label)
{
    if (actual != expected) {
        fprintf(
            stderr,
            "FAILED: %s (actual=%d expected=%d)\n",
            label,
            static_cast<int>(actual),
            static_cast<int>(expected));
        ++failures;
    }
}

bool fake_random(uint8_t*, size_t, void*) { return false; }
bool fake_x25519_public_key(uint8_t[signing::kLocalTransportCryptoKeyBytes], const uint8_t[signing::kLocalTransportCryptoKeyBytes], void*) { return false; }
bool fake_x25519_shared_secret(uint8_t[signing::kLocalTransportCryptoKeyBytes], const uint8_t[signing::kLocalTransportCryptoKeyBytes], const uint8_t[signing::kLocalTransportCryptoKeyBytes], void*) { return false; }
bool fake_sha256(const signing::LocalTransportCryptoBuffer*, size_t, uint8_t[signing::kLocalTransportCryptoHashBytes], void*) { return false; }
bool fake_hmac_sha256(const uint8_t*, size_t, const signing::LocalTransportCryptoBuffer*, size_t, uint8_t[signing::kLocalTransportCryptoHashBytes], void*) { return false; }
bool fake_encrypt(
    const uint8_t[signing::kLocalTransportCryptoKeyBytes],
    const uint8_t[signing::kLocalTransportCryptoNonceBytes],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t tag[signing::kLocalTransportCryptoTagBytes],
    void*)
{
    if (aad_len > sizeof(last_aad)) {
        return false;
    }
    memcpy(last_aad, aad, aad_len);
    last_aad_len = aad_len;
    for (size_t index = 0; index < plaintext_len; ++index) {
        ciphertext[index] = static_cast<uint8_t>(plaintext[index] ^ 0xA5);
    }
    for (size_t index = 0; index < signing::kLocalTransportCryptoTagBytes; ++index) {
        tag[index] = static_cast<uint8_t>(0xC0 + index);
    }
    return true;
}
bool fake_decrypt(
    const uint8_t[signing::kLocalTransportCryptoKeyBytes],
    const uint8_t[signing::kLocalTransportCryptoNonceBytes],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[signing::kLocalTransportCryptoTagBytes],
    uint8_t* plaintext,
    void*)
{
    if (aad_len > sizeof(last_aad)) {
        return false;
    }
    memcpy(last_aad, aad, aad_len);
    last_aad_len = aad_len;
    for (size_t index = 0; index < signing::kLocalTransportCryptoTagBytes; ++index) {
        if (tag[index] != static_cast<uint8_t>(0xC0 + index)) {
            return false;
        }
    }
    for (size_t index = 0; index < ciphertext_len; ++index) {
        plaintext[index] = static_cast<uint8_t>(ciphertext[index] ^ 0xA5);
    }
    return true;
}

const signing::LocalTransportCryptoOps fake_crypto_ops = {
    fake_random,
    fake_x25519_public_key,
    fake_x25519_shared_secret,
    fake_sha256,
    fake_hmac_sha256,
    fake_encrypt,
    fake_decrypt,
    nullptr,
};

}  // namespace

int main()
{
    size_t limit = 0;
    expect(signing::local_transport_fragment_payload_limit(509, &limit), "MTU 509 accepted");
    expect(limit == 480, "MTU 509 leaves 480-byte fragment payload");
    expect(signing::local_transport_fragment_payload_limit(52, &limit), "MTU 52 accepted");
    expect(limit == 23, "MTU 52 leaves 23-byte fragment payload");
    expect(!signing::local_transport_fragment_payload_limit(48, &limit), "small MTU rejected");
    expect(limit == 0, "rejected MTU clears limit");
    expect(!signing::local_transport_fragment_payload_limit(509, nullptr), "null limit rejected");

    uint8_t nonce[signing::kLocalTransportFrameNonceBytes] = {};
    expect(
        signing::local_transport_frame_nonce(0x0102030405060708ULL, nonce),
        "frame nonce builds");
    const uint8_t expected_nonce[] = {
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
    };
    expect(memcmp(nonce, expected_nonce, sizeof(expected_nonce)) == 0, "frame nonce bytes");
    expect(!signing::local_transport_frame_nonce(0, nullptr), "null nonce rejected");

    uint8_t aad[signing::kLocalTransportFrameAadBytes] = {};
    size_t aad_size = 0;
    expect(
        signing::local_transport_frame_aad(
            signing::LocalTransportFrameDirection::gateway_to_device,
            0x0102030405060708ULL,
            aad,
            sizeof(aad),
            &aad_size),
        "frame AAD builds");
    const uint8_t expected_aad[] = {
        'A', 'g', 'e', 'n', 't', '-', 'Q', ' ',
        'l', 'o', 'c', 'a', 'l', ' ',
        't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', ' ',
        'f', 'r', 'a', 'm', 'e', ' ', 'v', '1',
        0x00, 0x01,
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
    };
    expect(aad_size == sizeof(expected_aad), "frame AAD size");
    expect(memcmp(aad, expected_aad, sizeof(expected_aad)) == 0, "frame AAD bytes");
    expect(
        !signing::local_transport_frame_aad(
            signing::LocalTransportFrameDirection::device_to_gateway,
            0,
            aad,
            sizeof(aad) - 1,
            &aad_size),
        "small AAD output rejected");

    const uint8_t payload[] = {'h', 'e', 'l', 'l', 'o'};
    const signing::LocalTransportPlainFrame frame = {
        signing::kLocalTransportFrameTypeProtocolLineFragment,
        signing::kLocalTransportFrameFlagLast,
        2,
        sizeof(payload),
        payload,
        sizeof(payload),
    };
    uint8_t encoded[32] = {};
    size_t encoded_size = 0;
    expect_status(
        signing::local_transport_encode_plain_frame(
            frame,
            encoded,
            sizeof(encoded),
            &encoded_size),
        signing::LocalTransportFrameStatus::ok,
        "encode valid protocol fragment");
    const uint8_t expected[] = {
        0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05,
        'h', 'e', 'l', 'l', 'o',
    };
    expect(encoded_size == sizeof(expected), "encoded size");
    expect(memcmp(encoded, expected, sizeof(expected)) == 0, "encoded bytes");
    const size_t valid_encoded_size = encoded_size;

    signing::LocalTransportPlainFrame decoded = {};
    expect_status(
        signing::local_transport_decode_plain_frame(encoded, encoded_size, &decoded),
        signing::LocalTransportFrameStatus::ok,
        "decode valid protocol fragment");
    expect(decoded.type == frame.type, "decoded type");
    expect(decoded.flags == frame.flags, "decoded flags");
    expect(decoded.sequence == frame.sequence, "decoded sequence");
    expect(decoded.total_len == frame.total_len, "decoded total length");
    expect(decoded.payload_len == sizeof(payload), "decoded payload length");
    expect(memcmp(decoded.payload, payload, sizeof(payload)) == 0, "decoded payload bytes");

    signing::LocalTransportPlainFrame invalid = frame;
    invalid.flags = 0x02;
    expect_status(
        signing::local_transport_encode_plain_frame(invalid, encoded, sizeof(encoded), &encoded_size),
        signing::LocalTransportFrameStatus::invalid_flags,
        "invalid flags rejected");

    invalid = frame;
    invalid.type = 0x7f;
    expect_status(
        signing::local_transport_encode_plain_frame(invalid, encoded, sizeof(encoded), &encoded_size),
        signing::LocalTransportFrameStatus::invalid_type,
        "invalid type rejected");

    invalid = frame;
    invalid.total_len = 4;
    expect_status(
        signing::local_transport_encode_plain_frame(invalid, encoded, sizeof(encoded), &encoded_size),
        signing::LocalTransportFrameStatus::invalid_length,
        "payload longer than total rejected");

    expect_status(
        signing::local_transport_encode_plain_frame(frame, encoded, 4, &encoded_size),
        signing::LocalTransportFrameStatus::output_too_small,
        "small output rejected");

    uint8_t malformed[] = {
        0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06,
        'h', 'e', 'l', 'l', 'o',
    };
    expect_status(
        signing::local_transport_decode_plain_frame(malformed, sizeof(malformed), &decoded),
        signing::LocalTransportFrameStatus::invalid_length,
        "payload length mismatch rejected");

    uint8_t key[signing::kLocalTransportCryptoKeyBytes] = {};
    uint8_t sealed[signing::kLocalTransportMaximumEncryptedFrameBytes] = {};
    size_t sealed_size = 0;
    expect(
        signing::local_transport_encrypt_frame(
            key,
            signing::LocalTransportFrameDirection::device_to_gateway,
            7,
            frame,
            sealed,
            sizeof(sealed),
            &sealed_size,
            fake_crypto_ops) == signing::LocalTransportFrameAeadStatus::ok,
        "AEAD frame encrypts");
    expect(sealed_size == valid_encoded_size + signing::kLocalTransportAeadTagBytes, "AEAD size");
    expect(last_aad_len == signing::kLocalTransportFrameAadBytes, "AEAD captured AAD size");
    expect(last_aad[33] == 0x02, "AEAD direction byte device-to-gateway");
    expect(last_aad[41] == 0x07, "AEAD counter low byte");

    uint8_t opened[signing::kLocalTransportMaximumPlainFrameBytes] = {};
    signing::LocalTransportPlainFrame opened_frame = {};
    expect(
        signing::local_transport_decrypt_frame(
            key,
            signing::LocalTransportFrameDirection::device_to_gateway,
            7,
            sealed,
            sealed_size,
            opened,
            sizeof(opened),
            &opened_frame,
            fake_crypto_ops) == signing::LocalTransportFrameAeadStatus::ok,
        "AEAD frame decrypts");
    expect(opened_frame.type == frame.type, "opened type");
    expect(opened_frame.sequence == frame.sequence, "opened sequence");
    expect(opened_frame.total_len == frame.total_len, "opened total length");
    expect(opened_frame.payload_len == frame.payload_len, "opened payload length");
    expect(memcmp(opened_frame.payload, payload, sizeof(payload)) == 0, "opened payload");

    const signing::LocalTransportPlainFrame close_frame = {
        signing::kLocalTransportFrameTypeTransportClose,
        signing::kLocalTransportFrameFlagLast,
        0,
        1,
        nullptr,
        0,
    };
    expect_status(
        signing::local_transport_encode_plain_frame(
            close_frame,
            encoded,
            sizeof(encoded),
            &encoded_size),
        signing::LocalTransportFrameStatus::ok,
        "transport close frame accepted");

    uint8_t line_buffer[32] = {};
    signing::LocalTransportReassemblyState reassembly = {};
    expect(
        signing::local_transport_reassembly_init(
            &reassembly,
            line_buffer,
            sizeof(line_buffer),
            signing::kLocalTransportGatewayRequestLineCapBytes),
        "reassembly initializes");
    size_t line_size = 0;
    const uint8_t first_payload[] = {'h', 'e', 'l', 'l', 'o', ' '};
    const uint8_t second_payload[] = {'w', 'o', 'r', 'l', 'd'};
    const signing::LocalTransportPlainFrame first_fragment = {
        signing::kLocalTransportFrameTypeProtocolLineFragment,
        0,
        0,
        11,
        first_payload,
        sizeof(first_payload),
    };
    const signing::LocalTransportPlainFrame second_fragment = {
        signing::kLocalTransportFrameTypeProtocolLineFragment,
        signing::kLocalTransportFrameFlagLast,
        1,
        11,
        second_payload,
        sizeof(second_payload),
    };
    expect_reassembly_status(
        signing::local_transport_reassembly_accept(
            &reassembly,
            first_fragment,
            &line_size),
        signing::LocalTransportReassemblyStatus::in_progress,
        "first fragment starts reassembly");
    expect(line_size == 0, "in-progress reassembly does not expose line");
    expect_reassembly_status(
        signing::local_transport_reassembly_accept(
            &reassembly,
            second_fragment,
            &line_size),
        signing::LocalTransportReassemblyStatus::complete,
        "second fragment completes reassembly");
    expect(line_size == 11, "completed line size");
    expect(memcmp(line_buffer, "hello world", 11) == 0, "completed line bytes");

    expect(
        signing::local_transport_reassembly_init(&reassembly, line_buffer, sizeof(line_buffer), 5),
        "small-cap reassembly initializes");
    expect_reassembly_status(
        signing::local_transport_reassembly_accept(&reassembly, first_fragment, &line_size),
        signing::LocalTransportReassemblyStatus::line_too_large,
        "oversized reassembly rejected");

    expect(
        signing::local_transport_reassembly_init(
            &reassembly,
            line_buffer,
            sizeof(line_buffer),
            signing::kLocalTransportGatewayRequestLineCapBytes),
        "reassembly reinitializes");
    expect_reassembly_status(
        signing::local_transport_reassembly_accept(&reassembly, first_fragment, &line_size),
        signing::LocalTransportReassemblyStatus::in_progress,
        "first fragment accepted before bad seq");
    signing::LocalTransportPlainFrame bad_sequence = second_fragment;
    bad_sequence.sequence = 3;
    expect_reassembly_status(
        signing::local_transport_reassembly_accept(&reassembly, bad_sequence, &line_size),
        signing::LocalTransportReassemblyStatus::sequence_mismatch,
        "sequence mismatch rejected");
    for (size_t index = 0; index < sizeof(line_buffer); ++index) {
        expect(line_buffer[index] == 0, "sequence mismatch wipes buffer");
    }

    return failures == 0 ? 0 : 1;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_TRANSPORT_DIR}" \
  "${COMMON_TRANSPORT_DIR}/local_transport_crypto.cpp" \
  "${COMMON_TRANSPORT_DIR}/local_transport_frame.cpp" \
  "${TMP_DIR}/local_transport_frame_test.cpp" \
  -o "${TMP_DIR}/local_transport_frame_test"

"${TMP_DIR}/local_transport_frame_test"
