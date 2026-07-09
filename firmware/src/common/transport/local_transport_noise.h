#pragma once

#include <stddef.h>
#include <stdint.h>

#include "transport/local_transport_crypto.h"
#include "transport/local_transport_optical_payload.h"

namespace signing {

constexpr size_t kLocalTransportNoiseHandshakeHashBytes = 32;
constexpr size_t kLocalTransportNoiseStaticKeyBytes = kLocalTransportX25519KeyBytes;
constexpr size_t kLocalTransportNoiseMessage1Bytes = 32;
constexpr size_t kLocalTransportNoiseMessage2Bytes = 32 + 32 + 16 + 8 + 16;
constexpr size_t kLocalTransportNoiseMessage3Bytes = 32 + 16 + 16;
constexpr char kLocalTransportNoisePairingProloguePrefix[] =
    "Agent-Q local transport pairing v1";
constexpr size_t kLocalTransportNoisePairingProloguePrefixBytes =
    sizeof(kLocalTransportNoisePairingProloguePrefix);

enum class LocalTransportNoiseStatus {
    ok,
    invalid_argument,
    invalid_state,
    invalid_length,
    crypto_error,
    authentication_failed,
    output_too_small,
};

struct LocalTransportNoiseSessionKeys {
    uint8_t gateway_to_device[kLocalTransportCryptoKeyBytes];
    uint8_t device_to_gateway[kLocalTransportCryptoKeyBytes];
    uint8_t handshake_hash[kLocalTransportNoiseHandshakeHashBytes];
};

struct LocalTransportNoiseResponderState {
    bool active;
    bool has_key;
    uint64_t nonce;
    uint8_t chaining_key[kLocalTransportCryptoHashBytes];
    uint8_t handshake_hash[kLocalTransportCryptoHashBytes];
    uint8_t cipher_key[kLocalTransportCryptoKeyBytes];
    uint8_t device_ephemeral_secret[kLocalTransportNoiseStaticKeyBytes];
    uint8_t device_ephemeral_public[kLocalTransportNoiseStaticKeyBytes];
    uint8_t gateway_ephemeral_public[kLocalTransportNoiseStaticKeyBytes];
};

void local_transport_noise_clear_responder_state(LocalTransportNoiseResponderState* state);

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
    const LocalTransportCryptoOps& ops);

LocalTransportNoiseStatus local_transport_noise_responder_read_message3(
    LocalTransportNoiseResponderState* state,
    const uint8_t* message3,
    size_t message3_len,
    uint8_t gateway_static_public[kLocalTransportNoiseStaticKeyBytes],
    LocalTransportNoiseSessionKeys* session_keys,
    const LocalTransportCryptoOps& ops);

void local_transport_noise_clear_session_keys(LocalTransportNoiseSessionKeys* keys);

}  // namespace signing
