#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui/transaction_facts.h"

namespace signing {

constexpr uint8_t kSuiSignatureSchemeFlagZkLogin = 0x05;
constexpr size_t kSuiZkLoginPublicKeyMinBytes = 34;
constexpr size_t kSuiZkLoginPublicKeyMaxBytes = 288;
constexpr size_t kSuiZkLoginAddressBufferSize = kSuiAddressStringBufferSize;
constexpr size_t kSuiNetworkBufferSize = 9;           // "localnet" + NUL.
constexpr size_t kSuiZkLoginIssuerBufferSize = 513;   // 512 + NUL.
constexpr size_t kSuiZkLoginAddressSeedBufferSize = 79;  // uint256 decimal + NUL.
constexpr size_t kSuiZkLoginMaxEpochBufferSize = 21;     // uint64 decimal + NUL.
constexpr size_t kSuiZkLoginHeaderBase64BufferSize = 249;
constexpr size_t kSuiZkLoginIssBase64BufferSize = 513;
constexpr size_t kSuiZkLoginProofPointBufferSize = 79;
constexpr size_t kSuiZkLoginProofPointACount = 3;
constexpr size_t kSuiZkLoginProofPointBOuterCount = 3;
constexpr size_t kSuiZkLoginProofPointBInnerCount = 2;
constexpr size_t kSuiZkLoginProofPointCCount = 3;
constexpr size_t kSuiZkLoginProofHashBufferSize = 72;  // "sha256:" + 64 hex + NUL.
constexpr size_t kSuiZkLoginProofRecordMaxBytes = 4096;

struct SuiZkLoginProofPoints {
    char a[kSuiZkLoginProofPointACount][kSuiZkLoginProofPointBufferSize];
    char b[kSuiZkLoginProofPointBOuterCount][kSuiZkLoginProofPointBInnerCount]
          [kSuiZkLoginProofPointBufferSize];
    char c[kSuiZkLoginProofPointCCount][kSuiZkLoginProofPointBufferSize];
};

struct SuiZkLoginIssBase64Details {
    char value[kSuiZkLoginIssBase64BufferSize];
    uint8_t index_mod4;
};

struct SuiZkLoginSignatureInputs {
    SuiZkLoginProofPoints proof_points;
    SuiZkLoginIssBase64Details iss_base64_details;
    char header_base64[kSuiZkLoginHeaderBase64BufferSize];
    char address_seed[kSuiZkLoginAddressSeedBufferSize];
};

struct SuiZkLoginProofRecord {
    char network[kSuiNetworkBufferSize];
    char address[kSuiZkLoginAddressBufferSize];
    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes];
    size_t public_key_size;
    char issuer[kSuiZkLoginIssuerBufferSize];
    char address_seed[kSuiZkLoginAddressSeedBufferSize];
    char max_epoch[kSuiZkLoginMaxEpochBufferSize];
    SuiZkLoginSignatureInputs inputs;
    char proof_hash[kSuiZkLoginProofHashBufferSize];
};

bool sui_address_format_valid(const char* value);
bool derive_sui_address_from_scheme_prefixed_public_key(
    const uint8_t* public_key,
    size_t public_key_size,
    char* address_out,
    size_t address_out_size);
bool validate_sui_zklogin_proof_record(const SuiZkLoginProofRecord* record);

}  // namespace signing
