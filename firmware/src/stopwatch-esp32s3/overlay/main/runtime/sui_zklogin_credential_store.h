#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui/zklogin_proof_record.h"
#include "sui_public_material.h"

namespace stopwatch_target {

using signing::derive_sui_address_from_scheme_prefixed_public_key;
using signing::kSuiNetworkBufferSize;
using signing::kSuiSignatureSchemeFlagZkLogin;
using signing::kSuiZkLoginAddressSeedBufferSize;
using signing::kSuiZkLoginHeaderBase64BufferSize;
using signing::kSuiZkLoginIssuerBufferSize;
using signing::kSuiZkLoginIssBase64BufferSize;
using signing::kSuiZkLoginMaxEpochBufferSize;
using signing::kSuiZkLoginProofHashBufferSize;
using signing::kSuiZkLoginProofPointACount;
using signing::kSuiZkLoginProofPointBInnerCount;
using signing::kSuiZkLoginProofPointBOuterCount;
using signing::kSuiZkLoginProofPointBufferSize;
using signing::kSuiZkLoginProofPointCCount;
using signing::kSuiZkLoginPublicKeyMaxBytes;
using signing::kSuiZkLoginPublicKeyMinBytes;
using signing::SuiZkLoginIssBase64Details;
using signing::SuiZkLoginProofPoints;
using signing::SuiZkLoginProofRecord;
using signing::SuiZkLoginSignatureInputs;
using signing::validate_sui_zklogin_proof_record;

struct SuiZkLoginCredentialRecord {
    SuiZkLoginProofRecord proof;
    uint8_t prepared_seed[kSuiEd25519SeedBytes];
};

enum class SuiZkLoginCredentialStatus {
    active,
    missing,
    invalid,
    storage_error,
};

enum class SuiZkLoginCredentialWriteResult {
    stored,
    invalid_record,
    storage_error,
    consistency_error,
};

enum class SuiZkLoginCredentialAccessResult {
    consumed,
    missing,
    locked,
    invalid,
    storage_error,
    consumer_failed,
};

using SuiZkLoginCredentialConsumer = bool (*)(
    const SuiZkLoginCredentialRecord& credential,
    void* context);

struct SuiZkLoginAccountProjection {
    bool active;
    SuiZkLoginCredentialStatus status;
    char address[kSuiAddressBufferSize];
    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes];
    size_t public_key_size;
};

bool validate_sui_zklogin_credential_record(const SuiZkLoginCredentialRecord* record);
SuiZkLoginCredentialStatus sui_zklogin_credential_status();
SuiZkLoginCredentialAccessResult with_sui_zklogin_credential(
    SuiZkLoginCredentialConsumer consumer,
    void* consumer_context);
SuiZkLoginCredentialWriteResult store_sui_zklogin_credential(
    const SuiZkLoginCredentialRecord* record);
SuiZkLoginAccountProjection sui_zklogin_account_projection();

}  // namespace stopwatch_target
