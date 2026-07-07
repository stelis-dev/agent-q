#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui/active_identity.h"
#include "sui/zklogin_proof_record.h"
#include "sui_account.h"

namespace signing {

constexpr size_t kSuiSchemePrefixedEd25519PublicKeyBytes =
    1 + kSuiEd25519PublicKeyBytes;

enum class SuiZkLoginProofRecordStatus {
    active,
    missing,
    invalid,
    storage_error,
};

enum class SuiZkLoginProofRecordWriteResult {
    stored,
    invalid_record,
    storage_error,
    consistency_error,
};

SuiZkLoginProofRecordStatus sui_zklogin_proof_record_status();
SuiZkLoginProofRecordStatus read_sui_zklogin_proof_record(
    SuiZkLoginProofRecord* out);
SuiZkLoginProofRecordWriteResult store_sui_zklogin_proof_record(
    const SuiZkLoginProofRecord* record);
bool wipe_sui_zklogin_proof_record();
SuiActiveIdentity resolve_active_sui_identity();

}  // namespace signing
