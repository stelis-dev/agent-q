#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_sui_account.h"

namespace agent_q {

constexpr uint8_t kAgentQSuiSignatureSchemeFlagEd25519 = 0x00;
constexpr uint8_t kAgentQSuiSignatureSchemeFlagZkLogin = 0x05;
constexpr size_t kAgentQSuiSchemePrefixedEd25519PublicKeyBytes =
    1 + kSuiEd25519PublicKeyBytes;
constexpr size_t kAgentQSuiZkLoginPublicKeyMinBytes = 34;
constexpr size_t kAgentQSuiZkLoginPublicKeyMaxBytes = 288;
constexpr size_t kAgentQSuiNetworkBufferSize = 9;        // "localnet" + NUL.
constexpr size_t kAgentQSuiZkLoginIssuerBufferSize = 513;  // 512 + NUL.
constexpr size_t kAgentQSuiZkLoginAddressSeedBufferSize = 79;  // uint256 decimal + NUL.
constexpr size_t kAgentQSuiZkLoginMaxEpochBufferSize = 21;     // uint64 decimal + NUL.
constexpr size_t kAgentQSuiZkLoginHeaderBase64BufferSize = 249;
constexpr size_t kAgentQSuiZkLoginIssBase64BufferSize = 513;
constexpr size_t kAgentQSuiZkLoginProofPointBufferSize = 79;
constexpr size_t kAgentQSuiZkLoginProofPointACount = 3;
constexpr size_t kAgentQSuiZkLoginProofPointBOuterCount = 3;
constexpr size_t kAgentQSuiZkLoginProofPointBInnerCount = 2;
constexpr size_t kAgentQSuiZkLoginProofPointCCount = 3;
constexpr size_t kAgentQSuiZkLoginProofHashBufferSize = 72;  // "sha256:" + 64 hex + NUL.
constexpr size_t kAgentQSuiZkLoginProofRecordMaxBytes = 4096;

struct AgentQSuiZkLoginProofPoints {
    char a[kAgentQSuiZkLoginProofPointACount][kAgentQSuiZkLoginProofPointBufferSize];
    char b[kAgentQSuiZkLoginProofPointBOuterCount][kAgentQSuiZkLoginProofPointBInnerCount]
          [kAgentQSuiZkLoginProofPointBufferSize];
    char c[kAgentQSuiZkLoginProofPointCCount][kAgentQSuiZkLoginProofPointBufferSize];
};

struct AgentQSuiZkLoginIssBase64Details {
    char value[kAgentQSuiZkLoginIssBase64BufferSize];
    uint8_t index_mod4;
};

struct AgentQSuiZkLoginSignatureInputs {
    AgentQSuiZkLoginProofPoints proof_points;
    AgentQSuiZkLoginIssBase64Details iss_base64_details;
    char header_base64[kAgentQSuiZkLoginHeaderBase64BufferSize];
    char address_seed[kAgentQSuiZkLoginAddressSeedBufferSize];
};

struct AgentQSuiZkLoginProofRecord {
    char network[kAgentQSuiNetworkBufferSize];
    char address[kSuiAddressBufferSize];
    uint8_t public_key[kAgentQSuiZkLoginPublicKeyMaxBytes];
    size_t public_key_size;
    char issuer[kAgentQSuiZkLoginIssuerBufferSize];
    char address_seed[kAgentQSuiZkLoginAddressSeedBufferSize];
    char max_epoch[kAgentQSuiZkLoginMaxEpochBufferSize];
    AgentQSuiZkLoginSignatureInputs inputs;
    char proof_hash[kAgentQSuiZkLoginProofHashBufferSize];
};

enum class AgentQSuiZkLoginProofRecordStatus {
    active,
    missing,
    invalid,
    storage_error,
};

enum class AgentQSuiZkLoginProofRecordWriteResult {
    stored,
    invalid_record,
    storage_error,
    consistency_error,
};

enum class AgentQSuiActiveIdentityKind {
    native,
    zklogin,
    error,
};

enum class AgentQSuiActiveIdentityError {
    none,
    proof_storage_error,
    native_account_unavailable,
};

struct AgentQSuiActiveIdentity {
    AgentQSuiActiveIdentityKind kind;
    AgentQSuiActiveIdentityError error;
    char address[kSuiAddressBufferSize];
    uint8_t public_key[kAgentQSuiZkLoginPublicKeyMaxBytes];
    size_t public_key_size;
    AgentQSuiZkLoginProofRecord zklogin;
};

bool derive_sui_address_from_scheme_prefixed_public_key(
    const uint8_t* public_key,
    size_t public_key_size,
    char* address_out,
    size_t address_out_size);
bool validate_sui_zklogin_proof_record(const AgentQSuiZkLoginProofRecord* record);
AgentQSuiZkLoginProofRecordStatus sui_zklogin_proof_record_status();
AgentQSuiZkLoginProofRecordStatus read_sui_zklogin_proof_record(
    AgentQSuiZkLoginProofRecord* out);
AgentQSuiZkLoginProofRecordWriteResult store_sui_zklogin_proof_record(
    const AgentQSuiZkLoginProofRecord* record);
bool wipe_sui_zklogin_proof_record();
AgentQSuiActiveIdentity resolve_active_sui_identity();

}  // namespace agent_q
