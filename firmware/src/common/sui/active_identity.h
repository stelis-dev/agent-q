#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui/signing_limits.h"
#include "sui/zklogin_proof_record.h"

namespace signing {

enum class SuiActiveIdentityKind {
    none,
    native,
    zklogin,
    error,
};

enum class SuiActiveIdentityError {
    none,
    proof_storage_error,
    native_account_unavailable,
};

struct SuiActiveIdentity {
    SuiActiveIdentityKind kind;
    SuiActiveIdentityError error;
    char address[kSuiAddressStringBufferSize];
    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes];
    size_t public_key_size;
    SuiZkLoginProofRecord zklogin;
};

}  // namespace signing
