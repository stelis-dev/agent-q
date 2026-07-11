#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui/transaction_facts.h"

namespace signing {

constexpr size_t kSuiZkLoginPublicKeyMinBytes = 34;
constexpr size_t kSuiZkLoginPublicKeyMaxBytes = 288;

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

struct SuiPublicIdentity {
    SuiActiveIdentityKind kind;
    SuiActiveIdentityError error;
    char address[kSuiAddressStringBufferSize];
    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes];
    size_t public_key_size;
};

}  // namespace signing
