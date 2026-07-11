#pragma once

#include "sui/public_identity.h"
#include "sui/zklogin_proof_record.h"

namespace signing {

struct SuiActiveIdentity {
    SuiActiveIdentityKind kind;
    SuiActiveIdentityError error;
    char address[kSuiAddressStringBufferSize];
    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes];
    size_t public_key_size;
    SuiZkLoginProofRecord zklogin;
};

}  // namespace signing
