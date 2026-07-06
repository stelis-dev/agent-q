#include "user_signing_service_adapter.h"

#include "sui_signing_service.h"

namespace signing {
namespace {

UserSigningSignStatus map_user_signing_status(
    SuiSigningStatus status)
{
    switch (status) {
        case SuiSigningStatus::ok:
            return UserSigningSignStatus::ok;
        case SuiSigningStatus::invalid_input:
            return UserSigningSignStatus::invalid_input;
        case SuiSigningStatus::root_material_unavailable:
        case SuiSigningStatus::active_identity_unavailable:
            return UserSigningSignStatus::account_unavailable;
        case SuiSigningStatus::signature_output_too_small:
            return UserSigningSignStatus::signature_output_too_small;
        case SuiSigningStatus::zklogin_envelope_error:
            return UserSigningSignStatus::signature_envelope_error;
        case SuiSigningStatus::mnemonic_error:
        case SuiSigningStatus::signing_error:
        default:
            return UserSigningSignStatus::signing_error;
    }
}

}  // namespace

UserSigningSignStatus sign_user_signing_payload_from_active_identity(
    Route route,
    const uint8_t* payload,
    size_t payload_size,
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out,
    void*)
{
    SuiSigningStatus status = SuiSigningStatus::invalid_input;
    switch (route) {
        case Route::sui_sign_transaction:
            status = sign_sui_transaction_from_active_identity(
                payload,
                payload_size,
                signature_out,
                signature_size_out);
            break;
        case Route::sui_sign_personal_message:
            status = sign_sui_personal_message_from_active_identity(
                payload,
                payload_size,
                signature_out,
                signature_size_out);
            break;
        case Route::unsupported:
        default:
            status = SuiSigningStatus::invalid_input;
            break;
    }
    return map_user_signing_status(status);
}

}  // namespace signing
