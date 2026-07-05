#include "sui_zklogin_credential_clear.h"

#include "sui_zklogin_credential_store.h"
#include "usb_transport.h"

namespace stopwatch_target {

bool sui_zklogin_clear_active_credential()
{
    const bool wiped = wipe_sui_zklogin_credential();
    usb_transport_clear_session_scoped_state();
    return wiped && sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing;
}

}  // namespace stopwatch_target
