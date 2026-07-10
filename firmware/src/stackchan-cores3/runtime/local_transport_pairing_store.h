#pragma once

#include <stddef.h>
#include <stdint.h>

#include "transport/local_transport_identity.h"

namespace signing {

bool local_transport_load_or_create_pairing_identity(LocalTransportPairingIdentity* identity);
bool local_transport_load_pairing_identity_secret(
    LocalTransportPairingIdentitySecret* identity);
bool local_transport_wipe_pairing_store();

}  // namespace signing
