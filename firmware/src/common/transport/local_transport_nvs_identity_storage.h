#pragma once

#include "transport/local_transport_identity_store.h"

namespace signing {

struct LocalTransportNvsIdentityStorageConfig {
    const char* namespace_name = nullptr;
    const char* private_key_name = nullptr;
    const char* public_key_name = nullptr;
    const char* log_tag = nullptr;
};

// The immutable config and every referenced string must outlive the returned ops.
LocalTransportIdentityStorageOps local_transport_nvs_identity_storage_ops(
    const LocalTransportNvsIdentityStorageConfig* config);

}  // namespace signing
