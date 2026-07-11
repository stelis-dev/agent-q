#pragma once

#include "keystore/encrypted_keystore.h"

namespace signing {

struct EncryptedKeystoreNvsConfig {
    const char* namespace_name = nullptr;
    const char* log_tag = nullptr;
};

KeystoreStorageOps encrypted_keystore_nvs_storage_ops(
    const EncryptedKeystoreNvsConfig* config);

}  // namespace signing
