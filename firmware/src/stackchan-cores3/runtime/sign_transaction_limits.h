#pragma once

#include <stddef.h>

namespace signing {

constexpr size_t kSuiSignTransactionTxBytesMaxBytes = 128 * 1024;
constexpr size_t kSuiSignTransactionTxBytesMaxBase64Size =
    ((kSuiSignTransactionTxBytesMaxBytes + 2) / 3) * 4;

}  // namespace signing
