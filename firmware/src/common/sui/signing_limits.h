#pragma once

#include <stddef.h>

namespace signing {

constexpr size_t kSuiSignTransactionTxBytesMaxBytes = 128 * 1024;
constexpr size_t kSuiSignTransactionTxBytesMaxBase64Size =
    ((kSuiSignTransactionTxBytesMaxBytes + 2) / 3) * 4;

constexpr size_t kSuiSignPersonalMessageMaxBytes = 768;
constexpr size_t kSuiSignPersonalMessageMaxBase64Size =
    ((kSuiSignPersonalMessageMaxBytes + 2) / 3) * 4;
constexpr size_t kSignPersonalMessagePreviewSize = 49;
constexpr size_t kSuiPersonalMessageIntentDigestBytes = 32;

}  // namespace signing
