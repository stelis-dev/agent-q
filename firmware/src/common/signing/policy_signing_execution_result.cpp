#include "signing/policy_signing_execution_result.h"

#include <string.h>

namespace signing {
namespace {

void wipe_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace

void clear_policy_signing_execution_result(PolicySigningExecutionResult* result)
{
    if (result == nullptr) {
        return;
    }
    wipe_buffer(result->signature, sizeof(result->signature));
    memset(result, 0, sizeof(*result));
}

}  // namespace signing
