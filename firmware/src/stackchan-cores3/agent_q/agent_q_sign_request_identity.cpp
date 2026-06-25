#include "agent_q_sign_request_identity.h"

#include <string.h>

#include "mbedtls/sha256.h"

namespace agent_q {
namespace {

bool update_bytes(
    mbedtls_sha256_context* context,
    const uint8_t* value,
    size_t value_size)
{
    return context != nullptr &&
           value != nullptr &&
           mbedtls_sha256_update(context, value, value_size) == 0;
}

bool update_string(mbedtls_sha256_context* context, const char* value)
{
    if (context == nullptr || value == nullptr) {
        return false;
    }
    const size_t value_size = strlen(value);
    if (value_size > UINT32_MAX) {
        return false;
    }
    const uint8_t length[] = {
        static_cast<uint8_t>((value_size >> 24) & 0xFF),
        static_cast<uint8_t>((value_size >> 16) & 0xFF),
        static_cast<uint8_t>((value_size >> 8) & 0xFF),
        static_cast<uint8_t>(value_size & 0xFF),
    };
    return update_bytes(context, length, sizeof(length)) &&
           update_bytes(
               context,
               reinterpret_cast<const uint8_t*>(value),
               value_size);
}

}  // namespace

bool sign_request_identity(
    AgentQSupportedSignRoute route,
    const char* network,
    const char* canonical_base64_payload,
    uint8_t* output,
    size_t output_size)
{
    if (route == AgentQSupportedSignRoute::unsupported ||
        network == nullptr ||
        canonical_base64_payload == nullptr ||
        output == nullptr ||
        output_size != kAgentQSignRequestIdentitySize) {
        return false;
    }

    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    const uint8_t identity_form = 1;
    const uint8_t route_value = static_cast<uint8_t>(route);
    const bool ok =
        mbedtls_sha256_starts(&context, 0) == 0 &&
        update_bytes(&context, &identity_form, sizeof(identity_form)) &&
        update_bytes(&context, &route_value, sizeof(route_value)) &&
        update_string(&context, network) &&
        update_string(&context, canonical_base64_payload) &&
        mbedtls_sha256_finish(&context, output) == 0;
    mbedtls_sha256_free(&context);
    if (!ok) {
        memset(output, 0, output_size);
    }
    return ok;
}

}  // namespace agent_q
