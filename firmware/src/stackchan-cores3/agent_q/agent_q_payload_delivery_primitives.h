#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_approval_history.h"

namespace agent_q {

constexpr size_t kAgentQPayloadDeliveryTransferIdSize = 82;   // "transfer_" + 72 chars + NUL.
constexpr size_t kAgentQPayloadDeliveryPayloadRefSize = 81; // "payload_" + 72 chars + NUL.

bool payload_delivery_transfer_id_format_valid(const char* value);
bool payload_delivery_payload_ref_format_valid(const char* value);
bool payload_delivery_payload_digest_format_valid(const char* value);
bool payload_delivery_format_transfer_id(uint64_t value, char* output, size_t output_size);
bool payload_delivery_format_payload_ref(uint64_t value, char* output, size_t output_size);

}  // namespace agent_q
