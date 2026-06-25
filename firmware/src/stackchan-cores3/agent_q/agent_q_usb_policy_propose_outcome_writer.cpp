#include "agent_q_usb_policy_propose_outcome_writer.h"

#include <ArduinoJson.h>

#include "agent_q_protocol_constants.h"
#include "agent_q_usb_response_writer.h"

namespace agent_q {

bool usb_policy_propose_outcome_write(
    const char* id,
    const char* status,
    const char* reason_code,
    const AgentQPolicyUpdateFlowSnapshot* policy)
{
    JsonDocument result;
    result["status"] = status;
    result["reasonCode"] = reason_code;
    if (policy != nullptr) {
        JsonObject policy_json = result["policy"].to<JsonObject>();
        policy_json["policyHash"] = policy->policy_hash;
        policy_json["blockchainCount"] = policy->blockchain_count;
        policy_json["networkCount"] = policy->network_count;
        policy_json["policyCount"] = policy->policy_count;
        policy_json["conditionCount"] = policy->condition_count;
        policy_json["highestAction"] = policy->highest_action;
    }
    return usb_response_write_success_result(id, "policy_propose", result.as<JsonObjectConst>());
}

}  // namespace agent_q
