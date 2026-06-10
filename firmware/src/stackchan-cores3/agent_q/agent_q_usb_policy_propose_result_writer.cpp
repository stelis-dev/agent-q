#include "agent_q_usb_policy_propose_result_writer.h"

#include <ArduinoJson.h>

#include "agent_q_protocol_constants.h"
#include "agent_q_usb_response_writer.h"

namespace agent_q {

bool usb_policy_propose_result_write(
    const char* id,
    const char* status,
    const char* reason_code,
    const AgentQPolicyUpdateFlowSnapshot* policy)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "policy_propose_result";
    response["status"] = status;
    response["reasonCode"] = reason_code;
    if (policy != nullptr) {
        JsonObject policy_json = response["policy"].to<JsonObject>();
        policy_json["policyHash"] = policy->policy_hash;
        policy_json["ruleCount"] = policy->rule_count;
        policy_json["highestAction"] = policy->highest_action;
    }
    return usb_response_write_json(response);
}

}  // namespace agent_q
