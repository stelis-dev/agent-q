#include "policy/policy_json_writer.h"

namespace signing {

bool write_current_policy_json(
    JsonObject policy_json,
    const char* schema,
    const char* policy_id,
    const char* default_action,
    size_t blockchain_count,
    size_t network_count,
    size_t policy_count,
    size_t condition_count,
    const CurrentPolicyDocument* document)
{
    if (policy_json.isNull() || document == nullptr) {
        return false;
    }
    policy_json["schema"] = schema;
    policy_json["policyId"] = policy_id;
    policy_json["defaultAction"] = default_action;
    policy_json["blockchainCount"] = blockchain_count;
    policy_json["networkCount"] = network_count;
    policy_json["policyCount"] = policy_count;
    policy_json["conditionCount"] = condition_count;

    JsonArray blockchains = policy_json["blockchains"].to<JsonArray>();
    for (size_t blockchain_index = 0; blockchain_index < document->blockchain_count; ++blockchain_index) {
        const CurrentPolicyBlockchainScope& source_blockchain =
            document->blockchains[blockchain_index];
        JsonObject blockchain = blockchains.add<JsonObject>();
        blockchain["blockchain"] = source_blockchain.blockchain;
        JsonArray networks = blockchain["networks"].to<JsonArray>();
        for (size_t network_index = 0; network_index < source_blockchain.network_count; ++network_index) {
            const CurrentPolicyNetworkScope& source_network =
                source_blockchain.networks[network_index];
            JsonObject network = networks.add<JsonObject>();
            network["network"] = source_network.network;
            JsonArray policies = network["policies"].to<JsonArray>();
            for (size_t policy_index = 0; policy_index < source_network.policy_count; ++policy_index) {
                const CurrentPolicy& source_policy = source_network.policies[policy_index];
                JsonObject policy_object = policies.add<JsonObject>();
                policy_object["id"] = source_policy.id;
                policy_object["action"] = current_policy_action_name(source_policy.action);
                JsonArray conditions = policy_object["conditions"].to<JsonArray>();
                for (size_t condition_index = 0; condition_index < source_policy.condition_count; ++condition_index) {
                    const CurrentPolicyCondition& source_condition =
                        source_policy.conditions[condition_index];
                    JsonObject condition = conditions.add<JsonObject>();
                    condition["field"] = source_condition.field;
                    if (source_condition.where_type != nullptr &&
                        source_condition.where_type[0] != '\0') {
                        JsonObject where = condition["where"].to<JsonObject>();
                        where["type"] = source_condition.where_type;
                    }
                    condition["op"] = current_policy_operator_name(source_condition.op);
                    if (current_policy_operator_uses_value_list(source_condition.op)) {
                        JsonArray values = condition["values"].to<JsonArray>();
                        for (size_t value_index = 0; value_index < source_condition.value_count; ++value_index) {
                            values.add(source_condition.values[value_index]);
                        }
                    } else if (source_condition.value_count == 1) {
                        condition["value"] = source_condition.values[0];
                    } else {
                        return false;
                    }
                }
            }
        }
    }
    return true;
}

}  // namespace signing
