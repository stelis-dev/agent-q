#include "agent_q_policy_canonical.h"

#include <string.h>

#include "agent_q_policy_u64.h"

namespace agent_q {
namespace {

constexpr uint8_t kStoredPolicyFormatVersion = 1;
constexpr uint8_t kStoredPolicySchemaV0 = 1;
constexpr uint8_t kStoredPolicyActionReject = 0;
constexpr uint8_t kStoredPolicyActionAsk = 1;
constexpr uint8_t kStoredPolicyActionSign = 2;
constexpr uint8_t kStoredPolicyOperatorEq = 0;
constexpr uint8_t kStoredPolicyOperatorIn = 1;
constexpr uint8_t kStoredPolicyOperatorLte = 2;

struct StoredPolicyHeader {
    uint8_t magic[4];
    uint8_t format_version;
    uint8_t schema;
    uint8_t default_action;
    uint8_t rule_count;
    uint8_t reserved[8];
};

static_assert(sizeof(StoredPolicyHeader) == 16, "Stored policy header must stay fixed-size");
static_assert(
    sizeof(StoredPolicyHeader) == kAgentQPolicyDefaultCanonicalRecordBytes,
    "Default policy record size must match the stored policy header");

}  // namespace

namespace {

bool string_present(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

bool string_eq(const char* left, const char* right)
{
    return left != nullptr && right != nullptr && strcmp(left, right) == 0;
}

bool add_string(
    AgentQPolicyCanonicalDocument* policy,
    const char* input,
    size_t max_length,
    AgentQPolicyCanonicalString* output)
{
    if (policy == nullptr || output == nullptr || !string_present(input) || max_length == 0) {
        return false;
    }
    const size_t length = strlen(input);
    if (length == 0 || length > max_length ||
        policy->string_pool_size >= sizeof(policy->string_pool) ||
        length + 1 > sizeof(policy->string_pool) - policy->string_pool_size ||
        policy->string_pool_size > UINT16_MAX ||
        length > UINT16_MAX) {
        return false;
    }

    output->offset = static_cast<uint16_t>(policy->string_pool_size);
    output->length = static_cast<uint16_t>(length);
    memcpy(policy->string_pool + policy->string_pool_size, input, length + 1);
    policy->string_pool_size += length + 1;
    return true;
}

const char* get_string(
    const AgentQPolicyCanonicalDocument& policy,
    const AgentQPolicyCanonicalString& value)
{
    const size_t offset = value.offset;
    const size_t length = value.length;
    if (length == 0 ||
        offset >= sizeof(policy.string_pool) ||
        offset + length >= sizeof(policy.string_pool) ||
        offset + length >= policy.string_pool_size ||
        policy.string_pool[offset + length] != '\0') {
        return nullptr;
    }
    return policy.string_pool + offset;
}

bool has_string(
    const AgentQPolicyCanonicalDocument& policy,
    const AgentQPolicyCanonicalString& value)
{
    return get_string(policy, value) != nullptr;
}

uint8_t encode_action(AgentQPolicyAction action)
{
    switch (action) {
        case AgentQPolicyAction::reject:
            return kStoredPolicyActionReject;
        case AgentQPolicyAction::ask:
            return kStoredPolicyActionAsk;
        case AgentQPolicyAction::sign:
            return kStoredPolicyActionSign;
    }
    return 0xFF;
}

uint8_t encode_operator(AgentQPolicyOperator op)
{
    switch (op) {
        case AgentQPolicyOperator::eq:
            return kStoredPolicyOperatorEq;
        case AgentQPolicyOperator::in:
            return kStoredPolicyOperatorIn;
        case AgentQPolicyOperator::lte:
            return kStoredPolicyOperatorLte;
    }
    return 0xFF;
}

const AgentQPolicyMethodDescriptor* find_method_descriptor(
    const AgentQPolicyMethodDescriptor* descriptors,
    size_t descriptor_count,
    const char* chain,
    const char* operation)
{
    if (descriptors == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < descriptor_count; ++index) {
        if (string_eq(descriptors[index].chain, chain) &&
            string_eq(descriptors[index].operation, operation)) {
            return &descriptors[index];
        }
    }
    return nullptr;
}

const AgentQPolicyFieldDescriptor* find_field_descriptor(
    const AgentQPolicyMethodDescriptor& method,
    const char* field)
{
    const AgentQPolicyFieldDescriptor* common =
        agent_q_policy_find_common_field_descriptor(field);
    if (common != nullptr) {
        return common;
    }
    if (method.field_descriptors == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < method.field_descriptor_count; ++index) {
        if (string_eq(method.field_descriptors[index].field, field)) {
            return &method.field_descriptors[index];
        }
    }
    return nullptr;
}

bool append_u8(uint8_t value, uint8_t* output, size_t capacity, size_t* offset)
{
    if (output == nullptr || offset == nullptr || *offset >= capacity) {
        return false;
    }
    output[*offset] = value;
    *offset += 1;
    return true;
}

bool append_bytes(const void* bytes, size_t size, uint8_t* output, size_t capacity, size_t* offset)
{
    if (bytes == nullptr || output == nullptr || offset == nullptr || *offset > capacity ||
        size > capacity - *offset) {
        return false;
    }
    memcpy(output + *offset, bytes, size);
    *offset += size;
    return true;
}

bool append_string(const char* value, uint8_t* output, size_t capacity, size_t* offset)
{
    if (!string_present(value)) {
        return false;
    }
    const size_t length = strlen(value);
    if (length > 255) {
        return false;
    }
    return append_u8(static_cast<uint8_t>(length), output, capacity, offset) &&
           append_bytes(value, length, output, capacity, offset);
}

bool validate_canonical_shape(const AgentQPolicyCanonicalDocument& policy)
{
    if (policy.schema != kAgentQPolicyV0Schema ||
        policy.default_action != AgentQPolicyAction::reject ||
        policy.rule_count > kAgentQPolicyMaxRules ||
        policy.string_pool_size > sizeof(policy.string_pool)) {
        return false;
    }
    for (size_t rule_index = 0; rule_index < policy.rule_count; ++rule_index) {
        const AgentQPolicyCanonicalRule& rule = policy.rules[rule_index];
        if (!has_string(policy, rule.id) ||
            !has_string(policy, rule.chain) ||
            !has_string(policy, rule.operation) ||
            !agent_q_policy_is_known_action(rule.action) ||
            rule.criterion_count > kAgentQPolicyMaxRuleCriteria) {
            return false;
        }
        for (size_t criterion_index = 0; criterion_index < rule.criterion_count; ++criterion_index) {
            const AgentQPolicyCanonicalCriterion& criterion = rule.criteria[criterion_index];
            if (!has_string(policy, criterion.field) ||
                !agent_q_policy_is_known_operator(criterion.op)) {
                return false;
            }
            if (criterion.op == AgentQPolicyOperator::in) {
                if (criterion.value_count == 0 ||
                    criterion.value_count > kAgentQPolicyMaxCriterionValues ||
                    has_string(policy, criterion.value)) {
                    return false;
                }
                for (size_t value_index = 0; value_index < criterion.value_count; ++value_index) {
                    if (!has_string(policy, criterion.values[value_index])) {
                        return false;
                    }
                }
            } else if (!has_string(policy, criterion.value) ||
                       criterion.value_count != 0) {
                return false;
            }
        }
    }
    return true;
}

AgentQPolicyCanonicalStatus copy_criterion(
    const AgentQPolicyCriterion& input,
    const AgentQPolicyMethodDescriptor& method,
    AgentQPolicyCanonicalDocument* policy,
    AgentQPolicyCanonicalCriterion* output)
{
    if (policy == nullptr || output == nullptr) {
        return AgentQPolicyCanonicalStatus::invalid_argument;
    }
    *output = {};

    if (!agent_q_policy_is_safe_field_id(input.field) ||
        !agent_q_policy_is_known_operator(input.op)) {
        return AgentQPolicyCanonicalStatus::invalid_policy;
    }

    const AgentQPolicyFieldDescriptor* descriptor = find_field_descriptor(method, input.field);
    if (descriptor == nullptr || !agent_q_policy_operator_allowed(*descriptor, input.op)) {
        return AgentQPolicyCanonicalStatus::unsupported_field;
    }

    output->op = input.op;
    if (!add_string(policy, input.field, kAgentQPolicyMaxFieldIdLength, &output->field)) {
        return AgentQPolicyCanonicalStatus::invalid_policy;
    }

    switch (input.op) {
        case AgentQPolicyOperator::eq:
        case AgentQPolicyOperator::lte:
            if (!string_present(input.value) || input.values != nullptr || input.value_count != 0) {
                return AgentQPolicyCanonicalStatus::invalid_policy;
            }
            if (descriptor->type == AgentQPolicyValueType::u64_decimal &&
                !agent_q_policy_is_canonical_decimal_u64_string(input.value)) {
                return AgentQPolicyCanonicalStatus::invalid_policy;
            }
            return add_string(policy, input.value, kAgentQPolicyMaxValueLength, &output->value)
                       ? AgentQPolicyCanonicalStatus::ok
                       : AgentQPolicyCanonicalStatus::invalid_policy;

        case AgentQPolicyOperator::in:
            if (input.value != nullptr || input.values == nullptr || input.value_count == 0 ||
                input.value_count > kAgentQPolicyMaxCriterionValues) {
                return AgentQPolicyCanonicalStatus::invalid_policy;
            }
            output->value_count = input.value_count;
            for (size_t index = 0; index < input.value_count; ++index) {
                if (!string_present(input.values[index]) ||
                    (descriptor->type == AgentQPolicyValueType::u64_decimal &&
                     !agent_q_policy_is_canonical_decimal_u64_string(input.values[index])) ||
                    !add_string(
                        policy,
                        input.values[index],
                        kAgentQPolicyMaxValueLength,
                        &output->values[index])) {
                    return AgentQPolicyCanonicalStatus::invalid_policy;
                }
            }
            return AgentQPolicyCanonicalStatus::ok;
    }
    return AgentQPolicyCanonicalStatus::invalid_policy;
}

AgentQPolicyCanonicalStatus copy_rule(
    const AgentQPolicyRule& input,
    const AgentQPolicyMethodDescriptor* method_descriptors,
    size_t method_descriptor_count,
    AgentQPolicyCanonicalDocument* policy,
    AgentQPolicyCanonicalRule* output)
{
    if (policy == nullptr || output == nullptr) {
        return AgentQPolicyCanonicalStatus::invalid_argument;
    }
    *output = {};

    if (!agent_q_policy_is_identifier_string(input.id, kAgentQPolicyMaxRuleIdLength) ||
        !agent_q_policy_is_identifier_string(input.chain, kAgentQPolicyMaxChainIdLength) ||
        !agent_q_policy_is_identifier_string(input.operation, kAgentQPolicyMaxOperationLength) ||
        input.criterion_count > kAgentQPolicyMaxRuleCriteria ||
        (input.criterion_count != 0 && input.criteria == nullptr)) {
        return AgentQPolicyCanonicalStatus::invalid_policy;
    }
    if (input.action != AgentQPolicyAction::reject && input.criterion_count == 0) {
        return AgentQPolicyCanonicalStatus::invalid_policy;
    }

    const AgentQPolicyMethodDescriptor* method =
        find_method_descriptor(method_descriptors, method_descriptor_count, input.chain, input.operation);
    if (method == nullptr) {
        return AgentQPolicyCanonicalStatus::unsupported_method;
    }
    if (!agent_q_policy_method_supports_action(*method, input.action)) {
        return AgentQPolicyCanonicalStatus::unsupported_action;
    }

    if (!add_string(policy, input.id, kAgentQPolicyMaxRuleIdLength, &output->id) ||
        !add_string(policy, input.chain, kAgentQPolicyMaxChainIdLength, &output->chain) ||
        !add_string(policy, input.operation, kAgentQPolicyMaxOperationLength, &output->operation)) {
        return AgentQPolicyCanonicalStatus::invalid_policy;
    }
    output->action = input.action;
    output->criterion_count = input.criterion_count;

    for (size_t index = 0; index < input.criterion_count; ++index) {
        const AgentQPolicyCanonicalStatus status =
            copy_criterion(input.criteria[index], *method, policy, &output->criteria[index]);
        if (status != AgentQPolicyCanonicalStatus::ok) {
            return status;
        }
    }
    return AgentQPolicyCanonicalStatus::ok;
}

}  // namespace

AgentQPolicyCanonicalStatus canonicalize_agent_q_policy_v0(
    const AgentQPolicyDocument& policy,
    const AgentQPolicyMethodDescriptor* method_descriptors,
    size_t method_descriptor_count,
    AgentQPolicyCanonicalDocument* out)
{
    if (out == nullptr) {
        return AgentQPolicyCanonicalStatus::invalid_argument;
    }
    *out = {};

    if (policy.schema != kAgentQPolicyV0Schema ||
        policy.default_action != AgentQPolicyAction::reject ||
        policy.rule_count > kAgentQPolicyMaxRules ||
        (policy.rule_count != 0 && policy.rules == nullptr)) {
        return AgentQPolicyCanonicalStatus::invalid_policy;
    }
    if (policy.rule_count != 0 &&
        !agent_q_policy_validate_method_descriptors(method_descriptors, method_descriptor_count)) {
        return AgentQPolicyCanonicalStatus::invalid_argument;
    }

    out->schema = policy.schema;
    out->default_action = policy.default_action;
    out->rule_count = policy.rule_count;
    for (size_t index = 0; index < policy.rule_count; ++index) {
        const AgentQPolicyCanonicalStatus status =
            copy_rule(policy.rules[index], method_descriptors, method_descriptor_count, out, &out->rules[index]);
        if (status != AgentQPolicyCanonicalStatus::ok) {
            *out = {};
            return status;
        }
    }
    return AgentQPolicyCanonicalStatus::ok;
}

bool agent_q_policy_canonical_to_runtime_view(
    const AgentQPolicyCanonicalDocument& policy,
    AgentQPolicyRuntimeView* out)
{
    if (out == nullptr || !validate_canonical_shape(policy)) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    for (size_t rule_index = 0; rule_index < policy.rule_count; ++rule_index) {
        const AgentQPolicyCanonicalRule& canonical_rule = policy.rules[rule_index];
        for (size_t criterion_index = 0; criterion_index < canonical_rule.criterion_count; ++criterion_index) {
            const AgentQPolicyCanonicalCriterion& canonical_criterion =
                canonical_rule.criteria[criterion_index];
            AgentQPolicyCriterion& criterion = out->criteria[rule_index][criterion_index];
            criterion.field = get_string(policy, canonical_criterion.field);
            criterion.op = canonical_criterion.op;
            if (canonical_criterion.op == AgentQPolicyOperator::in) {
                for (size_t value_index = 0; value_index < canonical_criterion.value_count; ++value_index) {
                    out->values[rule_index][criterion_index][value_index] =
                        get_string(policy, canonical_criterion.values[value_index]);
                }
                criterion.values = out->values[rule_index][criterion_index];
                criterion.value_count = canonical_criterion.value_count;
            } else {
                criterion.value = get_string(policy, canonical_criterion.value);
            }
        }

        out->rules[rule_index] = AgentQPolicyRule{
            get_string(policy, canonical_rule.id),
            get_string(policy, canonical_rule.chain),
            get_string(policy, canonical_rule.operation),
            canonical_rule.action,
            canonical_rule.criterion_count == 0 ? nullptr : out->criteria[rule_index],
            canonical_rule.criterion_count,
        };
    }

    out->document = AgentQPolicyDocument{
        policy.schema,
        policy.default_action,
        policy.rule_count == 0 ? nullptr : out->rules,
        policy.rule_count,
    };
    return true;
}

AgentQPolicyCanonicalStatus encode_agent_q_policy_v0_canonical_record(
    const AgentQPolicyCanonicalDocument& policy,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output == nullptr || output_capacity == 0 || output_size == nullptr) {
        return AgentQPolicyCanonicalStatus::invalid_argument;
    }
    memset(output, 0, output_capacity);

    if (!validate_canonical_shape(policy)) {
        return AgentQPolicyCanonicalStatus::invalid_policy;
    }

    StoredPolicyHeader header = {
        {'A', 'Q', 'P', '0'},
        kStoredPolicyFormatVersion,
        kStoredPolicySchemaV0,
        kStoredPolicyActionReject,
        static_cast<uint8_t>(policy.rule_count),
        {},
    };

    size_t offset = 0;
    if (!append_bytes(&header, sizeof(header), output, output_capacity, &offset)) {
        return AgentQPolicyCanonicalStatus::output_too_small;
    }

    for (size_t rule_index = 0; rule_index < policy.rule_count; ++rule_index) {
        const AgentQPolicyCanonicalRule& rule = policy.rules[rule_index];
        if (!append_string(get_string(policy, rule.id), output, output_capacity, &offset) ||
            !append_string(get_string(policy, rule.chain), output, output_capacity, &offset) ||
            !append_string(get_string(policy, rule.operation), output, output_capacity, &offset) ||
            !append_u8(encode_action(rule.action), output, output_capacity, &offset) ||
            !append_u8(static_cast<uint8_t>(rule.criterion_count), output, output_capacity, &offset)) {
            return AgentQPolicyCanonicalStatus::output_too_small;
        }
        for (size_t criterion_index = 0; criterion_index < rule.criterion_count; ++criterion_index) {
            const AgentQPolicyCanonicalCriterion& criterion = rule.criteria[criterion_index];
            if (!append_string(get_string(policy, criterion.field), output, output_capacity, &offset) ||
                !append_u8(encode_operator(criterion.op), output, output_capacity, &offset)) {
                return AgentQPolicyCanonicalStatus::output_too_small;
            }
            if (criterion.op == AgentQPolicyOperator::in) {
                if (!append_u8(static_cast<uint8_t>(criterion.value_count), output, output_capacity, &offset)) {
                    return AgentQPolicyCanonicalStatus::output_too_small;
                }
                for (size_t value_index = 0; value_index < criterion.value_count; ++value_index) {
                    if (!append_string(get_string(policy, criterion.values[value_index]), output, output_capacity, &offset)) {
                        return AgentQPolicyCanonicalStatus::output_too_small;
                    }
                }
            } else {
                if (!append_string(get_string(policy, criterion.value), output, output_capacity, &offset)) {
                    return AgentQPolicyCanonicalStatus::output_too_small;
                }
            }
        }
    }

    *output_size = offset;
    return AgentQPolicyCanonicalStatus::ok;
}

AgentQPolicyCanonicalStatus encode_agent_q_policy_v0_default_record(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output == nullptr || output_capacity == 0 || output_size == nullptr) {
        return AgentQPolicyCanonicalStatus::invalid_argument;
    }
    memset(output, 0, output_capacity);

    const StoredPolicyHeader header = {
        {'A', 'Q', 'P', '0'},
        kStoredPolicyFormatVersion,
        kStoredPolicySchemaV0,
        kStoredPolicyActionReject,
        0,
        {},
    };

    size_t offset = 0;
    if (!append_bytes(&header, sizeof(header), output, output_capacity, &offset)) {
        return AgentQPolicyCanonicalStatus::output_too_small;
    }
    *output_size = offset;
    return AgentQPolicyCanonicalStatus::ok;
}

const char* agent_q_policy_canonical_status_name(AgentQPolicyCanonicalStatus status)
{
    switch (status) {
        case AgentQPolicyCanonicalStatus::ok:
            return "ok";
        case AgentQPolicyCanonicalStatus::invalid_argument:
            return "invalid_argument";
        case AgentQPolicyCanonicalStatus::invalid_policy:
            return "invalid_policy";
        case AgentQPolicyCanonicalStatus::unsupported_method:
            return "unsupported_method";
        case AgentQPolicyCanonicalStatus::unsupported_action:
            return "unsupported_action";
        case AgentQPolicyCanonicalStatus::unsupported_field:
            return "unsupported_field";
        case AgentQPolicyCanonicalStatus::output_too_small:
            return "output_too_small";
    }
    return "unknown";
}

}  // namespace agent_q
