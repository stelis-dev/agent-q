#include "evaluator.h"

#include <string.h>

#include "u64.h"

namespace signing {
namespace {

bool string_eq(const char* left, const char* right)
{
    return left != nullptr && right != nullptr && strcmp(left, right) == 0;
}

bool string_in_values(const char* value, const char* const* values, size_t value_count)
{
    if (value == nullptr || values == nullptr) {
        return false;
    }
    for (size_t index = 0; index < value_count; ++index) {
        if (string_eq(value, values[index])) {
            return true;
        }
    }
    return false;
}

bool decimal_lte(const char* left, const char* right)
{
    return policy_is_canonical_decimal_u64_string(left) &&
           policy_is_canonical_decimal_u64_string(right) &&
           policy_compare_decimal_u64_strings(left, right) <= 0;
}

bool evaluate_scalar(
    const char* actual,
    CurrentPolicyOperator op,
    const char* const* values,
    size_t value_count)
{
    if (actual == nullptr || actual[0] == '\0' || values == nullptr || value_count == 0) {
        return false;
    }
    switch (op) {
        case CurrentPolicyOperator::eq:
            return value_count == 1 && string_eq(actual, values[0]);
        case CurrentPolicyOperator::in:
            return string_in_values(actual, values, value_count);
        case CurrentPolicyOperator::not_in:
            return !string_in_values(actual, values, value_count);
        case CurrentPolicyOperator::lte:
            return value_count == 1 && decimal_lte(actual, values[0]);
        default:
            return false;
    }
}

bool set_contains(const SuiOfflinePolicyStringSet& set, const char* value)
{
    for (uint16_t index = 0; index < set.count; ++index) {
        if (string_eq(set.values[index], value)) {
            return true;
        }
    }
    return false;
}

bool set_all_in_values(
    const SuiOfflinePolicyStringSet& set,
    const char* const* values,
    size_t value_count)
{
    if (set.count == 0 || values == nullptr || value_count == 0) {
        return false;
    }
    for (uint16_t index = 0; index < set.count; ++index) {
        if (!string_in_values(set.values[index], values, value_count)) {
            return false;
        }
    }
    return true;
}

bool set_none_in_values(
    const SuiOfflinePolicyStringSet& set,
    const char* const* values,
    size_t value_count)
{
    if (values == nullptr || value_count == 0) {
        return false;
    }
    for (uint16_t index = 0; index < set.count; ++index) {
        if (string_in_values(set.values[index], values, value_count)) {
            return false;
        }
    }
    return true;
}

bool evaluate_string_set(
    const SuiOfflinePolicyStringSet& set,
    CurrentPolicyOperator op,
    const char* const* values,
    size_t value_count)
{
    if (values == nullptr || value_count == 0) {
        return false;
    }
    switch (op) {
        case CurrentPolicyOperator::contains:
            return value_count == 1 && set_contains(set, values[0]);
        case CurrentPolicyOperator::not_contains:
            return value_count == 1 && !set_contains(set, values[0]);
        case CurrentPolicyOperator::all_in:
            return set_all_in_values(set, values, value_count);
        case CurrentPolicyOperator::none_in:
            return set_none_in_values(set, values, value_count);
        default:
            return false;
    }
}

const char* bool_string(bool value)
{
    return value ? "true" : "false";
}

const char* token_source_kind_name(SuiOfflinePolicyTokenSourceKind value)
{
    switch (value) {
        case SuiOfflinePolicyTokenSourceKind::gas_coin:
            return "gas_coin";
        case SuiOfflinePolicyTokenSourceKind::funds_withdrawal_sender:
            return "funds_withdrawal_sender";
        case SuiOfflinePolicyTokenSourceKind::funds_withdrawal_sponsor:
            return "funds_withdrawal_sponsor";
        case SuiOfflinePolicyTokenSourceKind::unknown:
            return "unknown";
    }
    return "unknown";
}

bool evaluate_all_token_source_strings(
    const SuiOfflinePolicyConditionFacts& facts,
    CurrentPolicyEvaluationKind evaluation_kind,
    CurrentPolicyOperator op,
    const char* const* values,
    size_t value_count)
{
    if (facts.token_source_count == 0) {
        return op == CurrentPolicyOperator::not_in;
    }
    for (uint16_t index = 0; index < facts.token_source_count; ++index) {
        const SuiOfflinePolicyTokenSourceFact& source = facts.token_sources[index];
        const char* actual = nullptr;
        switch (evaluation_kind) {
            case CurrentPolicyEvaluationKind::sui_token_sources_type:
                actual = source.type_tag;
                break;
            case CurrentPolicyEvaluationKind::sui_token_sources_source:
                actual = token_source_kind_name(source.source);
                break;
            default:
                return false;
        }
        if (!evaluate_scalar(actual, op, values, value_count)) {
            return false;
        }
    }
    return true;
}

bool evaluate_all_token_source_amounts(
    const SuiOfflinePolicyConditionFacts& facts,
    CurrentPolicyOperator op,
    const char* const* values,
    size_t value_count)
{
    if (facts.token_source_count == 0) {
        return false;
    }
    for (uint16_t index = 0; index < facts.token_source_count; ++index) {
        const SuiOfflinePolicyTokenSourceFact& source = facts.token_sources[index];
        if (!source.amount_known ||
            !evaluate_scalar(source.amount_raw, op, values, value_count)) {
            return false;
        }
    }
    return true;
}

bool evaluate_selected_token_total_amount(
    const SuiOfflinePolicyConditionFacts& facts,
    const char* type_tag,
    CurrentPolicyOperator op,
    const char* const* values,
    size_t value_count)
{
    if (type_tag == nullptr || type_tag[0] == '\0' ||
        facts.token_unknown_amount_present) {
        return false;
    }
    const SuiOfflinePolicyTokenTotalFact* selected = nullptr;
    for (uint16_t index = 0; index < facts.token_total_count; ++index) {
        const SuiOfflinePolicyTokenTotalFact& total = facts.token_totals_by_type[index];
        if (!string_eq(total.type_tag, type_tag)) {
            continue;
        }
        if (selected != nullptr) {
            return false;
        }
        selected = &total;
    }
    return selected != nullptr &&
           evaluate_scalar(selected->amount_raw, op, values, value_count);
}

bool evaluate_condition(
    const CurrentPolicyCondition& condition,
    const SuiOfflinePolicyConditionFacts& facts)
{
    if (condition.field == nullptr ||
        condition.values == nullptr ||
        condition.value_count == 0) {
        return false;
    }
    const CurrentPolicyFieldDescriptor* descriptor =
        current_policy_find_field_descriptor(condition.field);
    if (descriptor == nullptr) {
        return false;
    }
    switch (descriptor->evaluation_kind) {
        case CurrentPolicyEvaluationKind::sui_gas_budget_raw:
            return evaluate_scalar(facts.gas_budget_raw, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_gas_price_raw:
            return evaluate_scalar(facts.gas_price_raw, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_gas_owner:
            return evaluate_scalar(facts.gas_owner, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_sponsored:
            return evaluate_scalar(bool_string(facts.sponsored), condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_command_count:
            return evaluate_scalar(facts.command_count, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_command_kinds:
            return evaluate_string_set(facts.command_kinds, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_move_call_packages:
            return evaluate_string_set(facts.move_call_packages, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_move_call_modules:
            return evaluate_string_set(facts.move_call_modules, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_move_call_functions:
            return evaluate_string_set(facts.move_call_functions, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_publish_present:
            return evaluate_scalar(bool_string(facts.publish_present), condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_upgrade_present:
            return evaluate_scalar(bool_string(facts.upgrade_present), condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_recipient_addresses:
            return evaluate_string_set(facts.recipient_addresses, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_pure_address_arguments:
            return evaluate_string_set(facts.pure_address_arguments, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_token_sources_type:
        case CurrentPolicyEvaluationKind::sui_token_sources_source:
            return evaluate_all_token_source_strings(
                facts,
                descriptor->evaluation_kind,
                condition.op,
                condition.values,
                condition.value_count);
        case CurrentPolicyEvaluationKind::sui_token_sources_amount_raw:
            return evaluate_all_token_source_amounts(facts, condition.op, condition.values, condition.value_count);
        case CurrentPolicyEvaluationKind::sui_token_totals_by_type_amount_raw:
            return evaluate_selected_token_total_amount(
                facts,
                condition.where_type,
                condition.op,
                condition.values,
                condition.value_count);
        case CurrentPolicyEvaluationKind::sui_token_unknown_amount_present:
            return evaluate_scalar(
                bool_string(facts.token_unknown_amount_present),
                condition.op,
                condition.values,
                condition.value_count);
    }
    return false;
}

bool policy_matches(
    const CurrentPolicy& policy,
    const SuiOfflinePolicyConditionFacts& facts)
{
    if (policy.condition_count == 0 || policy.conditions == nullptr) {
        return false;
    }
    for (size_t index = 0; index < policy.condition_count; ++index) {
        if (!evaluate_condition(policy.conditions[index], facts)) {
            return false;
        }
    }
    return true;
}

CurrentPolicyEvaluationResult make_result(
    CurrentPolicyEvaluationStatus status,
    const char* reason_code,
    const char* rule_ref)
{
    return CurrentPolicyEvaluationResult{
        status,
        reason_code,
        rule_ref,
    };
}

}  // namespace

CurrentPolicyEvaluationResult evaluate_current_policy_for_sui_sign_transaction(
    const CurrentPolicyDocument& policy,
    const char* network,
    const SuiOfflinePolicyConditionFacts& facts)
{
    if (network == nullptr || network[0] == '\0' ||
        validate_current_policy_document(policy) !=
            CurrentPolicyDocumentStatus::ok) {
        return make_result(
            CurrentPolicyEvaluationStatus::invalid_argument,
            "invalid_policy",
            "default");
    }
    if (!facts.valid_transaction_data ||
        facts.completeness != SuiOfflinePolicyFactsCompleteness::complete) {
        return make_result(
            CurrentPolicyEvaluationStatus::facts_incomplete,
            "policy_facts_incomplete",
            "default");
    }

    bool scope_matched = false;
    const char* matched_sign_rule = nullptr;
    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const CurrentPolicyBlockchainScope& blockchain = policy.blockchains[blockchain_index];
        if (!string_eq(blockchain.blockchain, "sui")) {
            continue;
        }
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const CurrentPolicyNetworkScope& network_scope = blockchain.networks[network_index];
            if (!string_eq(network_scope.network, network)) {
                continue;
            }
            scope_matched = true;
            for (size_t policy_index = 0; policy_index < network_scope.policy_count; ++policy_index) {
                const CurrentPolicy& candidate = network_scope.policies[policy_index];
                if (!policy_matches(candidate, facts)) {
                    continue;
                }
                if (candidate.action == CurrentPolicyAction::reject) {
                    return make_result(
                        CurrentPolicyEvaluationStatus::rejected,
                        "policy_rule_rejected",
                        candidate.id);
                }
                if (candidate.action == CurrentPolicyAction::sign &&
                    matched_sign_rule == nullptr) {
                    matched_sign_rule = candidate.id;
                }
            }
        }
    }
    if (!scope_matched) {
        return make_result(
            CurrentPolicyEvaluationStatus::no_matching_scope,
            "policy_scope_unmatched",
            "default");
    }
    if (matched_sign_rule != nullptr) {
        return make_result(
            CurrentPolicyEvaluationStatus::authorized,
            "policy_authorized",
            matched_sign_rule);
    }
    return make_result(
        CurrentPolicyEvaluationStatus::no_matching_policy,
        "policy_no_matching_rule",
        "default");
}

}  // namespace signing
