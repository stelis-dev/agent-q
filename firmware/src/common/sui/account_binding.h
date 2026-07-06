#pragma once

#include "transaction_facts.h"

namespace signing {

enum class SuiTransactionAccountBindingResult {
    ok,
    invalid_argument,
    account_mismatch,
};

SuiTransactionAccountBindingResult verify_sui_transaction_account_binding(
    const SuiPolicySubjectFacts& facts,
    const char* active_address,
    bool accept_gas_sponsor);

}  // namespace signing
