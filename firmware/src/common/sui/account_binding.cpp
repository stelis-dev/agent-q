#include "sui/account_binding.h"

#include <string.h>

namespace signing {

SuiTransactionAccountBindingResult verify_sui_transaction_account_binding(
    const SuiPolicySubjectFacts& facts,
    const char* active_address,
    bool accept_gas_sponsor)
{
    if (active_address == nullptr || active_address[0] == '\0' ||
        facts.sender[0] == '\0' || facts.gas_owner[0] == '\0') {
        return SuiTransactionAccountBindingResult::invalid_argument;
    }
    if (strcmp(facts.sender, active_address) != 0) {
        return SuiTransactionAccountBindingResult::account_mismatch;
    }
    if (strcmp(facts.gas_owner, active_address) == 0 || accept_gas_sponsor) {
        return SuiTransactionAccountBindingResult::ok;
    }
    return SuiTransactionAccountBindingResult::account_mismatch;
}

}  // namespace signing
