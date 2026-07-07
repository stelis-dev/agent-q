#pragma once

#include "persistent_material.h"
#include "signing/policy_signing_execution_result.h"
#include "signing/sign_transaction_policy_runtime.h"
#include "sui_signing_service.h"

namespace signing {

PolicySigningExecutionResult execute_policy_sign_transaction(
    const SignTransactionPolicyRuntimeResult& policy_result,
    const PersistentMaterialOps& material_ops);

}  // namespace signing
