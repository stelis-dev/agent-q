#pragma once

#include <ArduinoJson.h>

namespace agent_q {

enum class AgentQMethodRuntimeStatus {
    invalid_params,
    rejected,
};

struct AgentQMethodRuntimeResult {
    AgentQMethodRuntimeStatus status;
    const char* code;
    const char* message;
};

AgentQMethodRuntimeResult evaluate_call_method(
    const char* chain,
    const char* method,
    JsonVariant params);

}  // namespace agent_q
