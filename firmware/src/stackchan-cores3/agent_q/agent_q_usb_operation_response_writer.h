#pragma once

namespace agent_q {

struct AgentQUsbOperationResponseWriter {
    bool (*write_error)(const char* id, const char* code, const char* message);
    void (*log_write_failure)(const char* response_type, const char* id);
};

}  // namespace agent_q
