#pragma once

namespace agent_q {

struct AgentQUsbOperationResponseWriter {
    using WriteErrorFn = bool (*)(const char* id, const char* code);
    using WriteMethodErrorFn =
        bool (*)(const char* id, const char* method, const char* code);

    WriteErrorFn write_error_fn = nullptr;
    WriteMethodErrorFn write_method_error_fn = nullptr;
    void (*log_write_failure)(const char* response_type, const char* id);

    const char* method = nullptr;

    AgentQUsbOperationResponseWriter() = default;

    constexpr AgentQUsbOperationResponseWriter(
        WriteErrorFn write_error,
        void (*log_failure)(const char* response_type, const char* id))
        : write_error_fn(write_error),
          log_write_failure(log_failure)
    {
    }

    constexpr AgentQUsbOperationResponseWriter(
        WriteMethodErrorFn write_error,
        void (*log_failure)(const char* response_type, const char* id))
        : write_method_error_fn(write_error),
          log_write_failure(log_failure)
    {
    }

    bool can_write_error() const
    {
        return write_error_fn != nullptr || write_method_error_fn != nullptr;
    }

    bool write_error(const char* id, const char* code) const
    {
        if (write_method_error_fn != nullptr) {
            return write_method_error_fn(id, method, code);
        }
        return write_error_fn != nullptr ? write_error_fn(id, code) : false;
    }

    AgentQUsbOperationResponseWriter for_method(const char* next_method) const
    {
        AgentQUsbOperationResponseWriter copy = *this;
        copy.method = next_method;
        return copy;
    }
};

}  // namespace agent_q
