#pragma once

#include <ArduinoJson.h>

namespace signing {

struct UsbOperationResponseWriter {
    using WriteErrorFn = bool (*)(const char* id, const char* code);
    using WriteMethodErrorFn =
        bool (*)(const char* id, const char* method, const char* code);
    using WriteSuccessResultFn =
        bool (*)(const char* id, const char* method, JsonObjectConst result);
    using WriteTransportSuccessResultFn =
        bool (*)(const char* id, JsonObjectConst result);

    WriteErrorFn write_error_fn = nullptr;
    WriteMethodErrorFn write_method_error_fn = nullptr;
    WriteSuccessResultFn write_success_result_fn = nullptr;
    WriteTransportSuccessResultFn write_transport_success_result_fn = nullptr;
    void (*log_write_failure)(const char* response_type, const char* id);

    const char* method = nullptr;

    UsbOperationResponseWriter() = default;

    constexpr UsbOperationResponseWriter(
        WriteErrorFn write_error,
        void (*log_failure)(const char* response_type, const char* id))
        : write_error_fn(write_error),
          write_success_result_fn(nullptr),
          log_write_failure(log_failure)
    {
    }

    constexpr UsbOperationResponseWriter(
        WriteErrorFn write_error,
        WriteSuccessResultFn write_success_result,
        void (*log_failure)(const char* response_type, const char* id))
        : write_error_fn(write_error),
          write_success_result_fn(write_success_result),
          log_write_failure(log_failure)
    {
    }

    constexpr UsbOperationResponseWriter(
        WriteMethodErrorFn write_error,
        void (*log_failure)(const char* response_type, const char* id))
        : write_method_error_fn(write_error),
          write_success_result_fn(nullptr),
          log_write_failure(log_failure)
    {
    }

    constexpr UsbOperationResponseWriter(
        WriteMethodErrorFn write_error,
        WriteSuccessResultFn write_success_result,
        void (*log_failure)(const char* response_type, const char* id))
        : write_method_error_fn(write_error),
          write_success_result_fn(write_success_result),
          log_write_failure(log_failure)
    {
    }

    constexpr UsbOperationResponseWriter(
        WriteMethodErrorFn write_error,
        WriteSuccessResultFn write_success_result,
        WriteTransportSuccessResultFn write_transport_success_result,
        void (*log_failure)(const char* response_type, const char* id))
        : write_method_error_fn(write_error),
          write_success_result_fn(write_success_result),
          write_transport_success_result_fn(write_transport_success_result),
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

    bool write_success_result(const char* id, const char* next_method, JsonObjectConst result) const
    {
        return write_success_result_fn != nullptr
                   ? write_success_result_fn(id, next_method, result)
                   : false;
    }

    bool write_transport_success_result(const char* id, JsonObjectConst result) const
    {
        return write_transport_success_result_fn != nullptr
                   ? write_transport_success_result_fn(id, result)
                   : false;
    }

    UsbOperationResponseWriter for_method(const char* next_method) const
    {
        UsbOperationResponseWriter copy = *this;
        copy.method = next_method;
        return copy;
    }
};

}  // namespace signing
