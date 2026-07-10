#pragma once

#include "protocol/json_response.h"
#include "protocol/response_writer.h"
#include "protocol/protocol_transport_kind.h"

namespace signing {

struct ProtocolTransportEndpoint {
    ProtocolTransport transport = ProtocolTransport::none;
    ResponseWriter response_writer = {};
    JsonResponseWriteOps json_response_write_ops = {};

    bool valid() const
    {
        return transport != ProtocolTransport::none &&
               response_writer.can_write_error() &&
               json_response_write_ops.write_bytes != nullptr;
    }
};

class ProtocolTransportRoute {
public:
    ProtocolTransportRoute() = default;

    explicit ProtocolTransportRoute(const ProtocolTransportEndpoint& endpoint)
        : endpoint_(endpoint)
    {
    }

    bool bound() const
    {
        return endpoint_.valid();
    }

    ProtocolTransport transport() const
    {
        return bound() ? endpoint_.transport : ProtocolTransport::none;
    }

    const ResponseWriter& response_writer() const
    {
        static const ResponseWriter unbound_writer = {};
        return bound() ? endpoint_.response_writer : unbound_writer;
    }

    const JsonResponseWriteOps& json_response_write_ops() const
    {
        static const JsonResponseWriteOps unbound_ops = {};
        return bound() ? endpoint_.json_response_write_ops : unbound_ops;
    }

    void clear()
    {
        endpoint_ = {};
    }

private:
    ProtocolTransportEndpoint endpoint_ = {};
};

}  // namespace signing
