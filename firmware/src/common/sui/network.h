#pragma once

#include <stddef.h>
#include <string.h>

namespace signing {

constexpr size_t kSuiNetworkBufferSize = 9;  // "localnet" + NUL.

inline bool sui_network_supported(const char* network)
{
    return network != nullptr &&
           (strcmp(network, "mainnet") == 0 ||
            strcmp(network, "testnet") == 0 ||
            strcmp(network, "devnet") == 0 ||
            strcmp(network, "localnet") == 0);
}

}  // namespace signing
