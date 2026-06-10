#pragma once

#include <string.h>

namespace agent_q {

inline bool sui_network_supported(const char* network)
{
    return network != nullptr &&
           (strcmp(network, "mainnet") == 0 ||
            strcmp(network, "testnet") == 0 ||
            strcmp(network, "devnet") == 0 ||
            strcmp(network, "localnet") == 0);
}

}  // namespace agent_q
