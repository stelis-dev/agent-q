#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_TRANSPORT_DIR="${REPO_ROOT}/firmware/src/common/transport"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/local-transport-peer-store.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/local_transport_peer_store_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "local_transport_peer_store.h"

namespace {

void expect(bool condition, const char* message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        _Exit(1);
    }
}

void fill_key(uint8_t key[signing::kLocalTransportX25519KeyBytes], uint8_t seed)
{
    for (size_t index = 0; index < signing::kLocalTransportX25519KeyBytes; ++index) {
        key[index] = static_cast<uint8_t>(seed + index);
    }
}

}  // namespace

int main()
{
    signing::LocalTransportPairedPeerBlob blob = {};
    signing::local_transport_peer_store_init_empty(&blob);
    expect(signing::local_transport_peer_store_valid(blob), "empty store valid");
    expect(blob.count == 0, "empty count");
    expect(blob.next_seq == 1, "empty next sequence starts at one");

    uint8_t key[signing::kLocalTransportX25519KeyBytes] = {};
    fill_key(key, 1);
    expect(signing::local_transport_peer_store_upsert(&blob, key), "insert first peer");
    expect(blob.count == 1, "first peer increments count");
    expect(blob.records[0].first_paired_seq == 1, "first sequence recorded");
    expect(blob.records[0].last_seen_seq == 1, "last seen sequence recorded");
    expect(blob.next_seq == 2, "next sequence advanced");

    expect(signing::local_transport_peer_store_upsert(&blob, key), "duplicate peer updates");
    expect(blob.count == 1, "duplicate peer does not consume slot");
    expect(blob.records[0].first_paired_seq == 1, "duplicate preserves first sequence");
    expect(blob.records[0].last_seen_seq == 2, "duplicate updates last seen");
    expect(blob.next_seq == 3, "duplicate advances sequence");

    for (uint8_t seed = 2; seed <= 4; ++seed) {
        fill_key(key, seed);
        expect(signing::local_transport_peer_store_upsert(&blob, key), "insert bounded peer");
    }
    expect(blob.count == signing::kLocalTransportMaxPairedPeers, "store reaches max peers");

    fill_key(key, 9);
    expect(!signing::local_transport_peer_store_upsert(&blob, key), "new peer rejected when full");
    expect(blob.count == signing::kLocalTransportMaxPairedPeers, "full reject preserves count");

    blob.version = 99;
    expect(!signing::local_transport_peer_store_valid(blob), "invalid version rejected");

    return 0;
}
CPP

c++ -std=c++17 \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_TRANSPORT_DIR}" \
  "${COMMON_TRANSPORT_DIR}/local_transport_peer_store.cpp" \
  "${TMP_DIR}/local_transport_peer_store_test.cpp" \
  -o "${TMP_DIR}/local_transport_peer_store_test"

"${TMP_DIR}/local_transport_peer_store_test"
