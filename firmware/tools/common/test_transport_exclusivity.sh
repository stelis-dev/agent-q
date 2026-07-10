#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/transport-exclusivity.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>

#include "transport/transport_exclusivity.h"

int main()
{
    using signing::TransportExclusivityAction;
    using signing::TransportExclusivityState;

    const TransportExclusivityState idle{};
    assert(signing::secondary_transport_entry_allowed(idle));
    assert(signing::transport_exclusivity_action(idle) ==
           TransportExclusivityAction::none);

    const TransportExclusivityState primary_only{true, false};
    assert(!signing::secondary_transport_entry_allowed(primary_only));
    assert(signing::transport_exclusivity_action(primary_only) ==
           TransportExclusivityAction::none);

    const TransportExclusivityState secondary_only{false, true};
    assert(!signing::secondary_transport_entry_allowed(secondary_only));
    assert(signing::transport_exclusivity_action(secondary_only) ==
           TransportExclusivityAction::none);

    const TransportExclusivityState both{true, true};
    assert(!signing::secondary_transport_entry_allowed(both));
    assert(signing::transport_exclusivity_action(both) ==
           TransportExclusivityAction::close_secondary_transport);

    printf("Transport exclusivity tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
