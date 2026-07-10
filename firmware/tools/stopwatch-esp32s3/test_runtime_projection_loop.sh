#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
APP_CPP="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime/app.cpp"

if [[ ! -f "${APP_CPP}" ]]; then
  echo "Missing app source: ${APP_CPP}" >&2
  exit 1
fi

ON_RUNNING_BODY="$(
  awk '
    /^void RuntimeApp::onRunning\(\)$/ {
      pending = 1
      next
    }
    pending && /^\{/ {
      depth = 1
      capture = 1
      pending = 0
      print
      next
    }
    capture {
      line = $0
      print line
      opens = gsub(/\{/, "{", line)
      closes = gsub(/\}/, "}", line)
      depth += opens - closes
      if (depth == 0) {
        exit
      }
    }
  ' "${APP_CPP}"
)"

if [[ -z "${ON_RUNNING_BODY}" ]]; then
  echo "Could not extract RuntimeApp::onRunning body" >&2
  exit 1
fi

SNAPSHOT_COUNT="$(printf '%s\n' "${ON_RUNNING_BODY}" | grep -c 'local_auth_snapshot(' || true)"
if [[ "${SNAPSHOT_COUNT}" -ne 1 ]]; then
  echo "RuntimeApp::onRunning must read local_auth_snapshot exactly once; found ${SNAPSHOT_COUNT}" >&2
  exit 1
fi

if printf '%s\n' "${ON_RUNNING_BODY}" | grep -q 'sync_protocol_runtime_state();'; then
  echo "RuntimeApp::onRunning must reuse its LocalAuthSnapshot instead of calling sync_protocol_runtime_state()" >&2
  exit 1
fi

if printf '%s\n' "${ON_RUNNING_BODY}" | grep -q 'refresh_auth_mode();'; then
  echo "RuntimeApp::onRunning must reuse its LocalAuthSnapshot instead of calling refresh_auth_mode()" >&2
  exit 1
fi

echo "StopWatch runtime projection loop structure test passed"
