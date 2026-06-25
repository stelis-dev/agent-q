import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { normalizeErrorCode, PUBLIC_ERROR_MESSAGES } from "../dist/public-error.js";

// Drift guard: derive the set of literal error codes Agent-Q can throw straight
// from production sources, and assert each one is a current DeviceErrorCode.
// A new `new AgentQError("x", ...)` or provider-visible error that forgets to
// use a current DeviceErrorCode would otherwise silently collapse to
// unknown_error at every output boundary.
// Codes built from a variable (e.g. a parsed Firmware error code) are not matched
// here; the projection is their fail-closed default.
function sourcePath(rel) {
  return fileURLToPath(new URL(rel, import.meta.url));
}

function listTsFiles(dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const child = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      files.push(...listTsFiles(child));
    } else if (entry.isFile() && entry.name.endsWith(".ts")) {
      files.push(child);
    }
  }
  return files;
}

const SRC_DIRS = [
  sourcePath("../src"),
  sourcePath("../../agent-q/src"),
  sourcePath("../../provider-sui/src"),
];
const SRC_FILES = SRC_DIRS.flatMap((dir) => listTsFiles(dir)).sort();
const LITERAL_CODE = /new\s+(?:AgentQError|ConfigError|ProtocolError|AgentQSuiBrowserProviderError)\(\s*"([a-z_]+)"/g;

const producedCodes = new Set();
for (const file of SRC_FILES) {
  const source = readFileSync(file, "utf8");
  for (const match of source.matchAll(LITERAL_CODE)) {
    producedCodes.add(match[1]);
  }
}

const allowlist = new Set(Object.keys(PUBLIC_ERROR_MESSAGES));
const firmwareProtocolCodes = [
  "rng_unavailable",
  "account_unavailable",
  "policy_unavailable",
  "history_unavailable",
  "request_id_conflict",
  "unsupported_chain",
  "payload_too_large",
  "malformed_transaction",
  "invalid_response",
];

test("every literal Agent-Q error code is a current public error", () => {
  assert.ok(producedCodes.size > 20, "should discover thrown error codes across source packages");
  for (const expected of ["handshake_failed", "timeout", "unsupported_transport", "invalid_request"]) {
    assert.ok(producedCodes.has(expected), `source scan should include ${expected}`);
  }
  assert.ok(allowlist.has("unknown_error"), "public error projection loaded");
  const missing = [...producedCodes].filter((code) => !allowlist.has(code)).sort();
  assert.deepEqual(
    missing,
    [],
    `error codes thrown in src but missing from PUBLIC_ERROR_MESSAGES: ${missing.join(", ")}`,
  );
});

test("Firmware-emitted runtime error codes are public Agent-Q errors", () => {
  for (const code of firmwareProtocolCodes) {
    assert.ok(allowlist.has(code), `${code} should be registered`);
    assert.equal(normalizeErrorCode(code), code);
  }
});
