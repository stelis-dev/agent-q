import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PUBLIC_ERROR_MESSAGES } from "../dist/public-error.js";

// Drift guard: derive the set of error codes Gateway can actually throw straight
// from source, and assert each one has a canonical message in the public-error
// SoT allowlist. A new `new GatewayError("x", ...)` that forgets to register "x"
// would otherwise silently collapse to gateway_error at every output boundary.
// Codes built from a variable (e.g. a parsed Firmware error code) are not matched
// here; the allowlist is their fail-closed default.
function readSrc(rel) {
  return readFileSync(fileURLToPath(new URL(`../src/${rel}`, import.meta.url)), "utf8");
}

const SRC_FILES = ["config.ts", "core.ts", "protocol.ts", "usb.ts", "mcp.ts"];
const LITERAL_CODE = /new (?:Gateway|Config|Protocol)Error\(\s*"([a-z_]+)"/g;

const producedCodes = new Set();
for (const file of SRC_FILES) {
  for (const match of readSrc(file).matchAll(LITERAL_CODE)) {
    producedCodes.add(match[1]);
  }
}

const allowlist = new Set(Object.keys(PUBLIC_ERROR_MESSAGES));

test("every literal Gateway error code is registered in the public-error allowlist", () => {
  assert.ok(producedCodes.size > 5, "should discover the thrown error codes from source");
  assert.ok(allowlist.has("gateway_error"), "allowlist loaded");
  const missing = [...producedCodes].filter((code) => !allowlist.has(code)).sort();
  assert.deepEqual(
    missing,
    [],
    `error codes thrown in src but missing from PUBLIC_ERROR_MESSAGES: ${missing.join(", ")}`,
  );
});
