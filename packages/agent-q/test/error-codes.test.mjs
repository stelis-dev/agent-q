import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PUBLIC_ERROR_MESSAGES } from "@stelis/agent-q-core/adapter-internal";

function readSrc(rel) {
  return readFileSync(fileURLToPath(new URL(`../src/${rel}`, import.meta.url)), "utf8");
}

const SRC_FILES = ["local-api.ts", "mcp.ts", "sui-signer-local-client.ts", "bin/agent-q.ts"];
const LITERAL_CODE = /new AgentQError\(\s*"([a-z_]+)"/g;

const producedCodes = new Set();
for (const file of SRC_FILES) {
  for (const match of readSrc(file).matchAll(LITERAL_CODE)) {
    producedCodes.add(match[1]);
  }
}

const allowlist = new Set(Object.keys(PUBLIC_ERROR_MESSAGES));

test("every literal MCP/Admin Agent-Q error code is registered in the public-error allowlist", () => {
  assert.ok(producedCodes.size > 0, "should discover adapter error codes from source");
  const missing = [...producedCodes].filter((code) => !allowlist.has(code)).sort();
  assert.deepEqual(
    missing,
    [],
    `error codes thrown in MCP/Admin src but missing from PUBLIC_ERROR_MESSAGES: ${missing.join(", ")}`,
  );
});
