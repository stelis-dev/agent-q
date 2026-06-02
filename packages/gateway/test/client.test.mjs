import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createDefaultGatewayCore, GatewayCore } from "../dist/client.js";

test("client entrypoint constructs the default device-facing Gateway core", () => {
  const core = createDefaultGatewayCore();
  assert.equal(core instanceof GatewayCore, true);
});

test("client entrypoint does not import MCP or Admin adapters", async () => {
  const clientPath = fileURLToPath(new URL("../dist/client.js", import.meta.url));
  const source = await readFile(clientPath, "utf8");
  assert.doesNotMatch(source, /["']\.\/mcp\.js["']/);
  assert.doesNotMatch(source, /["']\.\/admin\.js["']/);
});

test("package metadata exposes only the current Gateway library entrypoints", async () => {
  const packagePath = fileURLToPath(new URL("../package.json", import.meta.url));
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  assert.equal(packageJson.main, "./dist/client.js");
  assert.equal(packageJson.types, "./dist/client.d.ts");
  assert.deepEqual(Object.keys(packageJson.exports).sort(), [".", "./client", "./mcp", "./package.json"]);
  assert.deepEqual(packageJson.exports["."], {
    types: "./dist/client.d.ts",
    import: "./dist/client.js",
  });
  assert.deepEqual(packageJson.exports["./client"], {
    types: "./dist/client.d.ts",
    import: "./dist/client.js",
  });
  assert.deepEqual(packageJson.exports["./mcp"], {
    types: "./dist/mcp.d.ts",
    import: "./dist/mcp.js",
  });
  assert.equal(packageJson.exports["./admin"], undefined);
  assert.equal(packageJson.exports["./provider"], undefined);
});

test("package self-reference resolves only the current Gateway library entrypoints", async () => {
  const root = await import("@stelis/agent-q");
  const client = await import("@stelis/agent-q/client");
  const mcp = await import("@stelis/agent-q/mcp");
  assert.equal(typeof root.createDefaultGatewayCore, "function");
  assert.equal(typeof client.createDefaultGatewayCore, "function");
  assert.equal(typeof mcp.createGatewayMcpServer, "function");
  await assert.rejects(() => import("@stelis/agent-q/provider"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
});
