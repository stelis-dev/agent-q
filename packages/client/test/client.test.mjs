import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createDefaultDeviceClientCore } from "../dist/client.js";
import { createDefaultGatewayCore, GatewayCore } from "../dist/admin.js";

test("client entrypoint constructs an admin-disabled device core facade", () => {
  const core = createDefaultDeviceClientCore();
  assert.equal(typeof core.scanDevices, "function");
  assert.equal(typeof core.signTransaction, "function");
  assert.equal(core.signByUser, undefined);
  assert.equal(core.signByPolicy, undefined);
  assert.equal(core.policyPropose, undefined);
});

test("admin entrypoint constructs the admin-capable Gateway core", () => {
  const core = createDefaultGatewayCore();
  assert.equal(core instanceof GatewayCore, true);
});

test("client entrypoint does not import MCP or Admin adapters", async () => {
  const clientPath = fileURLToPath(new URL("../dist/client.js", import.meta.url));
  const source = await readFile(clientPath, "utf8");
  assert.doesNotMatch(source, /["']\.\/mcp\.js["']/);
  assert.doesNotMatch(source, /["']\.\/admin\.js["']/);
});

test("package metadata exposes the current client entrypoints", async () => {
  const packagePath = fileURLToPath(new URL("../package.json", import.meta.url));
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  assert.equal(packageJson.name, "@stelis/agent-q-client");
  assert.equal(packageJson.main, "./dist/client.js");
  assert.equal(packageJson.types, "./dist/client.d.ts");
  assert.deepEqual(Object.keys(packageJson.exports).sort(), [
    ".",
    "./adapter-internal",
    "./admin",
    "./client",
    "./package.json",
    "./protocol",
  ]);
  assert.deepEqual(packageJson.exports["."], {
    types: "./dist/client.d.ts",
    import: "./dist/client.js",
  });
  assert.deepEqual(packageJson.exports["./client"], {
    types: "./dist/client.d.ts",
    import: "./dist/client.js",
  });
  assert.deepEqual(packageJson.exports["./admin"], {
    types: "./dist/admin.d.ts",
    import: "./dist/admin.js",
  });
  assert.equal(packageJson.exports["./usb"], undefined);
  assert.equal(packageJson.bin, undefined);
  assert.equal(packageJson.exports["./mcp"], undefined);
  assert.equal(packageJson.exports["./provider"], undefined);
});

test("package self-reference resolves only client entrypoints", async () => {
  const root = await import("@stelis/agent-q-client");
  const admin = await import("@stelis/agent-q-client/admin");
  const adapterInternal = await import("@stelis/agent-q-client/adapter-internal");
  const client = await import("@stelis/agent-q-client/client");
  const protocol = await import("@stelis/agent-q-client/protocol");
  assert.equal(typeof root.createDefaultDeviceClientCore, "function");
  assert.equal(root.createDefaultGatewayCore, undefined);
  assert.equal(typeof admin.createDefaultGatewayCore, "function");
  assert.equal(typeof adapterInternal.gatewaySuccessOutputSchemas, "object");
  assert.equal(typeof client.createDefaultDeviceClientCore, "function");
  assert.equal(typeof protocol.makeGetStatusRequest, "function");
  assert.equal(typeof protocol.makeSignTransactionRequest, "function");
  assert.equal(typeof admin.SerialPortUsbDriver, "function");
  for (const subpath of ["config", "core", "errors", "gateway-output-schema", "public-error", "safe-text", "usb"]) {
    await assert.rejects(() => import(`@stelis/agent-q-client/${subpath}`), {
      code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
    });
  }
  await assert.rejects(() => import("@stelis/agent-q-client/mcp"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
  await assert.rejects(() => import("@stelis/agent-q-client/provider"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
});
