import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createAgentQProvider, AgentQProvider } from "../dist/provider.js";
import { FORBIDDEN_SECRET_FIELD_NAMES } from "@stelis/agent-q-client/protocol";

function assertNoSecretFields(value) {
  const text = JSON.stringify(value).toLowerCase();
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.equal(text.includes(fieldName.toLowerCase()), false, `${fieldName} must not appear in provider output`);
  }
  assert.equal(text.includes("sessionid"), false, "sessionId must not appear in provider output");
}

function createFakeCore() {
  return {
    async scanDevices() {
      return { source: "live", devices: [], failures: [], activeDeviceId: null };
    },
    async identifyDevices() {
      return { source: "live", devices: [], activeDeviceId: null };
    },
    async selectDevice(input) {
      return {
        source: "selected",
        activeDeviceId: input.deviceId,
        purpose: input.purpose ?? null,
        device: {
          deviceId: input.deviceId,
          state: "idle",
          firmwareName: "Agent-Q Firmware",
          hardware: "stackchan-cores3",
          firmwareVersion: "0.0.0",
        },
      };
    },
    async listDevices() {
      return { source: "list", devices: [], activeDeviceId: null, activeDeviceIdsByPurpose: {} };
    },
    async connectDevice() {
      return {
        source: "connected",
        deviceId: "device-1",
        sessionTtlMs: 60000,
        connectedAt: "2026-06-02T00:00:00.000Z",
        device: {
          deviceId: "device-1",
          state: "idle",
          firmwareName: "Agent-Q Firmware",
          hardware: "stackchan-cores3",
          firmwareVersion: "0.0.0",
        },
      };
    },
    async disconnectDevice() {
      return { source: "disconnected", deviceId: "device-1", reason: "firmware_confirmed" };
    },
    async getCapabilities() {
      return {
        source: "live",
        deviceId: "device-1",
        capabilities: [{ id: "sui", accounts: [], methods: [] }],
      };
    },
    async getAccounts() {
      return { source: "live", deviceId: "device-1", accounts: [] };
    },
    async getPolicy() {
      return {
        source: "live",
        deviceId: "device-1",
        policy: {
          schema: "agentq.policy.v0",
          policyId: "sha256:4d180eb74c192a7952def9d3932128bd91dac4ebbe9fe96e21eeb32671f441ab",
          defaultAction: "reject",
          ruleCount: 0,
        },
      };
    },
    async getApprovalHistory() {
      return { source: "live", deviceId: "device-1", records: [], hasMore: false };
    },
  };
}

test("provider package metadata exposes only provider entrypoints", async () => {
  const packagePath = fileURLToPath(new URL("../package.json", import.meta.url));
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  assert.equal(packageJson.name, "@stelis/agent-q-provider");
  assert.deepEqual(Object.keys(packageJson.exports).sort(), [".", "./package.json", "./provider"]);
  assert.equal(packageJson.dependencies["@stelis/agent-q-client"], "0.0.0");
  assert.equal(packageJson.dependencies["@stelis/agent-q-mcp"], undefined);
  assert.equal(packageJson.bin, undefined);
});

test("provider package self-reference resolves provider only", async () => {
  const root = await import("@stelis/agent-q-provider");
  const provider = await import("@stelis/agent-q-provider/provider");
  assert.equal(typeof root.createAgentQProvider, "function");
  assert.equal(typeof provider.AgentQProvider, "function");
  await assert.rejects(() => import("@stelis/agent-q-provider/mcp"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
  await assert.rejects(() => import("@stelis/agent-q-provider/admin"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
});

test("provider does not import MCP or Admin adapters", async () => {
  const providerPath = fileURLToPath(new URL("../dist/provider.js", import.meta.url));
  const source = await readFile(providerPath, "utf8");
  assert.doesNotMatch(source, /@stelis\/agent-q-mcp/);
  assert.doesNotMatch(source, /mcp/i);
  assert.doesNotMatch(source, /admin/i);
});

test("provider exposes only device-facing adapter API", () => {
  const provider = createAgentQProvider({ core: createFakeCore() });
  const methodNames = Object.getOwnPropertyNames(Object.getPrototypeOf(provider))
    .filter((name) => name !== "constructor")
    .sort();
  assert.equal(provider instanceof AgentQProvider, true);
  assert.deepEqual(methodNames, [
    "connectDevice",
    "disconnectDevice",
    "getAccounts",
    "getApprovalHistory",
    "getCapabilities",
    "getPolicy",
    "identifyDevices",
    "listDevices",
    "scanDevices",
    "selectDevice",
  ]);
});

test("provider delegates current methods without exposing session ids or secrets", async () => {
  const provider = createAgentQProvider({ core: createFakeCore() });
  const outputs = [
    await provider.scanDevices(),
    await provider.identifyDevices(),
    await provider.selectDevice({ deviceId: "device-1" }),
    await provider.listDevices(),
    await provider.connectDevice({ deviceId: "device-1" }),
    await provider.disconnectDevice({ deviceId: "device-1" }),
    await provider.getCapabilities({ deviceId: "device-1" }),
    await provider.getAccounts({ deviceId: "device-1" }),
    await provider.getPolicy({ deviceId: "device-1" }),
    await provider.getApprovalHistory({ deviceId: "device-1" }),
  ];
  for (const output of outputs) {
    assertNoSecretFields(output);
  }
});
