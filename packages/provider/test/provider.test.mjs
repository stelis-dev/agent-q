import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createAgentQProvider, AgentQProvider } from "../dist/provider.js";
import { FORBIDDEN_SECRET_FIELD_NAMES, SUI_DERIVATION_PATH } from "@stelis/agent-q-client/protocol";

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
        capabilities: [
          {
            id: "sui",
            accounts: [{ keyScheme: "ed25519", derivationPath: SUI_DERIVATION_PATH }],
            methods: [],
          },
        ],
        signing: {
          user: [{ chain: "sui", method: "sign_transaction" }],
          policy: [{ chain: "sui", method: "sign_transaction" }],
        },
      };
    },
    async getAccounts() {
      return {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            chain: "sui",
            address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
            publicKey: "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk=",
            keyScheme: "ed25519",
            derivationPath: SUI_DERIVATION_PATH,
          },
        ],
      };
    },
    async getPolicy() {
      return {
        source: "live",
        deviceId: "device-1",
        policy: {
          schema: "agentq.policy.v0",
          policyId: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
          defaultAction: "reject",
          ruleCount: 0,
        },
      };
    },
    async getApprovalHistory() {
      return { source: "live", deviceId: "device-1", records: [], hasMore: false };
    },
    async signByUser() {
      return {
        source: "live",
        deviceId: "device-1",
        status: "user_rejected",
        authorization: "user",
        error: {
          code: "user_rejected",
          message: "The signing request was rejected on the device.",
        },
      };
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

test("provider exposes device-facing adapter API including signByUser", () => {
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
    "signByUser",
  ]);
  assert.equal(typeof provider.signByUser, "function");
  assert.equal(provider.signByPolicy, undefined);
  assert.equal(provider.proposePolicyUpdate, undefined);
});

test("provider delegates current methods and signByUser without exposing session ids or secrets", async () => {
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
    await provider.signByUser({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "AQID",
    }),
  ];
  for (const output of outputs) {
    assertNoSecretFields(output);
  }
  const capabilities = outputs[6];
  assert.deepEqual(capabilities.signing, {
    user: [{ chain: "sui", method: "sign_transaction" }],
  });
  assert.equal(JSON.stringify(capabilities).includes('"policy"'), false);
});

test("provider getCapabilities applies the provider capability schema after projection", async () => {
  const core = {
    ...createFakeCore(),
    async getCapabilities() {
      return {
        source: "live",
        deviceId: "device-1",
        capabilities: [
          {
            id: "sui",
            accounts: [{ keyScheme: "ed25519", derivationPath: SUI_DERIVATION_PATH }],
            methods: [],
          },
        ],
        signing: {
          user: [{ chain: "sui", method: "sign_personal_message" }],
          policy: [{ chain: "sui", method: "sign_transaction" }],
        },
      };
    },
  };
  const provider = createAgentQProvider({ core });
  await assert.rejects(
    () => provider.getCapabilities({ deviceId: "device-1" }),
  );
});

test("provider applies output boundary to every custom core method", async () => {
  const calls = [
    ["scanDevices", (provider) => provider.scanDevices()],
    ["identifyDevices", (provider) => provider.identifyDevices()],
    ["selectDevice", (provider) => provider.selectDevice({ deviceId: "device-1" })],
    ["listDevices", (provider) => provider.listDevices()],
    ["connectDevice", (provider) => provider.connectDevice({ deviceId: "device-1" })],
    ["disconnectDevice", (provider) => provider.disconnectDevice({ deviceId: "device-1" })],
    ["getCapabilities", (provider) => provider.getCapabilities({ deviceId: "device-1" })],
    ["getAccounts", (provider) => provider.getAccounts({ deviceId: "device-1" })],
    ["getPolicy", (provider) => provider.getPolicy({ deviceId: "device-1" })],
    ["getApprovalHistory", (provider) => provider.getApprovalHistory({ deviceId: "device-1" })],
    ["signByUser", (provider) => provider.signByUser({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "AQID",
    })],
  ];

  for (const [methodName, callProvider] of calls) {
    const baseCore = createFakeCore();
    const original = baseCore[methodName].bind(baseCore);
    const core = {
      ...baseCore,
      async [methodName](...args) {
        return { ...(await original(...args)), sessionId: "session_should_not_leak" };
      },
    };
    const provider = createAgentQProvider({ core });
    await assert.rejects(
      () => callProvider(provider),
      /forbidden output field/,
      `${methodName} must reject forbidden custom-core output fields`,
    );
  }
});

test("provider signByUser rejects non-user signing results from custom cores", async () => {
  const core = {
    ...createFakeCore(),
    async signByUser() {
      return {
        source: "live",
        deviceId: "device-1",
        status: "policy_rejected",
        authorization: "policy",
        policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
        ruleRef: "default",
        error: {
          code: "policy_rejected",
          message: "The signing request was rejected by device policy.",
        },
      };
    },
  };
  const provider = createAgentQProvider({ core });
  await assert.rejects(() => provider.signByUser({
    deviceId: "device-1",
    chain: "sui",
    method: "sign_transaction",
    network: "devnet",
    txBytes: "AQID",
  }));
});

test("provider does not expose raw method or Admin policy update entrypoints", () => {
  const provider = createAgentQProvider({ core: createFakeCore() });
  assert.equal(provider.signByPolicy, undefined);
  assert.equal(provider.proposePolicyUpdate, undefined);
  assert.equal(typeof provider.signByUser, "function");
});
