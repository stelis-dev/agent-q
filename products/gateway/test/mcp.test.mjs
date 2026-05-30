import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { GatewayError } from "../dist/errors.js";
import { createGatewayMcpServer, gatewayToolDefinitions } from "../dist/mcp.js";
import { FORBIDDEN_SECRET_FIELD_NAMES } from "../dist/protocol.js";

const expectedToolNames = [
  "connect_device",
  "disconnect_device",
  "get_accounts",
  "get_capabilities",
  "get_device_status",
  "identify_devices",
  "list_devices",
  "scan_devices",
  "select_device",
  "set_device_metadata",
];

const noOpCore = {
  async scanDevices() {
    return { source: "live", devices: [], activeDeviceId: null };
  },
  async getDeviceStatus() {
    return {
      source: "live",
      connected: true,
      portPath: "/dev/cu.usbmodem1",
      protocolResponse: {
        id: "req_status",
        version: 1,
        type: "status",
        device: {
          deviceId: "device-1",
          state: "idle",
          firmwareName: "Agent-Q Firmware",
          hardware: "hardware-id",
          firmwareVersion: "0.0.0",
        },
        provisioning: {
          state: "unprovisioned",
        },
      },
    };
  },
  async identifyDevices() {
    return { source: "live", devices: [], activeDeviceId: null };
  },
  async selectDevice() {
    return {
      source: "selected",
      activeDeviceId: "device-1",
      purpose: null,
      device: {
        deviceId: "device-1",
        state: "idle",
        firmwareName: "Agent-Q Firmware",
        hardware: "hardware-id",
        firmwareVersion: "0.0.0",
      },
    };
  },
  async listDevices() {
    return { source: "list", devices: [], activeDeviceId: null, activeDeviceIdsByPurpose: {} };
  },
  async setDeviceMetadata() {
    return { source: "metadata", deviceId: "device-1", label: null };
  },
  async connectDevice() {
    return {
      source: "connected",
      deviceId: "device-1",
      reused: false,
      sessionTtlMs: 1800000,
      connectedAt: "2026-05-28T00:00:00.000Z",
      expiresAt: "2026-05-28T00:30:00.000Z",
      device: {
        deviceId: "device-1",
        state: "idle",
        firmwareName: "Agent-Q Firmware",
        hardware: "hardware-id",
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
          accounts: [
            {
              keyScheme: "ed25519",
              derivationPath: "m/44'/784'/0'/0'/0'",
            },
          ],
          methods: [],
        },
      ],
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
          derivationPath: "m/44'/784'/0'/0'/0'",
        },
      ],
    };
  },
};

test("registers the full device tool set", () => {
  assert.deepEqual(
    Object.values(gatewayToolDefinitions).map((tool) => tool.name).sort(),
    expectedToolNames,
  );
});

test("tool input schemas do not expose secret fields", () => {
  const schemaKeys = new Set();
  for (const tool of Object.values(gatewayToolDefinitions)) {
    for (const key of Object.keys(tool.inputSchema)) {
      schemaKeys.add(key.toLowerCase());
    }
  }

  for (const forbidden of [...FORBIDDEN_SECRET_FIELD_NAMES, "sessionId", "session_id"]) {
    assert.equal(schemaKeys.has(forbidden.toLowerCase()), false, `forbidden key ${forbidden} must not appear`);
  }
});

test("connect_device output omits sessionId and secret fields", () => {
  const sample = gatewayToolDefinitions.connectDevice.outputSchema.safeParse({
    source: "connected",
    deviceId: "device-1",
    reused: false,
    sessionTtlMs: 1800000,
    connectedAt: "2026-05-28T00:00:00.000Z",
    expiresAt: "2026-05-28T00:30:00.000Z",
    device: {
      deviceId: "device-1",
      state: "idle",
      firmwareName: "Agent-Q Firmware",
      hardware: "hardware-id",
      firmwareVersion: "0.0.0",
    },
  });
  assert.equal(sample.success, true);

  // sessionId must be rejected: it is a Firmware token Gateway keeps internal.
  const withSessionId = gatewayToolDefinitions.connectDevice.outputSchema.safeParse({
    source: "connected",
    deviceId: "device-1",
    reused: false,
    sessionId: "session_aabbccdd",
    sessionTtlMs: 1800000,
    connectedAt: "2026-05-28T00:00:00.000Z",
    expiresAt: "2026-05-28T00:30:00.000Z",
    device: {
      deviceId: "device-1",
      state: "idle",
      firmwareName: "Agent-Q Firmware",
      hardware: "hardware-id",
      firmwareVersion: "0.0.0",
    },
  });
  // Zod strips unknown keys by default, so success is fine; assert the parsed
  // output does not carry sessionId through.
  assert.equal(withSessionId.success, true);
  assert.equal("sessionId" in withSessionId.data, false);

  for (const shape of [
    gatewayToolDefinitions.connectDevice.outputSchema,
    gatewayToolDefinitions.listDevices.outputSchema,
  ]) {
    const flat = JSON.stringify(shape).toLowerCase();
    for (const forbidden of [...FORBIDDEN_SECRET_FIELD_NAMES, "sessionId"]) {
      assert.equal(flat.includes(forbidden), false, `${forbidden} must not appear in schema`);
    }
  }
});

test("status output schema rejects unreachable source combinations", () => {
  const result = gatewayToolDefinitions.getDeviceStatus.outputSchema.safeParse({
    source: "live",
    connected: false,
    error: {
      code: "no_active_device",
      message: "No active device is configured.",
      retryable: false,
    },
  });

  assert.equal(result.success, false);
});

test("exported output schema rejects raw error text and unknown firmware codes", () => {
  const rawError = {
    source: "error",
    connected: false,
    error: { code: "handshake_failed", message: "session_LEAK raw text", retryable: true },
  };
  assert.equal(
    gatewayToolDefinitions.connectDevice.outputSchema.safeParse(rawError).success,
    false,
    "exported schema must reject a non-canonical (raw) error message",
  );

  const canonicalError = {
    source: "error",
    connected: false,
    error: {
      code: "handshake_failed",
      message: "The device did not respond to a status handshake.",
      retryable: true,
    },
  };
  assert.equal(
    gatewayToolDefinitions.connectDevice.outputSchema.safeParse(canonicalError).success,
    true,
    "exported schema accepts a canonical public error",
  );

  const device = { deviceId: "device-1", state: "idle", firmwareName: "f", hardware: "h", firmwareVersion: "0" };
  const cachedRawCode = {
    source: "cached",
    connected: false,
    statusObservedAt: "2026-05-28T00:00:00.000Z",
    unavailableReason: "handshake_failed",
    firmwareErrorCode: "weird_raw_code",
    cachedStatus: { device, provisioning: { state: "unprovisioned" } },
  };
  assert.equal(
    gatewayToolDefinitions.getDeviceStatus.outputSchema.safeParse(cachedRawCode).success,
    false,
    "exported schema must reject an unknown firmwareErrorCode",
  );
});

test("get_device_status exposes timeoutMs", () => {
  assert.equal("timeoutMs" in gatewayToolDefinitions.getDeviceStatus.inputSchema, true);
});

test("select_device input accepts purpose but rejects reserved 'default'", () => {
  const inputSchema = gatewayToolDefinitions.selectDevice.inputSchema.purpose;
  assert.equal(inputSchema.safeParse("payment").success, true);
  assert.equal(inputSchema.safeParse("default").success, false);
  assert.equal(inputSchema.safeParse("has space").success, false);
  assert.equal(inputSchema.safeParse("__proto__").success, false, "prototype-sensitive purpose rejected at input");
  assert.equal(inputSchema.safeParse("constructor").success, false);
});

test("can construct the MCP server with the full core", () => {
  const server = createGatewayMcpServer(noOpCore);
  assert.equal(server.isConnected(), false);
});

test("MCP tool descriptions disclose USB status handshake writes", () => {
  const byName = Object.fromEntries(
    Object.values(gatewayToolDefinitions).map((tool) => [tool.name, tool]),
  );

  const handshakeTools = ["scan_devices", "identify_devices", "get_device_status", "connect_device", "disconnect_device"];
  for (const toolName of handshakeTools) {
    assert.match(
      byName[toolName].description,
      /status handshake/i,
      `${toolName} description must disclose status handshake`,
    );
  }

  const localOnlyTools = ["list_devices", "set_device_metadata", "select_device"];
  for (const toolName of localOnlyTools) {
    assert.equal(
      /status handshake/i.test(byName[toolName].description),
      false,
      `${toolName} description must not falsely claim a USB handshake`,
    );
  }
});

async function withConnectedClient(run, core = noOpCore) {
  const server = createGatewayMcpServer(core);
  const client = new Client({ name: "agent-q-test-client", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    return await run(client);
  } finally {
    await client.close();
    await server.close();
  }
}

// Applied to every dispatched MCP result. MCP clients are untrusted request
// sources; no Firmware session token or key-like field may reach them.
function assertNoSecretFields(result, toolName) {
  const flat = JSON.stringify(result).toLowerCase();
  for (const forbidden of [...FORBIDDEN_SECRET_FIELD_NAMES, "sessionId", "session_id"]) {
    assert.equal(
      flat.includes(forbidden.toLowerCase()),
      false,
      `${toolName}: '${forbidden}' must not appear in the dispatched result`,
    );
  }
}

// Minimal valid arguments to drive each tool through the SDK input-schema and
// dispatch path. noOpCore ignores argument values and returns a success result.
const dispatchCases = [
  { name: "scan_devices", arguments: {} },
  { name: "identify_devices", arguments: {} },
  { name: "select_device", arguments: { deviceId: "device-1" } },
  { name: "get_device_status", arguments: {} },
  { name: "list_devices", arguments: {} },
  { name: "set_device_metadata", arguments: { deviceId: "device-1", label: null } },
  { name: "connect_device", arguments: {} },
  { name: "disconnect_device", arguments: {} },
  { name: "get_capabilities", arguments: {} },
  { name: "get_accounts", arguments: {} },
];

test("MCP client lists exactly the Agent-Q tool set over a real transport", async () => {
  await withConnectedClient(async (client) => {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name).sort(), expectedToolNames);
  });
});

test("every MCP tool dispatches cleanly with structured content and no secrets", async () => {
  await withConnectedClient(async (client) => {
    for (const dispatchCase of dispatchCases) {
      const result = await client.callTool(dispatchCase);

      // Regression guard for the union-output-schema crash: a validation crash
      // surfaced as isError with a "_zod" / "Output validation error" message.
      const text = (result.content ?? [])
        .map((part) => (part.type === "text" ? part.text : ""))
        .join(" ");
      assert.doesNotMatch(
        text,
        /_zod|output validation error/i,
        `${dispatchCase.name}: dispatch must not raise an output-validation crash`,
      );

      assert.equal(
        typeof result.structuredContent,
        "object",
        `${dispatchCase.name}: structuredContent must be present`,
      );
      assert.notEqual(result.structuredContent, null);
      assertNoSecretFields(result, dispatchCase.name);
    }
  });
});

test("connect_device dispatch returns a connected result without a session token", async () => {
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "connect_device", arguments: {} });
    assert.equal(result.structuredContent.source, "connected");
    assert.equal("sessionId" in result.structuredContent, false, "sessionId must not reach the client");
  });
});

test("get_accounts dispatch returns the public Sui account without a session token", async () => {
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_accounts", arguments: {} });
    assert.equal(result.structuredContent.source, "live");
    assert.equal(result.structuredContent.accounts.length, 1);
    assert.equal(result.structuredContent.accounts[0].chain, "sui");
    assert.equal(
      result.structuredContent.accounts[0].address,
      "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
    );
    assert.equal("sessionId" in result.structuredContent, false, "sessionId must not reach the client");
  });
});

test("get_capabilities dispatch returns current capabilities without a session token", async () => {
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_capabilities", arguments: {} });
    assert.equal(result.structuredContent.source, "live");
    assert.equal(result.structuredContent.capabilities.length, 1);
    assert.equal(result.structuredContent.capabilities[0].id, "sui");
    assert.equal(result.structuredContent.capabilities[0].accounts[0].keyScheme, "ed25519");
    assert.deepEqual(result.structuredContent.capabilities[0].methods, []);
    assert.equal("sessionId" in result.structuredContent, false, "sessionId must not reach the client");
  });
});

// Distinctive markers a leaking core would smuggle in. Searched for as
// substrings across the entire dispatched result (structuredContent + text).
const LEAK_MARKERS = ["session_leak", "privatekey_leak", "seed_leak"];

function assertNoLeakMarkers(result, toolName) {
  const flat = JSON.stringify(result).toLowerCase();
  for (const marker of LEAK_MARKERS) {
    assert.equal(flat.includes(marker), false, `${toolName}: leaked '${marker}' through the MCP boundary`);
  }
}

// A core that returns otherwise-valid success shapes with extra secret-like
// fields spread in. The MCP boundary must strip them.
const SECRET_EXTRAS = { sessionId: "SESSION_LEAK", privateKey: "PRIVATEKEY_LEAK", seed: "SEED_LEAK" };

const leakyCore = {
  async scanDevices() {
    return { source: "live", devices: [], activeDeviceId: null, ...SECRET_EXTRAS };
  },
  async identifyDevices() {
    return { source: "live", devices: [], activeDeviceId: null, ...SECRET_EXTRAS };
  },
  async selectDevice() {
    return {
      source: "selected",
      activeDeviceId: "device-1",
      purpose: null,
      device: { deviceId: "device-1", state: "idle", firmwareName: "f", hardware: "h", firmwareVersion: "0" },
      ...SECRET_EXTRAS,
    };
  },
  async getDeviceStatus() {
    return {
      source: "live",
      connected: true,
      portPath: "/dev/cu.usbmodem1",
      protocolResponse: {
        id: "req_status",
        version: 1,
        type: "status",
        device: { deviceId: "device-1", state: "idle", firmwareName: "f", hardware: "h", firmwareVersion: "0" },
        provisioning: { state: "unprovisioned" },
      },
      ...SECRET_EXTRAS,
    };
  },
  async listDevices() {
    return { source: "list", devices: [], activeDeviceId: null, activeDeviceIdsByPurpose: {}, ...SECRET_EXTRAS };
  },
  async setDeviceMetadata() {
    return { source: "metadata", deviceId: "device-1", label: null, ...SECRET_EXTRAS };
  },
  async connectDevice() {
    return {
      source: "connected",
      deviceId: "device-1",
      reused: false,
      sessionTtlMs: 1800000,
      connectedAt: "2026-05-28T00:00:00.000Z",
      expiresAt: "2026-05-28T00:30:00.000Z",
      device: { deviceId: "device-1", state: "idle", firmwareName: "f", hardware: "h", firmwareVersion: "0" },
      ...SECRET_EXTRAS,
    };
  },
  async disconnectDevice() {
    return { source: "disconnected", deviceId: "device-1", reason: "firmware_confirmed", ...SECRET_EXTRAS };
  },
  async getCapabilities() {
    return {
      source: "live",
      deviceId: "device-1",
      capabilities: [
        {
          id: "sui",
          accounts: [
            {
              keyScheme: "ed25519",
              derivationPath: "m/44'/784'/0'/0'/0'",
            },
          ],
          methods: [],
        },
      ],
      ...SECRET_EXTRAS,
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
          derivationPath: "m/44'/784'/0'/0'/0'",
        },
      ],
      ...SECRET_EXTRAS,
    };
  },
};

test("MCP boundary strips secret-like extra fields from every success result", async () => {
  await withConnectedClient(async (client) => {
    for (const dispatchCase of dispatchCases) {
      const result = await client.callTool(dispatchCase);
      assert.equal(result.isError ?? false, false, `${dispatchCase.name}: leaky-but-valid success must dispatch ok`);
      assertNoLeakMarkers(result, dispatchCase.name);
    }
  }, leakyCore);
});

test("get_device_status error-shaped success cannot leak out as a success", async () => {
  const errorShapedCore = {
    ...noOpCore,
    async getDeviceStatus() {
      // Not a live | cached shape: it must NOT pass the success sanitizer.
      return { source: "error", connected: false, error: { code: "boom", message: "raw", retryable: false } };
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_device_status", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.source, "error");
    assert.equal(result.structuredContent.error.code, "internal_output_error");
  }, errorShapedCore);
});

test("get_accounts unreachable shape (live without accounts) cannot leak out as a success", async () => {
  const malformedCore = {
    ...noOpCore,
    async getAccounts() {
      // A "live" result must carry accounts. The egress guard must reject this
      // unreachable shape instead of dispatching it as a success.
      return { source: "live", deviceId: "device-1" };
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_accounts", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "internal_output_error");
  }, malformedCore);
});

test("get_capabilities unreachable shape (live with signing method) cannot leak out as a success", async () => {
  const malformedCore = {
    ...noOpCore,
    async getCapabilities() {
      return {
        source: "live",
        deviceId: "device-1",
        capabilities: [
          {
            id: "sui",
            accounts: [
              {
                keyScheme: "ed25519",
                derivationPath: "m/44'/784'/0'/0'/0'",
              },
            ],
            methods: ["sign_transaction"],
          },
        ],
      };
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_capabilities", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "internal_output_error");
  }, malformedCore);
});

test("get_accounts unreachable shape (live with no accounts) cannot leak out as a success", async () => {
  const malformedCore = {
    ...noOpCore,
    async getAccounts() {
      // The current target has exactly one Sui account; an empty live result is
      // as unreachable as a missing accounts field.
      return { source: "live", deviceId: "device-1", accounts: [] };
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_accounts", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "internal_output_error");
  }, malformedCore);
});

test("get_accounts rejects a public key that does not match the Sui address", async () => {
  const malformedCore = {
    ...noOpCore,
    async getAccounts() {
      return {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            chain: "sui",
            address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
            publicKey: "vG6hEnkYNIpdmWa/WaLivd1FWBkxG+HfhXkyWgs9uP4=",
            keyScheme: "ed25519",
            derivationPath: "m/44'/784'/0'/0'/0'",
          },
        ],
      };
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_accounts", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "internal_output_error");
  }, malformedCore);
});

test("session lifecycle result reasons are source-specific at the MCP boundary", async () => {
  const cases = [
    {
      name: "disconnect_device",
      result: { source: "not_connected", deviceId: "device-1", reason: "firmware_confirmed" },
    },
    {
      name: "get_accounts",
      result: { source: "not_connected", deviceId: "device-1", reason: "firmware_confirmed" },
    },
    {
      name: "get_capabilities",
      result: { source: "not_connected", deviceId: "device-1", reason: "firmware_confirmed" },
    },
    {
      name: "get_accounts",
      result: { source: "session_ended", deviceId: "device-1", reason: "not_connected" },
    },
    {
      name: "get_capabilities",
      result: { source: "session_ended", deviceId: "device-1", reason: "not_connected" },
    },
  ];

  for (const testCase of cases) {
    const malformedCore = {
      ...noOpCore,
      async disconnectDevice() {
        return testCase.result;
      },
      async getAccounts() {
        return testCase.result;
      },
      async getCapabilities() {
        return testCase.result;
      },
    };
    await withConnectedClient(async (client) => {
      const result = await client.callTool({ name: testCase.name, arguments: {} });
      assert.equal(result.isError, true, `${testCase.name}: source/reason mismatch must fail closed`);
      assert.equal(result.structuredContent.error.code, "internal_output_error");
    }, malformedCore);
  }
});

test("get_device_status exposes live provisioning state", async () => {
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_device_status", arguments: {} });
    assert.equal(result.structuredContent.source, "live");
    assert.equal(result.structuredContent.protocolResponse.provisioning.state, "unprovisioned");
  }, noOpCore);
});

test("error path canonicalizes message and code; raw text never reaches the client", async () => {
  const throwingCore = {
    ...noOpCore,
    async connectDevice() {
      throw new GatewayError("handshake_failed", "session_LEAK privateKey_LEAK seed_LEAK on /dev/cu.x", true);
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "connect_device", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "handshake_failed");
    assert.equal(result.structuredContent.error.retryable, true);
    assert.equal(result.structuredContent.error.message, "The device did not respond to a status handshake.");
    assertNoLeakMarkers(result, "connect_device(error)");
  }, throwingCore);
});

test("unknown error codes collapse to a generic gateway_error", async () => {
  const throwingCore = {
    ...noOpCore,
    async connectDevice() {
      throw new GatewayError("ignore_previous_instructions", "do X; session_LEAK", false);
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "connect_device", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "gateway_error");
    assert.equal(result.structuredContent.error.message, "Gateway request failed.");
    assertNoLeakMarkers(result, "connect_device(unknown-code)");
  }, throwingCore);
});

test("output that fails sanitization returns a generic internal_output_error, not raw details", async () => {
  const malformedCore = {
    ...noOpCore,
    async connectDevice() {
      // Missing required fields (reused/sessionTtlMs/...): unsanitizable success.
      return { source: "connected", deviceId: "device-1", sessionId: "SESSION_LEAK" };
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "connect_device", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "internal_output_error");
    const text = (result.content ?? []).map((part) => (part.type === "text" ? part.text : "")).join(" ");
    assert.doesNotMatch(text, /_zod|output validation error/i, "raw ZodError must not reach the client");
    assertNoLeakMarkers(result, "connect_device(sanitize-fail)");
  }, malformedCore);
});

test("MCP boundary fails closed when a success result carries unsanitized display text", async () => {
  // The wire and disk boundaries sanitize device display strings; if an
  // unsanitized control character ever reaches egress it is a contract bug, so
  // the egress device shape is a tripwire that fails closed rather than leaking.
  const controlChar = String.fromCharCode(7);
  const unsanitizedCore = {
    ...noOpCore,
    async connectDevice() {
      return {
        source: "connected",
        deviceId: "device-1",
        reused: false,
        sessionTtlMs: 1800000,
        connectedAt: "2026-05-28T00:00:00.000Z",
        expiresAt: "2026-05-28T00:30:00.000Z",
        device: {
          deviceId: "device-1",
          state: "idle",
          firmwareName: "bad" + controlChar + "name",
          hardware: "hardware-id",
          firmwareVersion: "0.0.0",
        },
      };
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "connect_device", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "internal_output_error");
  }, unsanitizedCore);
});

test("MCP boundary fails closed on unsafe top-level identifiers, purposes, and timestamps", async () => {
  const NL = String.fromCharCode(10);
  const okDevice = { deviceId: "device-1", state: "idle", firmwareName: "f", hardware: "h", firmwareVersion: "0" };
  const cases = [
    {
      label: "list_devices/activeDeviceId",
      name: "list_devices",
      args: {},
      core: {
        ...noOpCore,
        async listDevices() {
          return { source: "list", devices: [], activeDeviceId: "bad" + NL + "id", activeDeviceIdsByPurpose: {} };
        },
      },
    },
    {
      label: "list_devices/purposeKey",
      name: "list_devices",
      args: {},
      core: {
        ...noOpCore,
        async listDevices() {
          return { source: "list", devices: [], activeDeviceId: null, activeDeviceIdsByPurpose: { ["bad purpose"]: "device-1" } };
        },
      },
    },
    {
      label: "select_device/purpose",
      name: "select_device",
      args: { deviceId: "device-1" },
      core: {
        ...noOpCore,
        async selectDevice() {
          return { source: "selected", activeDeviceId: "device-1", purpose: "bad purpose", device: okDevice };
        },
      },
    },
    {
      label: "connect_device/connectedAt",
      name: "connect_device",
      args: {},
      core: {
        ...noOpCore,
        async connectDevice() {
          return {
            source: "connected",
            deviceId: "device-1",
            reused: false,
            sessionTtlMs: 1800000,
            connectedAt: "not-a-date",
            expiresAt: "2026-05-28T00:30:00.000Z",
            device: okDevice,
          };
        },
      },
    },
  ];
  for (const testCase of cases) {
    await withConnectedClient(async (client) => {
      const result = await client.callTool({ name: testCase.name, arguments: testCase.args });
      assert.equal(result.isError, true, `${testCase.label}: unsafe top-level field must fail closed`);
      assert.equal(result.structuredContent.error.code, "internal_output_error", testCase.label);
    }, testCase.core);
  }
});

test("MCP boundary fails closed on an unsanitized live port path", async () => {
  const controlChar = String.fromCharCode(7);
  const core = {
    ...noOpCore,
    async scanDevices() {
      return {
        source: "live",
        activeDeviceId: null,
        devices: [
          {
            source: "live",
            connected: true,
            portPath: "/dev/cu." + controlChar + "x",
            protocolResponse: {
              id: "req_status",
              version: 1,
              type: "status",
              device: { deviceId: "device-1", state: "idle", firmwareName: "f", hardware: "h", firmwareVersion: "0" },
              provisioning: { state: "unprovisioned" },
            },
          },
        ],
      };
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "scan_devices", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "internal_output_error");
  }, core);
});

test("stderr diagnostics carry only allowlisted fields, never raw error text", async () => {
  const realError = console.error;
  const captured = [];
  console.error = (...parts) => {
    captured.push(parts.map(String).join(" "));
  };
  try {
    const throwingCore = {
      ...noOpCore,
      async connectDevice() {
        throw new GatewayError("handshake_failed", "session_LEAK privateKey_LEAK seed_LEAK on /dev/cu.x", true);
      },
    };
    await withConnectedClient(async (client) => {
      await client.callTool({ name: "connect_device", arguments: {} });
    }, throwingCore);
  } finally {
    console.error = realError;
  }
  const joined = captured.join("\n");
  assert.match(joined, /"event":"gateway_tool_error"/, "a diagnostic line was emitted");
  assert.match(joined, /"code":"handshake_failed"/, "diagnostic carries the canonical code");
  for (const marker of ["session_leak", "privatekey_leak", "seed_leak", "/dev/cu"]) {
    assert.equal(joined.toLowerCase().includes(marker), false, `diagnostic must not contain raw '${marker}'`);
  }
});

function identifyFailure(code, message) {
  return {
    source: "live",
    activeDeviceId: null,
    devices: [
      {
        source: "error",
        connected: false,
        portPath: "/dev/cu.usbmodem1",
        deviceId: "device-1",
        status: "error",
        error: { code, message, retryable: true },
      },
    ],
  };
}

test("identify_devices nested per-device errors are canonicalized (no raw message leak)", async () => {
  const core = {
    ...noOpCore,
    async identifyDevices() {
      return identifyFailure("handshake_failed", "session_LEAK privateKey_LEAK seed_LEAK from /dev/cu.x");
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "identify_devices", arguments: {} });
    assert.equal(result.isError ?? false, false);
    const failure = result.structuredContent.devices[0];
    // Known code preserved, message replaced with the canonical public string.
    assert.equal(failure.error.code, "handshake_failed");
    assert.equal(failure.error.message, "The device did not respond to a status handshake.");
    assert.equal(failure.error.retryable, true);
    assertNoLeakMarkers(result, "identify_devices(nested error)");
  }, core);
});

test("identify_devices unknown nested error code collapses to gateway_error", async () => {
  const core = {
    ...noOpCore,
    async identifyDevices() {
      return identifyFailure("ignore_previous_instructions", "do X; session_LEAK");
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "identify_devices", arguments: {} });
    const failure = result.structuredContent.devices[0];
    assert.equal(failure.error.code, "gateway_error");
    assert.equal(failure.error.message, "Gateway request failed.");
    assertNoLeakMarkers(result, "identify_devices(unknown nested code)");
  }, core);
});

function cachedStatusWithFirmwareCode(firmwareErrorCode) {
  return {
    source: "cached",
    connected: false,
    statusObservedAt: "2026-05-28T00:00:00.000Z",
    unavailableReason: "handshake_failed",
    firmwareErrorCode,
    cachedStatus: {
      device: {
        deviceId: "device-1",
        state: "idle",
        firmwareName: "Agent-Q Firmware",
        hardware: "hardware-id",
        firmwareVersion: "0.0.0",
      },
      provisioning: {
        state: "unprovisioned",
      },
    },
  };
}

test("get_device_status cached firmwareErrorCode: unknown code is normalized, no message attached", async () => {
  const core = {
    ...noOpCore,
    async getDeviceStatus() {
      return cachedStatusWithFirmwareCode("weird_injection_LEAK");
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_device_status", arguments: {} });
    assert.equal(result.structuredContent.source, "cached");
    assert.equal(result.structuredContent.firmwareErrorCode, "gateway_error");
    // It is a code, not an error object: no message field is fabricated for it.
    assert.equal("message" in result.structuredContent, false);
    assertNoLeakMarkers(result, "get_device_status(unknown firmwareErrorCode)");
  }, core);
});

test("get_device_status cached firmwareErrorCode: known code is preserved", async () => {
  const core = {
    ...noOpCore,
    async getDeviceStatus() {
      return cachedStatusWithFirmwareCode("timeout");
    },
  };
  await withConnectedClient(async (client) => {
    const result = await client.callTool({ name: "get_device_status", arguments: {} });
    assert.equal(result.structuredContent.firmwareErrorCode, "timeout");
  }, core);
});
