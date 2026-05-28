import assert from "node:assert/strict";
import test from "node:test";
import { createGatewayMcpServer, gatewayToolDefinitions } from "../dist/mcp.js";

const expectedToolNames = [
  "connect_device",
  "disconnect_device",
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
      source: "error",
      connected: false,
      error: { code: "no_active_device", message: "No active device is configured.", retryable: false },
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
    return { source: "disconnected", deviceId: "device-1" };
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

  for (const forbidden of [
    "privatekey",
    "private_key",
    "seed",
    "mnemonic",
    "signingkey",
    "signing_key",
    "sessionid",
    "session_id",
  ]) {
    assert.equal(schemaKeys.has(forbidden), false, `forbidden key ${forbidden} must not appear`);
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
    for (const forbidden of ["privatekey", "mnemonic", "seed", "signingkey", "sessionid"]) {
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

test("get_device_status exposes timeoutMs", () => {
  assert.equal("timeoutMs" in gatewayToolDefinitions.getDeviceStatus.inputSchema, true);
});

test("select_device input accepts purpose but rejects reserved 'default'", () => {
  const inputSchema = gatewayToolDefinitions.selectDevice.inputSchema.purpose;
  assert.equal(inputSchema.safeParse("payment").success, true);
  assert.equal(inputSchema.safeParse("default").success, false);
  assert.equal(inputSchema.safeParse("has space").success, false);
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
