import assert from "node:assert/strict";
import test from "node:test";
import { createGatewayMcpServer, gatewayToolDefinitions } from "../dist/mcp.js";

test("registers only M1 MCP tools", () => {
  assert.deepEqual(
    Object.values(gatewayToolDefinitions).map((tool) => tool.name).sort(),
    ["get_device_status", "identify_devices", "scan_devices", "select_device"],
  );
});

test("tool schemas do not expose secret fields", () => {
  const schemaKeys = new Set();
  for (const tool of Object.values(gatewayToolDefinitions)) {
    for (const key of Object.keys(tool.inputSchema)) {
      schemaKeys.add(key.toLowerCase());
    }
    for (const key of Object.keys(tool.outputSchema)) {
      schemaKeys.add(key.toLowerCase());
    }
  }

  for (const forbidden of ["privatekey", "private_key", "seed", "mnemonic", "signingkey", "signing_key"]) {
    assert.equal(schemaKeys.has(forbidden), false);
  }
});

test("can construct the MCP server", () => {
  const server = createGatewayMcpServer({
    async scanDevices() {
      return {
        source: "live",
        devices: [],
        activeDeviceId: null,
      };
    },
    async getDeviceStatus() {
      return {
        source: "error",
        connected: false,
        error: {
          code: "no_active_device",
          message: "No active device is configured.",
          retryable: false,
        },
      };
    },
    async identifyDevices() {
      return {
        source: "live",
        devices: [],
        activeDeviceId: null,
      };
    },
    async selectDevice() {
      return {
        source: "selected",
        activeDeviceId: "device-1",
        device: {
          deviceId: "device-1",
          state: "idle",
          firmwareName: "Agent-Q Firmware",
          hardware: "hardware-id",
          firmwareVersion: "0.0.0",
        },
      };
    },
  });

  assert.equal(server.isConnected(), false);
});
