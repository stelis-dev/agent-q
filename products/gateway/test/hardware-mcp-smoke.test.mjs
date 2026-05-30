// Hardware-gated MCP smoke test.
//
// Skipped by default. It runs only when AGENTQ_HW=1 AND a real Agent-Q Firmware
// device is connected over USB, because it drives the real GatewayCore +
// SerialPortUsbDriver through an in-process MCP client and requires a human to
// physically approve the connect prompt on the device.
//
// Run it with hardware attached (build first — it imports ../dist/*.js):
//   npm run build
//   AGENTQ_HW=1 node --test test/hardware-mcp-smoke.test.mjs
//
// It exercises the actual agent-facing path:
//   scan_devices -> identify_devices -> select_device -> connect_device (YES)
//   -> get_capabilities -> get_accounts -> call_method (policy reject) -> disconnect_device
//
// The device must already be provisioned for connect_device/get_capabilities/get_accounts/call_method.
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ConfigStore } from "../dist/config.js";
import { GatewayCore } from "../dist/core.js";
import { createGatewayMcpServer } from "../dist/mcp.js";
import { FORBIDDEN_SECRET_FIELD_NAMES } from "../dist/protocol.js";
import { SerialPortUsbDriver } from "../dist/usb.js";

const hardwareEnabled = process.env.AGENTQ_HW === "1";

test(
  "hardware: scan -> identify -> select -> connect -> get_capabilities -> get_accounts -> call_method -> disconnect over MCP",
  { skip: hardwareEnabled ? false : "set AGENTQ_HW=1 with a device connected" },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "agent-q-hw-smoke-"));
    const core = new GatewayCore(new ConfigStore(join(dir, "config.json")), new SerialPortUsbDriver());
    const server = createGatewayMcpServer(core);
    const client = new Client({ name: "agent-q-hw-smoke", version: "0.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      console.log("[hw-smoke] scanning for Agent-Q devices over USB...");
      const scan = await client.callTool({ name: "scan_devices", arguments: {} });
      const devices = scan.structuredContent?.devices ?? [];
      assert.ok(devices.length > 0, "expected at least one connected Agent-Q device");
      const deviceId = devices[0].protocolResponse.device.deviceId;
      console.log(`[hw-smoke] found device ${deviceId}`);

      console.log("[hw-smoke] requesting identification codes (watch the device screen)...");
      const identify = await client.callTool({ name: "identify_devices", arguments: {} });
      assert.equal(identify.structuredContent.source, "live");

      const select = await client.callTool({ name: "select_device", arguments: { deviceId } });
      assert.equal(select.structuredContent.source, "selected");

      console.log("[hw-smoke] sending connect — PRESS YES on the device within 60s...");
      const connect = await client.callTool({
        name: "connect_device",
        arguments: { deviceId, approvalTimeoutMs: 60000 },
      });
      assert.equal(connect.structuredContent.source, "connected", "connect must be physically approved");
      assert.equal("sessionId" in connect.structuredContent, false, "sessionId must not reach the client");

      console.log("[hw-smoke] requesting capabilities...");
      const capabilities = await client.callTool({ name: "get_capabilities", arguments: { deviceId } });
      assert.equal(capabilities.structuredContent.source, "live", "get_capabilities requires a provisioned device");
      assert.equal(capabilities.structuredContent.capabilities.length, 1);
      assert.equal(capabilities.structuredContent.capabilities[0].id, "sui");
      assert.equal(capabilities.structuredContent.capabilities[0].accounts[0].keyScheme, "ed25519");
      assert.deepEqual(capabilities.structuredContent.capabilities[0].methods, []);
      assert.equal("sessionId" in capabilities.structuredContent, false, "sessionId must not reach the client");
      const capabilitiesJson = JSON.stringify(capabilities.structuredContent).toLowerCase();
      for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
        assert.equal(
          capabilitiesJson.includes(fieldName.toLowerCase()),
          false,
          `${fieldName} must not reach the client`,
        );
      }

      console.log("[hw-smoke] requesting public accounts...");
      const accounts = await client.callTool({ name: "get_accounts", arguments: { deviceId } });
      assert.equal(accounts.structuredContent.source, "live", "get_accounts requires a provisioned device");
      assert.equal(accounts.structuredContent.accounts.length, 1);
      assert.equal(accounts.structuredContent.accounts[0].chain, "sui");
      assert.equal(accounts.structuredContent.accounts[0].keyScheme, "ed25519");
      assert.equal("sessionId" in accounts.structuredContent, false, "sessionId must not reach the client");
      const accountsJson = JSON.stringify(accounts.structuredContent).toLowerCase();
      for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
        assert.equal(accountsJson.includes(fieldName.toLowerCase()), false, `${fieldName} must not reach the client`);
      }

      const validSuiTransferHex = (
        await readFile(
          new URL("../../firmware/src/common/agent_q/sui/testdata/sui_transaction_facts/valid_sui_transfer_tx.bcs.hex", import.meta.url),
          "utf8",
        )
      ).replace(/\s+/g, "");
      const validSuiTransferTxBytes = Buffer.from(validSuiTransferHex, "hex").toString("base64");

      console.log("[hw-smoke] calling Sui sign_transaction policy-decision path...");
      const method = await client.callTool({
        name: "call_method",
        arguments: {
          deviceId,
          chain: "sui",
          method: "sign_transaction",
          params: { network: "devnet", txBytes: validSuiTransferTxBytes },
        },
      });
      assert.equal(method.structuredContent.source, "live", "call_method requires a provisioned session");
      assert.equal(method.structuredContent.status, "rejected");
      assert.equal(method.structuredContent.error.code, "policy_rejected");
      assert.equal("sessionId" in method.structuredContent, false, "sessionId must not reach the client");
      const methodJson = JSON.stringify(method.structuredContent).toLowerCase();
      for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
        assert.equal(methodJson.includes(fieldName.toLowerCase()), false, `${fieldName} must not reach the client`);
      }

      console.log("[hw-smoke] disconnecting...");
      const disconnect = await client.callTool({ name: "disconnect_device", arguments: { deviceId } });
      assert.equal(disconnect.structuredContent.source, "disconnected");
      console.log("[hw-smoke] OK");
    } finally {
      await client.close();
      await server.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);
