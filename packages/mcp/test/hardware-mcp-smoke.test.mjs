// Hardware-gated MCP smoke test.
//
// Skipped by default. The regular hardware smoke runs only when AGENTQ_HW=1
// and a real Agent-Q Firmware device is connected over USB. The mutating
// policy-update smoke runs only when AGENTQ_HW_POLICY_UPDATE=1 and a
// development device whose active policy may be changed is connected. These
// paths drive the real GatewayCore + SerialPortUsbDriver through an in-process
// MCP client and require a human to approve the device-local PIN prompts.
//
// Run it with hardware attached (build first — it imports ../dist/*.js):
//   npm run build
//   AGENTQ_HW=1 node --test test/hardware-mcp-smoke.test.mjs
//
// The policy-update smoke mutates the active policy on the device and is
// gated separately:
//   npm run build
//   AGENTQ_HW_POLICY_UPDATE=1 node --test test/hardware-mcp-smoke.test.mjs
// Set AGENTQ_HW_POLICY_UPDATE_DEVICE_ID=<device-id> when more than one Agent-Q
// device is connected. Without it, the mutating smoke fails unless exactly one
// device is discovered.
//
// It exercises the actual agent-facing path:
//   scan_devices -> identify_devices -> select_device -> connect_device
//   (device-local approval)
//   -> get_capabilities -> get_accounts -> get_policy
//   -> call_method (policy reject) -> disconnect_device
//
// The device must already be provisioned for connect_device/get_capabilities/get_accounts/get_policy/call_method.
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ConfigStore } from "@stelis/agent-q-client/adapter-internal";
import { GatewayCore } from "@stelis/agent-q-client/admin";
import { createGatewayMcpServer } from "../dist/mcp.js";
import {
  FORBIDDEN_SECRET_FIELD_NAMES,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_POLICY_RULE_COUNT,
} from "@stelis/agent-q-client/protocol";
import { SerialPortUsbDriver } from "@stelis/agent-q-client/admin";

const hardwareEnabled = process.env.AGENTQ_HW === "1";
const policyUpdateHardwareEnabled = process.env.AGENTQ_HW_POLICY_UPDATE === "1";
const policyUpdateTargetDeviceId = process.env.AGENTQ_HW_POLICY_UPDATE_DEVICE_ID ?? "";

function scanDeviceId(device) {
  return device?.protocolResponse?.device?.deviceId;
}

function selectMutatingSmokeDeviceId(devices, requestedDeviceId, envVarName, smokeName) {
  assert.ok(devices.length > 0, "expected at least one connected Agent-Q device");

  if (requestedDeviceId.length > 0) {
    const matchingDevice = devices.find((device) => scanDeviceId(device) === requestedDeviceId);
    assert.ok(
      matchingDevice,
      `${envVarName}=${requestedDeviceId} was not found in the USB scan results`,
    );
    return requestedDeviceId;
  }

  assert.equal(
    devices.length,
    1,
    `${smokeName} mutates active policy; connect exactly one Agent-Q device or set ${envVarName}`,
  );
  const deviceId = scanDeviceId(devices[0]);
  assert.equal(typeof deviceId, "string", "expected scanned Agent-Q device to include a deviceId");
  assert.notEqual(deviceId.length, 0, "expected scanned Agent-Q device to include a non-empty deviceId");
  return deviceId;
}

function selectPolicyUpdateSmokeDeviceId(devices, requestedDeviceId) {
  return selectMutatingSmokeDeviceId(
    devices,
    requestedDeviceId,
    "AGENTQ_HW_POLICY_UPDATE_DEVICE_ID",
    "AGENTQ_HW_POLICY_UPDATE",
  );
}

function approvalHistoryTopSeq(history) {
  const topRecord = history.structuredContent?.records?.[0];
  return topRecord === undefined ? null : BigInt(topRecord.seq);
}

function assertNewestPolicyUpdateRecord(history, previousTopSeq, updateResult) {
  assert.equal(history.structuredContent.source, "live");
  assert.ok(history.structuredContent.records.length > 0, "expected at least one approval-history record");

  const topRecord = history.structuredContent.records[0];
  const topSeq = BigInt(topRecord.seq);
  if (previousTopSeq !== null) {
    assert.ok(topSeq > previousTopSeq, "expected policy update to create a newer approval-history record");
  }
  assert.equal(topRecord.eventKind, "policy_update");
  assert.equal(topRecord.result, "applied");
  assert.equal(topRecord.reasonCode, updateResult.reasonCode);
  assert.equal(topRecord.policyHash, updateResult.policy.policyHash);
  assert.equal(topRecord.ruleCount, updateResult.policy.ruleCount);
  assert.equal(topRecord.highestAction, updateResult.policy.highestAction);
}

test("hardware policy-update target selection is fail-closed", () => {
  const deviceA = { protocolResponse: { device: { deviceId: "dev-a" } } };
  const deviceB = { protocolResponse: { device: { deviceId: "dev-b" } } };

  assert.equal(selectPolicyUpdateSmokeDeviceId([deviceA], ""), "dev-a");
  assert.equal(selectPolicyUpdateSmokeDeviceId([deviceA, deviceB], "dev-b"), "dev-b");
  assert.throws(() => selectPolicyUpdateSmokeDeviceId([], ""));
  assert.throws(() => selectPolicyUpdateSmokeDeviceId([deviceA, deviceB], ""));
  assert.throws(() => selectPolicyUpdateSmokeDeviceId([deviceA], "missing"));
});

test("hardware policy-update history proof requires the newest record from this run", () => {
  const updateResult = {
    reasonCode: "device_confirmed",
    policy: {
      policyHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      ruleCount: 1,
      highestAction: "reject",
    },
  };
  const staleMatchingHistory = {
    structuredContent: {
      source: "live",
      records: [
        {
          seq: "42",
          eventKind: "policy_update",
          result: "applied",
          reasonCode: "device_confirmed",
          policyHash: updateResult.policy.policyHash,
          ruleCount: 1,
          highestAction: "reject",
        },
      ],
    },
  };
  const wrongReasonHistory = {
    structuredContent: {
      source: "live",
      records: [
        {
          seq: "43",
          eventKind: "policy_update",
          result: "applied",
          reasonCode: "storage_error",
          policyHash: updateResult.policy.policyHash,
          ruleCount: 1,
          highestAction: "reject",
        },
      ],
    },
  };
  const freshHistory = {
    structuredContent: {
      source: "live",
      records: [
        {
          seq: "43",
          eventKind: "policy_update",
          result: "applied",
          reasonCode: "device_confirmed",
          policyHash: updateResult.policy.policyHash,
          ruleCount: 1,
          highestAction: "reject",
        },
      ],
    },
  };

  assert.equal(approvalHistoryTopSeq(staleMatchingHistory), 42n);
  assert.throws(() => assertNewestPolicyUpdateRecord(staleMatchingHistory, 42n, updateResult));
  assert.throws(() => assertNewestPolicyUpdateRecord(wrongReasonHistory, 42n, updateResult));
  assert.doesNotThrow(() => assertNewestPolicyUpdateRecord(freshHistory, 42n, updateResult));
});

test(
  "hardware: scan -> identify -> select -> connect -> get_capabilities -> get_accounts -> get_policy -> call_method -> disconnect over MCP",
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

      console.log("[hw-smoke] sending connect — approve the device-local prompt within 60s...");
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

      console.log("[hw-smoke] requesting active policy summary...");
      const policy = await client.callTool({ name: "get_policy", arguments: { deviceId } });
      assert.equal(policy.structuredContent.source, "live", "get_policy requires a provisioned device");
      assert.equal(policy.structuredContent.policy.schema, "agentq.policy.v0");
      assert.match(policy.structuredContent.policy.policyId, /^sha256:[0-9a-f]{64}$/);
      assert.equal(policy.structuredContent.policy.defaultAction, "reject");
      assert.equal(Number.isInteger(policy.structuredContent.policy.ruleCount), true);
      assert.ok(policy.structuredContent.policy.ruleCount >= 0);
      assert.ok(policy.structuredContent.policy.ruleCount <= MAX_POLICY_RULE_COUNT);
      assert.equal("sessionId" in policy.structuredContent, false, "sessionId must not reach the client");
      const policyJson = JSON.stringify(policy.structuredContent).toLowerCase();
      for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
        assert.equal(policyJson.includes(fieldName.toLowerCase()), false, `${fieldName} must not reach the client`);
      }

      const validSuiTransferHex = (
        await readFile(
          new URL("../../../firmware/src/common/agent_q/sui/testdata/sui_transaction_facts/valid_sui_transfer_tx.bcs.hex", import.meta.url),
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

test(
  "hardware: propose_policy_update -> get_policy -> get_approval_history over MCP",
  {
    skip: policyUpdateHardwareEnabled
      ? false
      : "set AGENTQ_HW_POLICY_UPDATE=1 with a provisioned development device whose policy may be changed",
  },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "agent-q-hw-policy-update-"));
    const core = new GatewayCore(new ConfigStore(join(dir, "config.json")), new SerialPortUsbDriver());
    const server = createGatewayMcpServer(core);
    const client = new Client({ name: "agent-q-hw-policy-update", version: "0.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      console.log("[hw-policy-update] scanning for Agent-Q devices over USB...");
      const scan = await client.callTool({ name: "scan_devices", arguments: {} });
      const devices = scan.structuredContent?.devices ?? [];
      const deviceId = selectPolicyUpdateSmokeDeviceId(devices, policyUpdateTargetDeviceId);
      console.log(`[hw-policy-update] found device ${deviceId}`);

      const select = await client.callTool({ name: "select_device", arguments: { deviceId } });
      assert.equal(select.structuredContent.source, "selected");

      console.log("[hw-policy-update] connecting — enter the device PIN within 60s...");
      const connect = await client.callTool({
        name: "connect_device",
        arguments: { deviceId, approvalTimeoutMs: 60000 },
      });
      assert.equal(connect.structuredContent.source, "connected", "connect must be approved on the device");
      assert.equal("sessionId" in connect.structuredContent, false, "sessionId must not reach the client");

      console.log("[hw-policy-update] reading newest approval-history seq before the proposal...");
      const historyBeforeUpdate = await client.callTool({
        name: "get_approval_history",
        arguments: { deviceId, limit: 1 },
      });
      assert.equal(historyBeforeUpdate.structuredContent.source, "live");
      assert.equal("sessionId" in historyBeforeUpdate.structuredContent, false, "sessionId must not reach the client");
      const previousHistoryTopSeq = approvalHistoryTopSeq(historyBeforeUpdate);

      const proposal = {
        schema: "agentq.policy.v0",
        defaultAction: "reject",
        rules: [
          {
            id: "reject_devnet",
            chain: "sui",
            method: "sign_transaction",
            action: "reject",
            criteria: [{ field: "common.network", op: "eq", value: "devnet" }],
          },
        ],
      };

      console.log("[hw-policy-update] proposing reject-only policy — enter the device PIN within 60s...");
      const update = await client.callTool({
        name: "propose_policy_update",
        arguments: { deviceId, policy: proposal, timeoutMs: 61000 },
      });
      assert.equal(update.structuredContent.source, "live");
      assert.equal(update.structuredContent.status, "applied");
      assert.equal(update.structuredContent.reasonCode, "device_confirmed");
      assert.equal(update.structuredContent.policy.ruleCount, 1);
      assert.equal(update.structuredContent.policy.highestAction, "reject");
      assert.match(update.structuredContent.policy.policyHash, /^sha256:[0-9a-f]{64}$/);
      assert.equal("sessionId" in update.structuredContent, false, "sessionId must not reach the client");
      const updateJson = JSON.stringify(update.structuredContent).toLowerCase();
      for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
        assert.equal(updateJson.includes(fieldName.toLowerCase()), false, `${fieldName} must not reach the client`);
      }

      console.log("[hw-policy-update] verifying committed policy summary...");
      const policy = await client.callTool({ name: "get_policy", arguments: { deviceId } });
      assert.equal(policy.structuredContent.source, "live");
      assert.equal(policy.structuredContent.policy.schema, "agentq.policy.v0");
      assert.equal(policy.structuredContent.policy.policyId, update.structuredContent.policy.policyHash);
      assert.equal(policy.structuredContent.policy.defaultAction, "reject");
      assert.equal(policy.structuredContent.policy.ruleCount, 1);
      assert.equal("sessionId" in policy.structuredContent, false, "sessionId must not reach the client");

      console.log("[hw-policy-update] verifying policy-update approval-history record...");
      const history = await client.callTool({
        name: "get_approval_history",
        arguments: { deviceId, limit: MAX_APPROVAL_HISTORY_RECORDS },
      });
      assert.equal(history.structuredContent.source, "live");
      assertNewestPolicyUpdateRecord(history, previousHistoryTopSeq, update.structuredContent);
      assert.equal("sessionId" in history.structuredContent, false, "sessionId must not reach the client");

      console.log("[hw-policy-update] disconnecting...");
      const disconnect = await client.callTool({ name: "disconnect_device", arguments: { deviceId } });
      assert.equal(disconnect.structuredContent.source, "disconnected");
      console.log("[hw-policy-update] OK");
    } finally {
      await client.close();
      await server.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);
