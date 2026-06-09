// Hardware-gated Sign API smoke tests.
//
// Skipped by default. These tests own direct USB/Firmware smoke coverage for
// Agent-Q client/core. Adapter packages should test only their public boundary
// and projection behavior.
//
// Build first because this file imports ../dist/*.js:
//   npm --workspace @stelis/agent-q-client run build
//
// User-authorized sign_transaction smoke:
//   AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER=1 \
//   AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_SCENARIO=positive \
//   AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_TX_BYTES=<base64> \
//   node --test packages/client/test/hardware-sign-api-smoke.test.mjs
//
// Policy-authorized sign_transaction smoke:
//   AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY=1 \
//   AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY_SCENARIO=rejected \
//   node --test packages/client/test/hardware-sign-api-smoke.test.mjs
//
// User-authorized sign_personal_message smoke:
//   AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER=1 \
//   AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER_SCENARIO=positive \
//   node --test packages/client/test/hardware-sign-api-smoke.test.mjs
//
// Policy-mode sign_personal_message fail-closed smoke:
//   AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_POLICY=1 \
//   node --test packages/client/test/hardware-sign-api-smoke.test.mjs
//
// Policy update smoke mutates the active policy on the device:
//   AGENTQ_HW_CLIENT_POLICY_UPDATE=1 \
//   node --test packages/client/test/hardware-sign-api-smoke.test.mjs
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { ConfigStore } from "../dist/adapter-internal.js";
import { AgentQHostCore, SerialPortUsbDriver } from "../dist/admin.js";
import {
  FORBIDDEN_SECRET_FIELD_NAMES,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_POLICY_RULE_COUNT,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
} from "../dist/protocol.js";

const USER_SIGNING_METHODS = Object.freeze([
  { chain: "sui", method: "sign_transaction" },
  { chain: "sui", method: "sign_personal_message" },
]);
const POLICY_SIGNING_METHODS = Object.freeze([
  { chain: "sui", method: "sign_transaction" },
]);
const DEFAULT_PERSONAL_MESSAGE_BYTES = Buffer.from("Agent-Q personal message check").toString("base64");

const userSigningEnabled = process.env.AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER === "1";
const userSigningScenario = process.env.AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_SCENARIO ?? "";
const userSigningDeviceId = process.env.AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_DEVICE_ID ?? "";
const userSigningTxBytes = (process.env.AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_TX_BYTES ?? "").replace(/\s+/g, "");
const userSigningScenarios = new Set(["positive", "reject", "timeout", "disconnect"]);

const policySigningEnabled = process.env.AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY === "1";
const policySigningScenario = process.env.AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY_SCENARIO ?? "";
const policySigningDeviceId = process.env.AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY_DEVICE_ID ?? "";
const policySigningTxBytes = (process.env.AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY_TX_BYTES ?? "").replace(/\s+/g, "");
const policySigningScenarios = new Set(["signed", "rejected"]);

const userPersonalMessageEnabled = process.env.AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER === "1";
const userPersonalMessageScenario = process.env.AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER_SCENARIO ?? "";
const userPersonalMessageDeviceId = process.env.AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER_DEVICE_ID ?? "";
const userPersonalMessageBytes = (
  process.env.AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER_MESSAGE ?? DEFAULT_PERSONAL_MESSAGE_BYTES
).replace(/\s+/g, "");
const userPersonalMessageScenarios = new Set(["positive", "reject", "timeout", "disconnect"]);

const policyPersonalMessageEnabled = process.env.AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_POLICY === "1";
const policyPersonalMessageDeviceId = process.env.AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_POLICY_DEVICE_ID ?? "";
const policyPersonalMessageBytes = (
  process.env.AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_POLICY_MESSAGE ?? DEFAULT_PERSONAL_MESSAGE_BYTES
).replace(/\s+/g, "");

const policyUpdateEnabled = process.env.AGENTQ_HW_CLIENT_POLICY_UPDATE === "1";
const policyUpdateDeviceId = process.env.AGENTQ_HW_CLIENT_POLICY_UPDATE_DEVICE_ID ?? "";

const SIGN_TRANSACTION_USER_PURPOSE = "hw.sign_tx.user";
const SIGN_TRANSACTION_POLICY_PURPOSE = "hw.sign_tx.policy";
const SIGN_PERSONAL_MESSAGE_USER_PURPOSE = "hw.sign_msg.user";
const SIGN_PERSONAL_MESSAGE_POLICY_PURPOSE = "hw.sign_msg.policy";
const POLICY_UPDATE_PURPOSE = "client-policy-update-smoke";
const DEVICE_VISIBLE_CLIENT_NAME = "Agent-Q";
const RECONNECT_SCAN_ATTEMPTS = 20;
const RECONNECT_SCAN_INTERVAL_MS = 1000;

function isCanonicalBase64(value) {
  if (value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return false;
  }
  try {
    const decoded = Buffer.from(value, "base64");
    return decoded.length > 0 && decoded.toString("base64") === value;
  } catch {
    return false;
  }
}

function userSigningSkipReason() {
  if (!userSigningEnabled) {
    return "set AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER=1 with a provisioned development device in user signing mode";
  }
  if (!userSigningScenarios.has(userSigningScenario)) {
    return "set AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_SCENARIO=positive, reject, timeout, or disconnect";
  }
  if (!isCanonicalBase64(userSigningTxBytes)) {
    return "set AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_TX_BYTES to canonical base64 txBytes accepted by the device";
  }
  return false;
}

function policySigningSkipReason() {
  if (!policySigningEnabled) {
    return "set AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY=1 with a provisioned development device in policy signing mode";
  }
  if (!policySigningScenarios.has(policySigningScenario)) {
    return "set AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY_SCENARIO=signed or rejected";
  }
  if (policySigningScenario === "signed" && !isCanonicalBase64(policySigningTxBytes)) {
    return "set AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY_TX_BYTES to txBytes matching the active sign policy";
  }
  return false;
}

function userPersonalMessageSkipReason() {
  if (!userPersonalMessageEnabled) {
    return "set AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER=1 with a provisioned development device in user signing mode";
  }
  if (!userPersonalMessageScenarios.has(userPersonalMessageScenario)) {
    return "set AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER_SCENARIO=positive, reject, timeout, or disconnect";
  }
  if (!isCanonicalBase64(userPersonalMessageBytes)) {
    return "set AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER_MESSAGE to canonical base64 message bytes";
  }
  return false;
}

function policyPersonalMessageSkipReason() {
  if (!policyPersonalMessageEnabled) {
    return "set AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_POLICY=1 with a provisioned development device in policy signing mode";
  }
  if (!isCanonicalBase64(policyPersonalMessageBytes)) {
    return "set AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_POLICY_MESSAGE to canonical base64 message bytes";
  }
  return false;
}

function policyUpdateSkipReason() {
  return policyUpdateEnabled
    ? false
    : "set AGENTQ_HW_CLIENT_POLICY_UPDATE=1 with a provisioned development device whose policy may be changed";
}

function scanDeviceId(device) {
  return device?.protocolResponse?.device?.deviceId;
}

function selectSmokeDeviceId(devices, requestedDeviceId, envVarName, smokeName) {
  assert.ok(devices.length > 0, "expected at least one connected Agent-Q device");

  if (requestedDeviceId.length > 0) {
    const matchingDevice = devices.find((device) => scanDeviceId(device) === requestedDeviceId);
    assert.ok(
      matchingDevice,
      `${envVarName}=${requestedDeviceId} was not found in USB scan results`,
    );
    return requestedDeviceId;
  }

  assert.equal(
    devices.length,
    1,
    `${smokeName} requires exactly one Agent-Q device or ${envVarName}`,
  );
  const deviceId = scanDeviceId(devices[0]);
  assert.equal(typeof deviceId, "string", "expected scanned device to include a deviceId");
  assert.notEqual(deviceId.length, 0, "expected scanned device to include a non-empty deviceId");
  return deviceId;
}

async function waitForRecoveredSmokeDevice(core, deviceId) {
  let lastScan = null;
  for (let attempt = 0; attempt < RECONNECT_SCAN_ATTEMPTS; attempt += 1) {
    lastScan = await core.scanDevices();
    const recoveredDevice = lastScan.devices.find((device) => scanDeviceId(device) === deviceId);
    if (recoveredDevice !== undefined) {
      return recoveredDevice;
    }
    await sleep(RECONNECT_SCAN_INTERVAL_MS);
  }
  assert.fail(
    `expected the same device after USB reconnect; last scan=${JSON.stringify(lastScan)}`,
  );
}

async function waitForSmokeScanDevices(core) {
  let lastScan = null;
  for (let attempt = 0; attempt < RECONNECT_SCAN_ATTEMPTS; attempt += 1) {
    lastScan = await core.scanDevices();
    if (lastScan.devices.length > 0) {
      return lastScan.devices;
    }
    await sleep(RECONNECT_SCAN_INTERVAL_MS);
  }
  assert.fail(
    `expected at least one connected Agent-Q device; last scan=${JSON.stringify(lastScan)}`,
  );
}

function topSeq(history) {
  const record = history.records?.[0];
  return record === undefined ? null : BigInt(record.seq);
}

function forbiddenPayload(label, value) {
  return { label, value };
}

function assertNoSmokeOutputLeak(value, forbiddenPayloads = []) {
  const text = JSON.stringify(value);
  const lower = text.toLowerCase();
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.equal(lower.includes(fieldName.toLowerCase()), false, `${fieldName} must not appear in client output`);
  }
  assert.equal(lower.includes("sessionid"), false, "sessionId must not appear in client output");
  const payloads = Array.isArray(forbiddenPayloads) ? forbiddenPayloads : [forbiddenPayloads];
  for (const payload of payloads) {
    if (payload.value.length > 0) {
      assert.equal(text.includes(payload.value), false, `${payload.label} must not appear in this client output`);
    }
  }
}

function assertNewestSigningTerminal(
  history,
  previousTopSeq,
  expectedAuthorization,
  expectedTerminalResult,
  expectedMethod = "sign_transaction",
) {
  assert.equal(history.source, "live");
  assert.ok(history.records.length > 0, "expected at least one approval-history record");
  const topRecord = history.records[0];
  const newTopSeq = BigInt(topRecord.seq);
  if (previousTopSeq !== null) {
    assert.ok(newTopSeq > previousTopSeq, "expected signing to create a newer approval-history record");
  }
  assert.equal(topRecord.eventKind, "signing");
  assert.equal(topRecord.recordKind, "terminal");
  assert.equal(topRecord.authorization, expectedAuthorization);
  assert.equal(topRecord.terminalResult, expectedTerminalResult);
  assert.equal(topRecord.chain, "sui");
  assert.equal(topRecord.method, expectedMethod);
  assert.match(topRecord.payloadDigest, /^sha256:[0-9a-f]{64}$/);
  if (expectedAuthorization === "policy") {
    assert.match(topRecord.policyHash, /^sha256:[0-9a-f]{64}$/);
    assert.equal(typeof topRecord.ruleRef, "string");
  } else {
    assert.equal(topRecord.policyHash, undefined);
    assert.equal(topRecord.ruleRef, undefined);
  }
}

function assertRecentUserConfirmation(history, previousTopSeq, expectedMethod = "sign_transaction") {
  const confirmation = history.records.find((record) => {
    return (
      record.eventKind === "signing" &&
      record.recordKind === "confirmation" &&
      (record.confirmationKind === "local_pin" ||
        record.confirmationKind === "physical_confirm") &&
      (previousTopSeq === null || BigInt(record.seq) > previousTopSeq)
    );
  });
  assert.ok(confirmation, "expected a newer user confirmation history record");
  assert.equal(confirmation.chain, "sui");
  assert.equal(confirmation.method, expectedMethod);
  assert.match(confirmation.payloadDigest, /^sha256:[0-9a-f]{64}$/);
}

function assertNoNewSigningHistory(history, previousTopSeq) {
  assert.equal(history.source, "live");
  const unexpected = history.records.find((record) => {
    return (
      record.eventKind === "signing" &&
      (previousTopSeq === null || BigInt(record.seq) > previousTopSeq)
    );
  });
  assert.equal(
    unexpected,
    undefined,
    "expected no newer signing confirmation or terminal history",
  );
}

function approvalHistoryTopSeq(history) {
  const topRecord = history.records?.[0];
  return topRecord === undefined ? null : BigInt(topRecord.seq);
}

function assertNewestPolicyUpdateRecord(history, previousTopSeq, updateResult) {
  assert.equal(history.source, "live");
  assert.ok(history.records.length > 0, "expected at least one approval-history record");

  const topRecord = history.records[0];
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

async function readDefaultSuiTransferTxBytes() {
  const validSuiTransferHex = (
    await readFile(
      new URL("../../../firmware/src/common/agent_q/sui/testdata/sui_transaction_facts/valid_sui_transfer_tx.bcs.hex", import.meta.url),
      "utf8",
    )
  ).replace(/\s+/g, "");
  return Buffer.from(validSuiTransferHex, "hex").toString("base64");
}

async function withSmokeCore(prefix, callback) {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  const core = new AgentQHostCore(new ConfigStore(join(dir, "config.json")), new SerialPortUsbDriver());
  try {
    return await callback(core);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("client hardware smoke target selection is fail-closed", () => {
  const deviceA = { protocolResponse: { device: { deviceId: "dev-a" } } };
  const deviceB = { protocolResponse: { device: { deviceId: "dev-b" } } };

  assert.equal(
    selectSmokeDeviceId([deviceA], "", "AGENTQ_HW_CLIENT_POLICY_UPDATE_DEVICE_ID", "AGENTQ_HW_CLIENT_POLICY_UPDATE"),
    "dev-a",
  );
  assert.equal(
    selectSmokeDeviceId(
      [deviceA, deviceB],
      "dev-b",
      "AGENTQ_HW_CLIENT_POLICY_UPDATE_DEVICE_ID",
      "AGENTQ_HW_CLIENT_POLICY_UPDATE",
    ),
    "dev-b",
  );
  assert.throws(
    () => selectSmokeDeviceId([], "", "AGENTQ_HW_CLIENT_POLICY_UPDATE_DEVICE_ID", "AGENTQ_HW_CLIENT_POLICY_UPDATE"),
  );
  assert.throws(
    () => selectSmokeDeviceId(
      [deviceA, deviceB],
      "",
      "AGENTQ_HW_CLIENT_POLICY_UPDATE_DEVICE_ID",
      "AGENTQ_HW_CLIENT_POLICY_UPDATE",
    ),
  );
  assert.throws(
    () => selectSmokeDeviceId(
      [deviceA],
      "missing",
      "AGENTQ_HW_CLIENT_POLICY_UPDATE_DEVICE_ID",
      "AGENTQ_HW_CLIENT_POLICY_UPDATE",
    ),
  );
});

test("client hardware smoke policy-update proof requires the newest record from this run", () => {
  const updateResult = {
    reasonCode: "device_confirmed",
    policy: {
      policyHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      ruleCount: 1,
      highestAction: "reject",
    },
  };
  const staleMatchingHistory = {
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
  };
  const wrongReasonHistory = {
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
  };
  const freshHistory = {
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
  };

  assert.equal(approvalHistoryTopSeq(staleMatchingHistory), 42n);
  assert.throws(() => assertNewestPolicyUpdateRecord(staleMatchingHistory, 42n, updateResult));
  assert.throws(() => assertNewestPolicyUpdateRecord(wrongReasonHistory, 42n, updateResult));
  assert.doesNotThrow(() => assertNewestPolicyUpdateRecord(freshHistory, 42n, updateResult));
});

test(
  "hardware: client core signTransaction user terminal path",
  { skip: userSigningSkipReason() },
  async () => {
    await withSmokeCore("agent-q-client-sign-transaction-user-", async (core) => {
      console.log("[client-sign-transaction-user-smoke] scanning devices...");
      const deviceId = selectSmokeDeviceId(
        await waitForSmokeScanDevices(core),
        userSigningDeviceId,
        "AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_DEVICE_ID",
        "AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER",
      );

      try {
        console.log("[client-sign-transaction-user-smoke] selecting device...");
        await core.selectDevice({ deviceId, purpose: SIGN_TRANSACTION_USER_PURPOSE });

        console.log("[client-sign-transaction-user-smoke] approve connect on device...");
        const connect = await core.connectDevice({
          deviceId,
          purpose: SIGN_TRANSACTION_USER_PURPOSE,
          clientName: DEVICE_VISIBLE_CLIENT_NAME,
        });
        assert.equal(connect.source, "connected");

        console.log("[client-sign-transaction-user-smoke] checking raw client signing capability...");
        const capabilities = await core.getCapabilities({ deviceId, purpose: SIGN_TRANSACTION_USER_PURPOSE });
        assert.equal(capabilities.source, "live");
        assert.equal(capabilities.signing?.authorization, "user");
        assert.deepEqual(capabilities.signing?.methods, USER_SIGNING_METHODS);
        assert.equal(
          capabilities.capabilities.some((chain) => chain.methods.includes("sign_transaction")),
          false,
          "delegated chain methods must not advertise signing",
        );
        assertNoSmokeOutputLeak(capabilities, forbiddenPayload("raw txBytes", userSigningTxBytes));

        const beforeHistory = await core.getApprovalHistory({
          deviceId,
          purpose: SIGN_TRANSACTION_USER_PURPOSE,
          limit: 4,
        });
        assert.equal(beforeHistory.source, "live");
        const previousTopSeq = topSeq(beforeHistory);

        if (userSigningScenario === "positive") {
          console.log("[client-sign-transaction-user-smoke] approve review using the current human approval input mode on device...");
        } else if (userSigningScenario === "reject") {
          console.log("[client-sign-transaction-user-smoke] reject the signing review on device...");
        } else if (userSigningScenario === "disconnect") {
          console.log("[client-sign-transaction-user-smoke] unplug USB while the signing review is visible, then reconnect...");
        } else {
          console.log("[client-sign-transaction-user-smoke] leave the signing review untouched until device timeout...");
        }

        const result = await core.signTransaction({
          deviceId,
          purpose: SIGN_TRANSACTION_USER_PURPOSE,
          chain: "sui",
          method: "sign_transaction",
          network: "devnet",
          txBytes: userSigningTxBytes,
        });
        assertNoSmokeOutputLeak(result, forbiddenPayload("raw txBytes", userSigningTxBytes));

        if (userSigningScenario === "disconnect") {
          assert.equal(result.source, "session_ended");
          assert.ok(
            ["transport_unavailable", "timeout"].includes(result.reason),
            `expected transport session end, got ${result.reason}`,
          );
          console.log("[client-sign-transaction-user-smoke] verifying post-reconnect cleanup...");
          const recoveredDevice = await waitForRecoveredSmokeDevice(core, deviceId);
          assert.equal(recoveredDevice.protocolResponse.device.state, "idle");
          assert.equal(recoveredDevice.protocolResponse.provisioning.state, "provisioned");

          await core.selectDevice({ deviceId, purpose: SIGN_TRANSACTION_USER_PURPOSE });
          console.log("[client-sign-transaction-user-smoke] approve reconnect after USB session loss...");
          const reconnect = await core.connectDevice({
            deviceId,
            purpose: SIGN_TRANSACTION_USER_PURPOSE,
            clientName: DEVICE_VISIBLE_CLIENT_NAME,
          });
          assert.equal(reconnect.source, "connected");

          const recoveredCapabilities = await core.getCapabilities({
            deviceId,
            purpose: SIGN_TRANSACTION_USER_PURPOSE,
          });
          assert.equal(recoveredCapabilities.source, "live");
          assert.equal(recoveredCapabilities.signing?.authorization, "user");
          assert.deepEqual(recoveredCapabilities.signing?.methods, USER_SIGNING_METHODS);

          const afterReconnectHistory = await core.getApprovalHistory({
            deviceId,
            purpose: SIGN_TRANSACTION_USER_PURPOSE,
            limit: 4,
          });
          assertNoSmokeOutputLeak(afterReconnectHistory, forbiddenPayload("raw txBytes", userSigningTxBytes));
          assertNoNewSigningHistory(afterReconnectHistory, previousTopSeq);
          return;
        }

        assert.equal(result.source, "live");

        const afterHistory = await core.getApprovalHistory({
          deviceId,
          purpose: SIGN_TRANSACTION_USER_PURPOSE,
          limit: 4,
        });
        assertNoSmokeOutputLeak(afterHistory, forbiddenPayload("raw txBytes", userSigningTxBytes));

        if (userSigningScenario === "positive") {
          assert.equal(result.status, "signed");
          assert.equal(result.authorization, "user");
          assert.equal(result.chain, "sui");
          assert.equal(result.method, "sign_transaction");
          assert.match(result.signature, SUI_ED25519_SIGNATURE_BASE64_PATTERN);
          assertNewestSigningTerminal(afterHistory, previousTopSeq, "user", "signed");
          assertRecentUserConfirmation(afterHistory, previousTopSeq);
        } else if (userSigningScenario === "reject") {
          assert.equal(result.status, "user_rejected");
          assert.equal(result.authorization, "user");
          assert.equal(result.error.code, "user_rejected");
          assertNewestSigningTerminal(afterHistory, previousTopSeq, "user", "user_rejected");
        } else {
          assert.equal(result.status, "user_timed_out");
          assert.equal(result.authorization, "user");
          assert.equal(result.error.code, "user_timed_out");
          assertNewestSigningTerminal(afterHistory, previousTopSeq, "user", "user_timed_out");
        }
      } finally {
        console.log("[client-sign-transaction-user-smoke] disconnecting...");
        await core.disconnectDevice({ deviceId, purpose: SIGN_TRANSACTION_USER_PURPOSE }).catch(() => {});
      }
    });
  },
);

test(
  "hardware: client core signTransaction policy terminal path",
  { skip: policySigningSkipReason() },
  async () => {
    await withSmokeCore("agent-q-client-sign-transaction-policy-", async (core) => {
      console.log("[client-sign-transaction-policy-smoke] scanning devices...");
      const deviceId = selectSmokeDeviceId(
        await waitForSmokeScanDevices(core),
        policySigningDeviceId,
        "AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY_DEVICE_ID",
        "AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY",
      );
      const txBytes = policySigningTxBytes.length > 0
        ? policySigningTxBytes
        : await readDefaultSuiTransferTxBytes();

      try {
        await core.selectDevice({ deviceId, purpose: SIGN_TRANSACTION_POLICY_PURPOSE });
        console.log("[client-sign-transaction-policy-smoke] approve connect on device...");
        const connect = await core.connectDevice({
          deviceId,
          purpose: SIGN_TRANSACTION_POLICY_PURPOSE,
          clientName: DEVICE_VISIBLE_CLIENT_NAME,
        });
        assert.equal(connect.source, "connected");

        const capabilities = await core.getCapabilities({ deviceId, purpose: SIGN_TRANSACTION_POLICY_PURPOSE });
        assert.equal(capabilities.source, "live");
        assert.equal(capabilities.signing?.authorization, "policy");
        assert.deepEqual(capabilities.signing?.methods, POLICY_SIGNING_METHODS);
        assertNoSmokeOutputLeak(capabilities, forbiddenPayload("raw txBytes", txBytes));

        const beforeHistory = await core.getApprovalHistory({
          deviceId,
          purpose: SIGN_TRANSACTION_POLICY_PURPOSE,
          limit: 4,
        });
        assert.equal(beforeHistory.source, "live");
        const previousTopSeq = topSeq(beforeHistory);

        console.log("[client-sign-transaction-policy-smoke] sending policy-authorized Sui sign_transaction...");
        const result = await core.signTransaction({
          deviceId,
          purpose: SIGN_TRANSACTION_POLICY_PURPOSE,
          chain: "sui",
          method: "sign_transaction",
          network: "devnet",
          txBytes,
        });
        assertNoSmokeOutputLeak(result, forbiddenPayload("raw txBytes", txBytes));
        assert.equal(result.source, "live");
        assert.equal(result.authorization, "policy");

        const afterHistory = await core.getApprovalHistory({
          deviceId,
          purpose: SIGN_TRANSACTION_POLICY_PURPOSE,
          limit: 4,
        });
        assertNoSmokeOutputLeak(afterHistory, forbiddenPayload("raw txBytes", txBytes));

        if (policySigningScenario === "signed") {
          assert.equal(result.status, "signed");
          assert.equal(result.chain, "sui");
          assert.equal(result.method, "sign_transaction");
          assert.match(result.signature, SUI_ED25519_SIGNATURE_BASE64_PATTERN);
          assertNewestSigningTerminal(afterHistory, previousTopSeq, "policy", "signed");
        } else {
          assert.equal(result.status, "policy_rejected");
          assert.equal(result.error.code, "policy_rejected");
          assert.match(result.policyHash, /^sha256:[0-9a-f]{64}$/);
          assert.equal(typeof result.ruleRef, "string");
          assertNewestSigningTerminal(afterHistory, previousTopSeq, "policy", "policy_rejected");
        }
      } finally {
        console.log("[client-sign-transaction-policy-smoke] disconnecting...");
        await core.disconnectDevice({ deviceId, purpose: SIGN_TRANSACTION_POLICY_PURPOSE }).catch(() => {});
      }
    });
  },
);

test(
  "hardware: client core signPersonalMessage terminal path",
  { skip: userPersonalMessageSkipReason() },
  async () => {
    await withSmokeCore("agent-q-client-sign-personal-message-user-", async (core) => {
      console.log("[client-sign-personal-message-user-smoke] scanning devices...");
      const deviceId = selectSmokeDeviceId(
        await waitForSmokeScanDevices(core),
        userPersonalMessageDeviceId,
        "AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER_DEVICE_ID",
        "AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_USER",
      );

      try {
        console.log("[client-sign-personal-message-user-smoke] selecting device...");
        await core.selectDevice({ deviceId, purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE });

        console.log("[client-sign-personal-message-user-smoke] approve connect on device...");
        const connect = await core.connectDevice({
          deviceId,
          purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE,
          clientName: DEVICE_VISIBLE_CLIENT_NAME,
        });
        assert.equal(connect.source, "connected");

        console.log("[client-sign-personal-message-user-smoke] checking raw client signing capability...");
        const capabilities = await core.getCapabilities({
          deviceId,
          purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE,
        });
        assert.equal(capabilities.source, "live");
        assert.equal(capabilities.signing?.authorization, "user");
        assert.deepEqual(capabilities.signing?.methods, USER_SIGNING_METHODS);
        assert.equal(
          capabilities.capabilities.some((chain) => chain.methods.includes("sign_personal_message")),
          false,
          "delegated chain methods must not advertise signing",
        );
        assertNoSmokeOutputLeak(capabilities, forbiddenPayload("raw message bytes", userPersonalMessageBytes));

        const beforeHistory = await core.getApprovalHistory({
          deviceId,
          purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE,
          limit: 4,
        });
        assert.equal(beforeHistory.source, "live");
        const previousTopSeq = topSeq(beforeHistory);

        if (userPersonalMessageScenario === "positive") {
          console.log("[client-sign-personal-message-user-smoke] approve review using the current human approval input mode on device...");
        } else if (userPersonalMessageScenario === "reject") {
          console.log("[client-sign-personal-message-user-smoke] reject the signing review on device...");
        } else if (userPersonalMessageScenario === "disconnect") {
          console.log("[client-sign-personal-message-user-smoke] unplug USB while the signing review is visible, then reconnect...");
        } else {
          console.log("[client-sign-personal-message-user-smoke] leave the signing review untouched until device timeout...");
        }

        const result = await core.signPersonalMessage({
          deviceId,
          purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE,
          chain: "sui",
          method: "sign_personal_message",
          network: "devnet",
          message: userPersonalMessageBytes,
        });

        if (userPersonalMessageScenario === "disconnect") {
          assertNoSmokeOutputLeak(result, forbiddenPayload("raw message bytes", userPersonalMessageBytes));
          assert.equal(result.source, "session_ended");
          assert.ok(
            ["transport_unavailable", "timeout"].includes(result.reason),
            `expected transport session end, got ${result.reason}`,
          );
          console.log("[client-sign-personal-message-user-smoke] verifying post-reconnect cleanup...");
          const recoveredDevice = await waitForRecoveredSmokeDevice(core, deviceId);
          assert.equal(recoveredDevice.protocolResponse.device.state, "idle");
          assert.equal(recoveredDevice.protocolResponse.provisioning.state, "provisioned");

          await core.selectDevice({ deviceId, purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE });
          console.log("[client-sign-personal-message-user-smoke] approve reconnect after USB session loss...");
          const reconnect = await core.connectDevice({
            deviceId,
            purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE,
            clientName: DEVICE_VISIBLE_CLIENT_NAME,
          });
          assert.equal(reconnect.source, "connected");

          const recoveredCapabilities = await core.getCapabilities({
            deviceId,
            purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE,
          });
          assert.equal(recoveredCapabilities.source, "live");
          assert.equal(recoveredCapabilities.signing?.authorization, "user");
          assert.deepEqual(recoveredCapabilities.signing?.methods, USER_SIGNING_METHODS);

          const afterReconnectHistory = await core.getApprovalHistory({
            deviceId,
            purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE,
            limit: 4,
          });
          assertNoSmokeOutputLeak(afterReconnectHistory, forbiddenPayload("raw message bytes", userPersonalMessageBytes));
          assertNoNewSigningHistory(afterReconnectHistory, previousTopSeq);
          return;
        }

        assert.equal(result.source, "live");

        const afterHistory = await core.getApprovalHistory({
          deviceId,
          purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE,
          limit: 4,
        });
        assertNoSmokeOutputLeak(afterHistory, forbiddenPayload("raw message bytes", userPersonalMessageBytes));

        if (userPersonalMessageScenario === "positive") {
          assertNoSmokeOutputLeak(result);
          assert.equal(result.status, "signed");
          assert.equal(result.authorization, "user");
          assert.equal(result.chain, "sui");
          assert.equal(result.method, "sign_personal_message");
          assert.match(result.signature, SUI_ED25519_SIGNATURE_BASE64_PATTERN);
          assert.equal(result.messageBytes, userPersonalMessageBytes);
          assertNewestSigningTerminal(afterHistory, previousTopSeq, "user", "signed", "sign_personal_message");
          assertRecentUserConfirmation(afterHistory, previousTopSeq, "sign_personal_message");
        } else if (userPersonalMessageScenario === "reject") {
          assertNoSmokeOutputLeak(result, forbiddenPayload("raw message bytes", userPersonalMessageBytes));
          assert.equal(result.status, "user_rejected");
          assert.equal(result.authorization, "user");
          assert.equal(result.error.code, "user_rejected");
          assertNewestSigningTerminal(afterHistory, previousTopSeq, "user", "user_rejected", "sign_personal_message");
        } else {
          assertNoSmokeOutputLeak(result, forbiddenPayload("raw message bytes", userPersonalMessageBytes));
          assert.equal(result.status, "user_timed_out");
          assert.equal(result.authorization, "user");
          assert.equal(result.error.code, "user_timed_out");
          assertNewestSigningTerminal(afterHistory, previousTopSeq, "user", "user_timed_out", "sign_personal_message");
        }
      } finally {
        console.log("[client-sign-personal-message-user-smoke] disconnecting...");
        await core.disconnectDevice({ deviceId, purpose: SIGN_PERSONAL_MESSAGE_USER_PURPOSE }).catch(() => {});
      }
    });
  },
);

test(
  "hardware: client core signPersonalMessage fails closed in policy mode",
  { skip: policyPersonalMessageSkipReason() },
  async () => {
    await withSmokeCore("agent-q-client-sign-personal-message-policy-", async (core) => {
      console.log("[client-sign-personal-message-policy-smoke] scanning devices...");
      const deviceId = selectSmokeDeviceId(
        await waitForSmokeScanDevices(core),
        policyPersonalMessageDeviceId,
        "AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_POLICY_DEVICE_ID",
        "AGENTQ_HW_CLIENT_SIGN_PERSONAL_MESSAGE_POLICY",
      );

      try {
        await core.selectDevice({ deviceId, purpose: SIGN_PERSONAL_MESSAGE_POLICY_PURPOSE });
        console.log("[client-sign-personal-message-policy-smoke] approve connect on device...");
        const connect = await core.connectDevice({
          deviceId,
          purpose: SIGN_PERSONAL_MESSAGE_POLICY_PURPOSE,
          clientName: DEVICE_VISIBLE_CLIENT_NAME,
        });
        assert.equal(connect.source, "connected");

        const capabilities = await core.getCapabilities({
          deviceId,
          purpose: SIGN_PERSONAL_MESSAGE_POLICY_PURPOSE,
        });
        assert.equal(capabilities.source, "live");
        assert.equal(capabilities.signing?.authorization, "policy");
        assert.deepEqual(capabilities.signing?.methods, POLICY_SIGNING_METHODS);
        assertNoSmokeOutputLeak(capabilities, forbiddenPayload("raw message bytes", policyPersonalMessageBytes));

        const beforeHistory = await core.getApprovalHistory({
          deviceId,
          purpose: SIGN_PERSONAL_MESSAGE_POLICY_PURPOSE,
          limit: 4,
        });
        assert.equal(beforeHistory.source, "live");
        const previousTopSeq = topSeq(beforeHistory);

        console.log("[client-sign-personal-message-policy-smoke] sending policy-mode Sui sign_personal_message...");
        await assert.rejects(
          () => core.signPersonalMessage({
            deviceId,
            purpose: SIGN_PERSONAL_MESSAGE_POLICY_PURPOSE,
            chain: "sui",
            method: "sign_personal_message",
            network: "devnet",
            message: policyPersonalMessageBytes,
          }),
          { code: "unsupported_method" },
        );

        const afterHistory = await core.getApprovalHistory({
          deviceId,
          purpose: SIGN_PERSONAL_MESSAGE_POLICY_PURPOSE,
          limit: 4,
        });
        assertNoSmokeOutputLeak(afterHistory, forbiddenPayload("raw message bytes", policyPersonalMessageBytes));
        assertNoNewSigningHistory(afterHistory, previousTopSeq);
      } finally {
        console.log("[client-sign-personal-message-policy-smoke] disconnecting...");
        await core.disconnectDevice({ deviceId, purpose: SIGN_PERSONAL_MESSAGE_POLICY_PURPOSE }).catch(() => {});
      }
    });
  },
);

test(
  "hardware: client core policyPropose terminal path",
  { skip: policyUpdateSkipReason() },
  async () => {
    await withSmokeCore("agent-q-client-policy-update-", async (core) => {
      console.log("[client-policy-update-smoke] scanning devices...");
      const deviceId = selectSmokeDeviceId(
        await waitForSmokeScanDevices(core),
        policyUpdateDeviceId,
        "AGENTQ_HW_CLIENT_POLICY_UPDATE_DEVICE_ID",
        "AGENTQ_HW_CLIENT_POLICY_UPDATE",
      );

      try {
        await core.selectDevice({ deviceId, purpose: POLICY_UPDATE_PURPOSE });
        console.log("[client-policy-update-smoke] connecting — enter the device PIN within 30s...");
        const connect = await core.connectDevice({
          deviceId,
          purpose: POLICY_UPDATE_PURPOSE,
          clientName: DEVICE_VISIBLE_CLIENT_NAME,
        });
        assert.equal(connect.source, "connected");

        console.log("[client-policy-update-smoke] reading newest approval-history seq before the proposal...");
        const historyBeforeUpdate = await core.getApprovalHistory({
          deviceId,
          purpose: POLICY_UPDATE_PURPOSE,
          limit: 1,
        });
        assert.equal(historyBeforeUpdate.source, "live");
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
              criteria: [{ field: "common.intent", op: "eq", value: "single_asset_transfer" }],
            },
          ],
        };

        console.log("[client-policy-update-smoke] proposing reject-only policy — enter the device PIN within 30s...");
        const update = await core.policyPropose({
          deviceId,
          purpose: POLICY_UPDATE_PURPOSE,
          policy: proposal,
        });
        assert.equal(update.source, "live");
        assert.equal(update.status, "applied");
        assert.equal(update.reasonCode, "device_confirmed");
        assert.equal(update.policy.ruleCount, 1);
        assert.equal(update.policy.highestAction, "reject");
        assert.match(update.policy.policyHash, /^sha256:[0-9a-f]{64}$/);
        assertNoSmokeOutputLeak(update);

        console.log("[client-policy-update-smoke] verifying committed policy document...");
        const policy = await core.policyGet({ deviceId, purpose: POLICY_UPDATE_PURPOSE });
        assert.equal(policy.source, "live");
        assert.equal(policy.policy.schema, "agentq.policy.v0");
        assert.equal(policy.policy.policyId, update.policy.policyHash);
        assert.equal(policy.policy.defaultAction, "reject");
        assert.equal(policy.policy.ruleCount, 1);
        assert.equal(policy.policy.rules.length, 1);
        assert.ok(policy.policy.ruleCount <= MAX_POLICY_RULE_COUNT);
        assertNoSmokeOutputLeak(policy);

        console.log("[client-policy-update-smoke] verifying policy-update approval-history record...");
        const history = await core.getApprovalHistory({
          deviceId,
          purpose: POLICY_UPDATE_PURPOSE,
          limit: MAX_APPROVAL_HISTORY_RECORDS,
        });
        assert.equal(history.source, "live");
        assertNewestPolicyUpdateRecord(history, previousHistoryTopSeq, update);
        assertNoSmokeOutputLeak(history);
      } finally {
        console.log("[client-policy-update-smoke] disconnecting...");
        await core.disconnectDevice({ deviceId, purpose: POLICY_UPDATE_PURPOSE }).catch(() => {});
      }
    });
  },
);
