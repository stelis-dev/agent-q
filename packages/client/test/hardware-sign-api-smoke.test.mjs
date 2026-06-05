// Hardware-gated Sign API smoke tests.
//
// Skipped by default. These tests own direct USB/Firmware smoke coverage for
// Agent-Q client/core. Adapter packages should test only their public boundary
// and projection behavior.
//
// Build first because this file imports ../dist/*.js:
//   npm --workspace @stelis/agent-q-client run build
//
// Provider-facing user signing smoke:
//   AGENTQ_HW_CLIENT_SIGN_BY_USER=1 \
//   AGENTQ_HW_CLIENT_SIGN_BY_USER_SCENARIO=positive \
//   AGENTQ_HW_CLIENT_SIGN_BY_USER_TX_BYTES=<base64> \
//   node --test packages/client/test/hardware-sign-api-smoke.test.mjs
//
// Policy-authorized signing smoke:
//   AGENTQ_HW_CLIENT_SIGN_BY_POLICY=1 \
//   AGENTQ_HW_CLIENT_SIGN_BY_POLICY_SCENARIO=rejected \
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
import { ConfigStore } from "../dist/adapter-internal.js";
import { GatewayCore, SerialPortUsbDriver } from "../dist/admin.js";
import {
  FORBIDDEN_SECRET_FIELD_NAMES,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_POLICY_RULE_COUNT,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
} from "../dist/protocol.js";

const userSigningEnabled = process.env.AGENTQ_HW_CLIENT_SIGN_BY_USER === "1";
const userSigningScenario = process.env.AGENTQ_HW_CLIENT_SIGN_BY_USER_SCENARIO ?? "";
const userSigningDeviceId = process.env.AGENTQ_HW_CLIENT_SIGN_BY_USER_DEVICE_ID ?? "";
const userSigningTxBytes = (process.env.AGENTQ_HW_CLIENT_SIGN_BY_USER_TX_BYTES ?? "").replace(/\s+/g, "");
const userSigningScenarios = new Set(["positive", "reject", "timeout", "disconnect"]);

const policySigningEnabled = process.env.AGENTQ_HW_CLIENT_SIGN_BY_POLICY === "1";
const policySigningScenario = process.env.AGENTQ_HW_CLIENT_SIGN_BY_POLICY_SCENARIO ?? "";
const policySigningDeviceId = process.env.AGENTQ_HW_CLIENT_SIGN_BY_POLICY_DEVICE_ID ?? "";
const policySigningTxBytes = (process.env.AGENTQ_HW_CLIENT_SIGN_BY_POLICY_TX_BYTES ?? "").replace(/\s+/g, "");
const policySigningScenarios = new Set(["signed", "rejected"]);

const policyUpdateEnabled = process.env.AGENTQ_HW_CLIENT_POLICY_UPDATE === "1";
const policyUpdateDeviceId = process.env.AGENTQ_HW_CLIENT_POLICY_UPDATE_DEVICE_ID ?? "";

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
    return "set AGENTQ_HW_CLIENT_SIGN_BY_USER=1 with a provisioned development device";
  }
  if (!userSigningScenarios.has(userSigningScenario)) {
    return "set AGENTQ_HW_CLIENT_SIGN_BY_USER_SCENARIO=positive, reject, timeout, or disconnect";
  }
  if (!isCanonicalBase64(userSigningTxBytes)) {
    return "set AGENTQ_HW_CLIENT_SIGN_BY_USER_TX_BYTES to canonical base64 txBytes accepted by the device";
  }
  return false;
}

function policySigningSkipReason() {
  if (!policySigningEnabled) {
    return "set AGENTQ_HW_CLIENT_SIGN_BY_POLICY=1 with a provisioned development device";
  }
  if (!policySigningScenarios.has(policySigningScenario)) {
    return "set AGENTQ_HW_CLIENT_SIGN_BY_POLICY_SCENARIO=signed or rejected";
  }
  if (policySigningScenario === "signed" && !isCanonicalBase64(policySigningTxBytes)) {
    return "set AGENTQ_HW_CLIENT_SIGN_BY_POLICY_TX_BYTES to txBytes matching the active sign policy";
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

function topSeq(history) {
  const record = history.records?.[0];
  return record === undefined ? null : BigInt(record.seq);
}

function assertNoSmokeOutputLeak(value, txBytes = "") {
  const text = JSON.stringify(value);
  const lower = text.toLowerCase();
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.equal(lower.includes(fieldName.toLowerCase()), false, `${fieldName} must not appear in client output`);
  }
  assert.equal(lower.includes("sessionid"), false, "sessionId must not appear in client output");
  if (txBytes.length > 0) {
    assert.equal(text.includes(txBytes), false, "raw txBytes must not appear in client output");
  }
}

function assertNewestSigningTerminal(history, previousTopSeq, expectedAuthorization, expectedTerminalResult) {
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
  assert.equal(topRecord.method, "sign_transaction");
  assert.match(topRecord.payloadDigest, /^sha256:[0-9a-f]{64}$/);
  if (expectedAuthorization === "policy") {
    assert.match(topRecord.policyHash, /^sha256:[0-9a-f]{64}$/);
    assert.equal(typeof topRecord.ruleRef, "string");
  } else {
    assert.equal(topRecord.policyHash, undefined);
    assert.equal(topRecord.ruleRef, undefined);
  }
}

function assertRecentUserConfirmation(history, previousTopSeq) {
  const confirmation = history.records.find((record) => {
    return (
      record.eventKind === "signing" &&
      record.recordKind === "confirmation" &&
      record.confirmationKind === "local_pin" &&
      (previousTopSeq === null || BigInt(record.seq) > previousTopSeq)
    );
  });
  assert.ok(confirmation, "expected a newer local-PIN confirmation history record");
  assert.equal(confirmation.chain, "sui");
  assert.equal(confirmation.method, "sign_transaction");
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
    "disconnect before confirmation must not create signature confirmation or terminal history",
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
  const core = new GatewayCore(new ConfigStore(join(dir, "config.json")), new SerialPortUsbDriver());
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
  "hardware: client core signByUser terminal path",
  { skip: userSigningSkipReason() },
  async () => {
    await withSmokeCore("agent-q-client-sign-by-user-", async (core) => {
      console.log("[client-sign-by-user-smoke] scanning devices...");
      const scan = await core.scanDevices();
      const deviceId = selectSmokeDeviceId(
        scan.devices,
        userSigningDeviceId,
        "AGENTQ_HW_CLIENT_SIGN_BY_USER_DEVICE_ID",
        "AGENTQ_HW_CLIENT_SIGN_BY_USER",
      );

      try {
        console.log("[client-sign-by-user-smoke] selecting device...");
        await core.selectDevice({ deviceId, purpose: "client-sign-by-user-smoke" });

        console.log("[client-sign-by-user-smoke] approve connect on device...");
        const connect = await core.connectDevice({
          deviceId,
          purpose: "client-sign-by-user-smoke",
          gatewayName: "Agent-Q client sign_by_user smoke",
        });
        assert.equal(connect.source, "connected");

        console.log("[client-sign-by-user-smoke] checking raw client signing capability...");
        const capabilities = await core.getCapabilities({ deviceId, purpose: "client-sign-by-user-smoke" });
        assert.equal(capabilities.source, "live");
        assert.deepEqual(capabilities.signing?.user, [{ chain: "sui", method: "sign_transaction" }]);
        assert.equal(
          capabilities.capabilities.some((chain) => chain.methods.includes("sign_transaction")),
          false,
          "delegated chain methods must not advertise signing",
        );
        assertNoSmokeOutputLeak(capabilities, userSigningTxBytes);

        const beforeHistory = await core.getApprovalHistory({
          deviceId,
          purpose: "client-sign-by-user-smoke",
          limit: 4,
        });
        assert.equal(beforeHistory.source, "live");
        const previousTopSeq = topSeq(beforeHistory);

        if (userSigningScenario === "positive") {
          console.log("[client-sign-by-user-smoke] approve review and enter local PIN on device...");
        } else if (userSigningScenario === "reject") {
          console.log("[client-sign-by-user-smoke] reject the signing review on device...");
        } else if (userSigningScenario === "disconnect") {
          console.log("[client-sign-by-user-smoke] unplug USB while the signing review is visible, then reconnect...");
        } else {
          console.log("[client-sign-by-user-smoke] leave the signing review untouched until device timeout...");
        }

        const result = await core.signByUser({
          deviceId,
          purpose: "client-sign-by-user-smoke",
          chain: "sui",
          method: "sign_transaction",
          network: "devnet",
          txBytes: userSigningTxBytes,
        });
        assertNoSmokeOutputLeak(result, userSigningTxBytes);

        if (userSigningScenario === "disconnect") {
          assert.equal(result.source, "session_ended");
          assert.ok(
            ["transport_unavailable", "timeout"].includes(result.reason),
            `expected transport session end, got ${result.reason}`,
          );
          console.log("[client-sign-by-user-smoke] verifying post-reconnect cleanup...");
          const recoveryScan = await core.scanDevices();
          const recoveredDevice = recoveryScan.devices.find((device) => scanDeviceId(device) === deviceId);
          assert.ok(recoveredDevice, "expected the same device after USB reconnect");
          assert.equal(recoveredDevice.protocolResponse.device.state, "idle");
          assert.equal(recoveredDevice.protocolResponse.provisioning.state, "provisioned");

          await core.selectDevice({ deviceId, purpose: "client-sign-by-user-smoke" });
          console.log("[client-sign-by-user-smoke] approve reconnect after USB session loss...");
          const reconnect = await core.connectDevice({
            deviceId,
            purpose: "client-sign-by-user-smoke",
            gatewayName: "Agent-Q client sign_by_user smoke",
          });
          assert.equal(reconnect.source, "connected");

          const recoveredCapabilities = await core.getCapabilities({
            deviceId,
            purpose: "client-sign-by-user-smoke",
          });
          assert.equal(recoveredCapabilities.source, "live");
          assert.deepEqual(recoveredCapabilities.signing?.user, [{ chain: "sui", method: "sign_transaction" }]);

          const afterReconnectHistory = await core.getApprovalHistory({
            deviceId,
            purpose: "client-sign-by-user-smoke",
            limit: 4,
          });
          assertNoSmokeOutputLeak(afterReconnectHistory, userSigningTxBytes);
          assertNoNewSigningHistory(afterReconnectHistory, previousTopSeq);
          return;
        }

        assert.equal(result.source, "live");

        const afterHistory = await core.getApprovalHistory({
          deviceId,
          purpose: "client-sign-by-user-smoke",
          limit: 4,
        });
        assertNoSmokeOutputLeak(afterHistory, userSigningTxBytes);

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
        console.log("[client-sign-by-user-smoke] disconnecting...");
        await core.disconnectDevice({ deviceId, purpose: "client-sign-by-user-smoke" }).catch(() => {});
      }
    });
  },
);

test(
  "hardware: client core signByPolicy terminal path",
  { skip: policySigningSkipReason() },
  async () => {
    await withSmokeCore("agent-q-client-sign-by-policy-", async (core) => {
      console.log("[client-sign-by-policy-smoke] scanning devices...");
      const scan = await core.scanDevices();
      const deviceId = selectSmokeDeviceId(
        scan.devices,
        policySigningDeviceId,
        "AGENTQ_HW_CLIENT_SIGN_BY_POLICY_DEVICE_ID",
        "AGENTQ_HW_CLIENT_SIGN_BY_POLICY",
      );
      const txBytes = policySigningTxBytes.length > 0
        ? policySigningTxBytes
        : await readDefaultSuiTransferTxBytes();

      try {
        await core.selectDevice({ deviceId, purpose: "client-sign-by-policy-smoke" });
        console.log("[client-sign-by-policy-smoke] approve connect on device...");
        const connect = await core.connectDevice({
          deviceId,
          purpose: "client-sign-by-policy-smoke",
          gatewayName: "Agent-Q client sign_by_policy smoke",
        });
        assert.equal(connect.source, "connected");

        const capabilities = await core.getCapabilities({ deviceId, purpose: "client-sign-by-policy-smoke" });
        assert.equal(capabilities.source, "live");
        assert.deepEqual(capabilities.signing?.policy, [{ chain: "sui", method: "sign_transaction" }]);
        assertNoSmokeOutputLeak(capabilities, txBytes);

        const beforeHistory = await core.getApprovalHistory({
          deviceId,
          purpose: "client-sign-by-policy-smoke",
          limit: 4,
        });
        assert.equal(beforeHistory.source, "live");
        const previousTopSeq = topSeq(beforeHistory);

        console.log("[client-sign-by-policy-smoke] sending policy-authorized Sui sign_transaction...");
        const result = await core.signByPolicy({
          deviceId,
          purpose: "client-sign-by-policy-smoke",
          chain: "sui",
          method: "sign_transaction",
          network: "devnet",
          txBytes,
        });
        assertNoSmokeOutputLeak(result, txBytes);
        assert.equal(result.source, "live");
        assert.equal(result.authorization, "policy");

        const afterHistory = await core.getApprovalHistory({
          deviceId,
          purpose: "client-sign-by-policy-smoke",
          limit: 4,
        });
        assertNoSmokeOutputLeak(afterHistory, txBytes);

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
        console.log("[client-sign-by-policy-smoke] disconnecting...");
        await core.disconnectDevice({ deviceId, purpose: "client-sign-by-policy-smoke" }).catch(() => {});
      }
    });
  },
);

test(
  "hardware: client core proposePolicyUpdate terminal path",
  { skip: policyUpdateSkipReason() },
  async () => {
    await withSmokeCore("agent-q-client-policy-update-", async (core) => {
      console.log("[client-policy-update-smoke] scanning devices...");
      const scan = await core.scanDevices();
      const deviceId = selectSmokeDeviceId(
        scan.devices,
        policyUpdateDeviceId,
        "AGENTQ_HW_CLIENT_POLICY_UPDATE_DEVICE_ID",
        "AGENTQ_HW_CLIENT_POLICY_UPDATE",
      );

      try {
        await core.selectDevice({ deviceId, purpose: "client-policy-update-smoke" });
        console.log("[client-policy-update-smoke] connecting — enter the device PIN within 30s...");
        const connect = await core.connectDevice({
          deviceId,
          purpose: "client-policy-update-smoke",
          gatewayName: "Agent-Q client policy update smoke",
        });
        assert.equal(connect.source, "connected");

        console.log("[client-policy-update-smoke] reading newest approval-history seq before the proposal...");
        const historyBeforeUpdate = await core.getApprovalHistory({
          deviceId,
          purpose: "client-policy-update-smoke",
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
        const update = await core.proposePolicyUpdate({
          deviceId,
          purpose: "client-policy-update-smoke",
          policy: proposal,
        });
        assert.equal(update.source, "live");
        assert.equal(update.status, "applied");
        assert.equal(update.reasonCode, "device_confirmed");
        assert.equal(update.policy.ruleCount, 1);
        assert.equal(update.policy.highestAction, "reject");
        assert.match(update.policy.policyHash, /^sha256:[0-9a-f]{64}$/);
        assertNoSmokeOutputLeak(update);

        console.log("[client-policy-update-smoke] verifying committed policy summary...");
        const policy = await core.getPolicy({ deviceId, purpose: "client-policy-update-smoke" });
        assert.equal(policy.source, "live");
        assert.equal(policy.policy.schema, "agentq.policy.v0");
        assert.equal(policy.policy.policyId, update.policy.policyHash);
        assert.equal(policy.policy.defaultAction, "reject");
        assert.equal(policy.policy.ruleCount, 1);
        assert.ok(policy.policy.ruleCount <= MAX_POLICY_RULE_COUNT);
        assertNoSmokeOutputLeak(policy);

        console.log("[client-policy-update-smoke] verifying policy-update approval-history record...");
        const history = await core.getApprovalHistory({
          deviceId,
          purpose: "client-policy-update-smoke",
          limit: MAX_APPROVAL_HISTORY_RECORDS,
        });
        assert.equal(history.source, "live");
        assertNewestPolicyUpdateRecord(history, previousHistoryTopSeq, update);
        assertNoSmokeOutputLeak(history);
      } finally {
        console.log("[client-policy-update-smoke] disconnecting...");
        await core.disconnectDevice({ deviceId, purpose: "client-policy-update-smoke" }).catch(() => {});
      }
    });
  },
);
