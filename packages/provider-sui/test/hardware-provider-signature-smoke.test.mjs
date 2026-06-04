// Hardware-gated provider signing smoke test.
//
// Skipped by default. Run only with a provisioned development device flashed
// with a current build that intentionally enables provider-facing
// sign_by_user.
//
// The test drives the public provider API:
//   scanDevices -> selectDevice -> connectDevice (device approval)
//   -> getCapabilities -> signByUser
//
// It verifies approval history through the shared device client core used by
// the provider instance. Approval history is smoke evidence, not a public
// provider-sui API.
//
// It does not generate txBytes. Provide txBytes from a separate smoke fixture or
// hardware-preflight helper so this file validates the provider boundary rather
// than becoming a transaction builder.
//
// Example:
//   npm run build
//   AGENTQ_HW_PROVIDER_SIGNATURE=1 \
//   AGENTQ_HW_PROVIDER_SIGNATURE_SCENARIO=positive \
//   AGENTQ_HW_PROVIDER_SIGNATURE_TX_BYTES=<base64> \
//   node --test test/hardware-provider-signature-smoke.test.mjs
//
// Scenarios:
//   positive  approve review and enter the local PIN on device
//   reject    reject the review on device
//   timeout   leave the review untouched until the device times out
//   disconnect unplug USB while the signing review is visible, then reconnect
import assert from "node:assert/strict";
import test from "node:test";
import { createDefaultDeviceClientCore } from "@stelis/agent-q-client";
import { createAgentQSuiProvider } from "../dist/provider-sui.js";
import {
  FORBIDDEN_SECRET_FIELD_NAMES,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
} from "@stelis/agent-q-client/protocol";

const enabled = process.env.AGENTQ_HW_PROVIDER_SIGNATURE === "1";
const requestedScenario = process.env.AGENTQ_HW_PROVIDER_SIGNATURE_SCENARIO ?? "";
const requestedDeviceId = process.env.AGENTQ_HW_PROVIDER_SIGNATURE_DEVICE_ID ?? "";
const requestedTxBytes = (process.env.AGENTQ_HW_PROVIDER_SIGNATURE_TX_BYTES ?? "").replace(/\s+/g, "");
const scenarios = new Set(["positive", "reject", "timeout", "disconnect"]);

function skipReason() {
  if (!enabled) {
    return "set AGENTQ_HW_PROVIDER_SIGNATURE=1 with a provisioned development device";
  }
  if (!scenarios.has(requestedScenario)) {
    return "set AGENTQ_HW_PROVIDER_SIGNATURE_SCENARIO=positive, reject, timeout, or disconnect";
  }
  if (!isCanonicalBase64(requestedTxBytes)) {
    return "set AGENTQ_HW_PROVIDER_SIGNATURE_TX_BYTES to canonical base64 txBytes accepted by the device";
  }
  return false;
}

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

function scanDeviceId(device) {
  return device?.protocolResponse?.device?.deviceId;
}

function selectSmokeDeviceId(devices) {
  assert.ok(devices.length > 0, "expected at least one connected Agent-Q device");
  if (requestedDeviceId.length > 0) {
    const matchingDevice = devices.find((device) => scanDeviceId(device) === requestedDeviceId);
    assert.ok(
      matchingDevice,
      `AGENTQ_HW_PROVIDER_SIGNATURE_DEVICE_ID=${requestedDeviceId} was not found in USB scan results`,
    );
    return requestedDeviceId;
  }
  assert.equal(
    devices.length,
    1,
    "provider signing smoke requires exactly one Agent-Q device or AGENTQ_HW_PROVIDER_SIGNATURE_DEVICE_ID",
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

function assertNoSmokeOutputLeak(value, txBytes) {
  const text = JSON.stringify(value);
  const lower = text.toLowerCase();
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.equal(lower.includes(fieldName.toLowerCase()), false, `${fieldName} must not appear in provider output`);
  }
  assert.equal(lower.includes("sessionid"), false, "sessionId must not appear in provider output");
  assert.equal(text.includes(txBytes), false, "raw txBytes must not appear in provider output");
}

function assertNewestSignatureTerminal(history, previousTopSeq, expectedTerminalResult) {
  assert.equal(history.source, "live");
  assert.ok(history.records.length > 0, "expected at least one approval-history record");
  const topRecord = history.records[0];
  const newTopSeq = BigInt(topRecord.seq);
  if (previousTopSeq !== null) {
    assert.ok(newTopSeq > previousTopSeq, "expected signByUser to create a newer approval-history record");
  }
  assert.equal(topRecord.eventKind, "signing");
  assert.equal(topRecord.recordKind, "terminal");
  assert.equal(topRecord.terminalResult, expectedTerminalResult);
  assert.equal(topRecord.chain, "sui");
  assert.equal(topRecord.method, "sign_transaction");
  assert.match(topRecord.payloadDigest, /^sha256:[0-9a-f]{64}$/);
}

function assertRecentSignatureConfirmation(history, previousTopSeq) {
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

function assertNoNewSignByUserHistory(history, previousTopSeq) {
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

test(
  "hardware: provider signByUser terminal path",
  { skip: skipReason() },
  async () => {
    const core = createDefaultDeviceClientCore();
    const provider = createAgentQSuiProvider({ core });

    console.log("[provider-signature-smoke] scanning devices...");
    const scan = await provider.scanDevices();
    const deviceId = selectSmokeDeviceId(scan.devices);

    try {
      console.log("[provider-signature-smoke] selecting device...");
      await provider.selectDevice({ deviceId, purpose: "provider-signature-smoke" });

      console.log("[provider-signature-smoke] approve connect on device...");
      const connect = await provider.connectDevice({
        deviceId,
        purpose: "provider-signature-smoke",
        gatewayName: "Agent-Q provider signature smoke",
      });
      assert.equal(connect.source, "connected");

      console.log("[provider-signature-smoke] checking provider-facing signing capability...");
      const capabilities = await provider.getCapabilities({ deviceId, purpose: "provider-signature-smoke" });
      assert.equal(capabilities.source, "live");
      assert.deepEqual(capabilities.signing.user, [{ chain: "sui", method: "sign_transaction" }]);
      assert.equal(JSON.stringify(capabilities).includes('"policy"'), false);
      assert.equal(
        capabilities.capabilities.some((chain) => chain.methods.includes("sign_transaction")),
        false,
        "delegated chain methods must not advertise signing",
      );
      assertNoSmokeOutputLeak(capabilities, requestedTxBytes);

      const beforeHistory = await core.getApprovalHistory({
        deviceId,
        purpose: "provider-signature-smoke",
        limit: 4,
      });
      assert.equal(beforeHistory.source, "live");
      const previousTopSeq = topSeq(beforeHistory);

      if (requestedScenario === "positive") {
        console.log("[provider-signature-smoke] approve review and enter local PIN on device...");
      } else if (requestedScenario === "reject") {
        console.log("[provider-signature-smoke] reject the signing review on device...");
      } else if (requestedScenario === "disconnect") {
        console.log("[provider-signature-smoke] unplug USB while the signing review is visible, then reconnect...");
      } else {
        console.log("[provider-signature-smoke] leave the signing review untouched until device timeout...");
      }

      const result = await provider.signByUser({
        deviceId,
        purpose: "provider-signature-smoke",
        chain: "sui",
        method: "sign_transaction",
        network: "devnet",
        txBytes: requestedTxBytes,
      });
      assertNoSmokeOutputLeak(result, requestedTxBytes);

      if (requestedScenario === "disconnect") {
        assert.equal(result.source, "session_ended");
        assert.ok(
          ["transport_unavailable", "timeout"].includes(result.reason),
          `expected transport session end, got ${result.reason}`,
        );
        console.log("[provider-signature-smoke] verifying post-reconnect cleanup...");
        const recoveryScan = await provider.scanDevices();
        const recoveredDevice = recoveryScan.devices.find((device) => scanDeviceId(device) === deviceId);
        assert.ok(recoveredDevice, "expected the same device after USB reconnect");
        assert.equal(recoveredDevice.protocolResponse.device.state, "idle");
        assert.equal(recoveredDevice.protocolResponse.provisioning.state, "provisioned");

        await provider.selectDevice({ deviceId, purpose: "provider-signature-smoke" });
        console.log("[provider-signature-smoke] approve reconnect after USB session loss...");
        const reconnect = await provider.connectDevice({
          deviceId,
          purpose: "provider-signature-smoke",
          gatewayName: "Agent-Q provider signature smoke",
        });
        assert.equal(reconnect.source, "connected");

        const recoveredCapabilities = await provider.getCapabilities({
          deviceId,
          purpose: "provider-signature-smoke",
        });
        assert.equal(recoveredCapabilities.source, "live");
        assert.deepEqual(recoveredCapabilities.signing.user, [{ chain: "sui", method: "sign_transaction" }]);

        const afterReconnectHistory = await core.getApprovalHistory({
          deviceId,
          purpose: "provider-signature-smoke",
          limit: 4,
        });
        assertNoSmokeOutputLeak(afterReconnectHistory, requestedTxBytes);
        assertNoNewSignByUserHistory(afterReconnectHistory, previousTopSeq);
        return;
      }

      assert.equal(result.source, "live");

      const afterHistory = await core.getApprovalHistory({
        deviceId,
        purpose: "provider-signature-smoke",
        limit: 4,
      });
      assertNoSmokeOutputLeak(afterHistory, requestedTxBytes);

      if (requestedScenario === "positive") {
        assert.equal(result.status, "signed");
        assert.equal(result.authorization, "user");
        assert.equal(result.chain, "sui");
        assert.equal(result.method, "sign_transaction");
        assert.match(result.signature, SUI_ED25519_SIGNATURE_BASE64_PATTERN);
        assertNewestSignatureTerminal(afterHistory, previousTopSeq, "signed");
        assertRecentSignatureConfirmation(afterHistory, previousTopSeq);
      } else if (requestedScenario === "reject") {
        assert.equal(result.status, "user_rejected");
        assert.equal(result.authorization, "user");
        assert.equal(result.error.code, "user_rejected");
        assertNewestSignatureTerminal(afterHistory, previousTopSeq, "user_rejected");
      } else {
        assert.equal(result.status, "user_timed_out");
        assert.equal(result.authorization, "user");
        assert.equal(result.error.code, "user_timed_out");
        assertNewestSignatureTerminal(afterHistory, previousTopSeq, "user_timed_out");
      }
    } finally {
      console.log("[provider-signature-smoke] disconnecting...");
      await provider.disconnectDevice({ deviceId, purpose: "provider-signature-smoke" }).catch(() => {});
    }
  },
);
