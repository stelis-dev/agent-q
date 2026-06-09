import assert from "node:assert/strict";
import test from "node:test";

import { createLocalServerSuiSignCliCore } from "../dist/sui-signer-local-client.js";
import { runSuiSignCli } from "../dist/sui-sign-cli.js";
import {
  ACCOUNT,
  DEVICE_ID,
  SIGNATURE,
  TX_BYTES,
  allocatePort,
  makeSuiSignerHarness,
  withLocalServer,
} from "./sui-signer-test-support.mjs";

test("Sui CLI call sign can use the local Agent-Q server API", async () => {
  const calls = [];
  await withLocalServer(
    {
      async connectDevice(input) {
        calls.push(["connect", input]);
        return {
          source: "connected",
          deviceId: DEVICE_ID,
          sessionTtlMs: 4294967295,
          connectedAt: "2026-05-28T00:00:00.000Z",
          device: {
            deviceId: DEVICE_ID,
            state: "idle",
            firmwareName: "Agent-Q Firmware",
            hardware: "stackchan-cores3",
            firmwareVersion: "0.0.0",
          },
        };
      },
      async disconnectDevice(input) {
        calls.push(["disconnect", input]);
        return { source: "disconnected", deviceId: DEVICE_ID, reason: "firmware_confirmed" };
      },
      async getAccounts(input) {
        calls.push(["accounts", input]);
        return { source: "live", deviceId: DEVICE_ID, accounts: [ACCOUNT] };
      },
      async signTransaction(input) {
        calls.push(["sign", input]);
        return {
          source: "live",
          deviceId: DEVICE_ID,
          status: "signed",
          authorization: "user",
          chain: "sui",
          method: "sign_transaction",
          signature: SIGNATURE,
        };
      },
      async listDevices() {
        return { source: "list", devices: [], activeDeviceId: null, activeDeviceIdsByPurpose: {} };
      },
      async scanDevices() {
        return { source: "live", devices: [], failures: [], activeDeviceId: null };
      },
      async policyGet() {
        return { source: "not_connected", deviceId: DEVICE_ID, reason: "not_connected" };
      },
      async getApprovalHistory() {
        return { source: "not_connected", deviceId: DEVICE_ID, reason: "not_connected" };
      },
      async policyPropose() {
        return { source: "not_connected", deviceId: DEVICE_ID, reason: "not_connected" };
      },
    },
    async (baseUrl) => {
      const harness = makeSuiSignerHarness({
        dependencies: {
          core: createLocalServerSuiSignCliCore({ baseUrl }),
          async readStdin() {
            return `{"jsonrpc":"2.0","method":"sign","params":{"key_id":"${ACCOUNT.derivationPath}","msg":"${TX_BYTES}"},"id":22}\n`;
          },
          async loadConfig() {
            return { network: "testnet", deviceId: DEVICE_ID, purpose: "sui-cli" };
          },
        },
      });
      assert.equal(await runSuiSignCli(["call"], harness.dependencies), 0, harness.stdout.join(""));
      assert.deepEqual(JSON.parse(harness.stdout.join("")).result, { signature: SIGNATURE });
    },
  );
  assert.deepEqual(calls.map((call) => call[0]), ["connect", "accounts", "sign", "disconnect"]);
  assert.equal(calls[0][1].purpose, "sui-cli");
  assert.equal(calls[2][1].txBytes, TX_BYTES);
});

test("Sui CLI call returns a clear JSON-RPC error when the local server is absent", async () => {
  const port = await allocatePort();
  const harness = makeSuiSignerHarness({
    dependencies: {
      core: createLocalServerSuiSignCliCore({ baseUrl: `http://127.0.0.1:${port}` }),
      async readStdin() {
        return '{"jsonrpc":"2.0","method":"keys","params":null,"id":23}\n';
      },
    },
  });
  assert.equal(await runSuiSignCli(["call"], harness.dependencies), 1);
  const response = JSON.parse(harness.stdout.join(""));
  assert.equal(response.id, 23);
  assert.equal(response.error.code, 1);
  assert.match(response.error.message, /Start the local Agent-Q server/);
});
