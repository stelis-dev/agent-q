import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  buildMinimalSuiTestnetPolicy,
  createLocalApiHttpServer,
  startLocalApiServer,
} from "../dist/local-api.js";
import { AgentQError } from "@stelis/agent-q-core/adapter-internal";
import { MAX_SUI_SIGN_TRANSACTION_TX_BYTES } from "@stelis/agent-q-core/protocol";

const deviceId = "a508d833-5c83-4680-88bb-18aee976881e";
const suiAddress = "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133";
const suiPublicKey = "ACJkf+7vNjBgvUIFoWcaFfEKEjZ2WRixtfY42C8zz8Rp";
const policyHash = "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3";

function currentPolicyDocument(policies = []) {
  const conditionCount = policies.reduce((sum, policy) => sum + policy.conditions.length, 0);
  return {
    schema: "agentq.policy",
    policyId: policyHash,
    defaultAction: "reject",
    blockchainCount: 1,
    networkCount: 1,
    policyCount: policies.length,
    conditionCount,
    blockchains: [
      {
        blockchain: "sui",
        networks: [
          {
            network: "testnet",
            policies,
          },
        ],
      },
    ],
  };
}

function defaultCore(overrides = {}) {
  return {
    async listDevices() {
      return {
        source: "list",
        devices: [
          {
            deviceId,
            transport: "usb",
            lastPortHint: "/dev/cu.usbmodem1",
            lastSeenAt: "2026-05-28T00:00:00.000Z",
            label: null,
            lastStatus: {
              device: {
                deviceId,
                state: "idle",
                firmwareName: "Agent-Q Firmware",
                hardware: "stackchan-cores3",
                firmwareVersion: "0.0.0",
              },
              provisioning: { state: "provisioned" },
            },
            assignedPurposes: [],
            isDefaultActive: true,
            runtimeSession: {
              sessionTtlMs: 4294967295,
              connectedAt: "2026-05-28T00:00:00.000Z",
            },
          },
        ],
        activeDeviceId: deviceId,
        activeDeviceIdsByPurpose: {},
      };
    },
    async scanDevices() {
      return { source: "live", devices: [], failures: [], activeDeviceId: deviceId };
    },
    async connectDevice() {
      return {
        source: "connected",
        deviceId,
        sessionTtlMs: 4294967295,
        connectedAt: "2026-05-28T00:00:00.000Z",
        device: {
          deviceId,
          state: "idle",
          firmwareName: "Agent-Q Firmware",
          hardware: "stackchan-cores3",
          firmwareVersion: "0.0.0",
        },
      };
    },
    async disconnectDevice() {
      return { source: "disconnected", deviceId, reason: "firmware_confirmed" };
    },
    async policyGet() {
      return {
        source: "live",
        deviceId,
        policy: currentPolicyDocument(),
      };
    },
    async getApprovalHistory() {
      return { source: "live", deviceId, records: [], hasMore: false };
    },
    async getAccounts() {
      return {
        source: "live",
        deviceId,
        accounts: [
          {
            chain: "sui",
            address: suiAddress,
            publicKey: suiPublicKey,
            keyScheme: "ed25519",
            derivationPath: "m/44'/784'/0'/0'/0'",
          },
        ],
      };
    },
    async signTransaction() {
      return {
        source: "live",
        deviceId,
        status: "signed",
        authorization: "user",
        chain: "sui",
        method: "sign_transaction",
        signature: `${"A".repeat(130)}==`,
      };
    },
    async policyPropose() {
      return {
        source: "live",
        deviceId,
        status: "applied",
        reasonCode: "device_confirmed",
        policy: {
          policyHash: policyHash,
          blockchainCount: 1,
          networkCount: 1,
          policyCount: 1,
          conditionCount: 1,
          highestAction: "sign",
        },
      };
    },
    ...overrides,
  };
}

async function withAdminServer(core, callback) {
  const server = createLocalApiHttpServer(core);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  try {
    await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function postJson(baseUrl, path, body = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function postRaw(baseUrl, path, headers, body) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers,
    body,
  });
  return { status: response.status, body: await response.json() };
}

test("Admin page serves the local management UI without session tokens", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await fetch(`${baseUrl}/`);
    const body = await response.text();
    assert.equal(response.status, 200);
    assert.match(body, /Agent-Q Admin/);
    assert.match(body, /id="policySaveOverlay"/);
    assert.doesNotMatch(body, /sessionId/);
    const jsResponse = await fetch(`${baseUrl}/admin.js`);
    const jsBody = await jsResponse.text();
    assert.equal(jsResponse.status, 200);
    assert.match(jsBody, /showPolicySaveOverlay\("Waiting for device-local approval\."\)/);
    assert.match(jsBody, /showPolicySaveOverlay\("Refreshing active policy\."\)/);
    assert.match(jsBody, /showPolicySaveOverlay\("Updating approval history\."\)/);
    assert.doesNotMatch(jsBody, /sessionId/);
  });
});

test("Admin policy save overlay closes when save and refresh requests complete", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin.js`);
    const jsBody = await response.text();
    assert.equal(response.status, 200);
    const proposeIndex = jsBody.indexOf('api("/api/policy_propose"');
    const policyGetIndex = jsBody.indexOf('api("/api/policy_get"', proposeIndex);
    const historyIndex = jsBody.indexOf('api("/api/get_approval_history"', policyGetIndex);
    const hideIndex = jsBody.indexOf("hidePolicySaveOverlay();", historyIndex);
    assert.ok(proposeIndex > 0, "policy propose request must exist");
    assert.ok(policyGetIndex > proposeIndex, "active policy refresh must follow policy propose");
    assert.ok(historyIndex > policyGetIndex, "history refresh must follow active policy refresh");
    assert.ok(hideIndex > historyIndex, "overlay must hide after save and refresh requests complete");
    assert.doesNotMatch(jsBody, /requestAnimationFrame/);
    assert.doesNotMatch(jsBody, /setTimeout/);
  });
});

test("Admin egress boundary uses shared Agent-Q output schemas without importing MCP", async () => {
  const localApiPath = fileURLToPath(new URL("../dist/local-api.js", import.meta.url));
  const source = await readFile(localApiPath, "utf8");
  assert.doesNotMatch(source, /["']\.\/mcp\.js["']/);
  assert.match(source, /["']@stelis\/agent-q-core\/adapter-internal["']/);
});

test("Admin agent-q rejects non-loopback bind hosts", async () => {
  await assert.rejects(
    () => startLocalApiServer({ core: defaultCore(), host: "0.0.0.0", port: 0 }),
    (error) =>
      error instanceof AgentQError &&
      error.code === "invalid_params" &&
      error.retryable === false,
  );
});

test("Local API rejects cross-origin or non-JSON POST before core dispatch", async () => {
  let called = false;
  await withAdminServer(
    defaultCore({
      async policyPropose() {
        called = true;
        return {};
      },
    }),
    async (baseUrl) => {
      const textPlain = await postRaw(
        baseUrl,
        "/api/policy_propose",
        { "Content-Type": "text/plain" },
        JSON.stringify({}),
      );
      assert.equal(textPlain.status, 400);
      assert.equal(textPlain.body.ok, false);
      assert.equal(textPlain.body.error.code, "invalid_params");

      const crossOrigin = await postRaw(
        baseUrl,
        "/api/policy_propose",
        {
          "Content-Type": "application/json",
          Origin: "https://example.invalid",
          "Sec-Fetch-Site": "cross-site",
        },
        JSON.stringify({}),
      );
      assert.equal(crossOrigin.status, 400);
      assert.equal(crossOrigin.body.ok, false);
      assert.equal(crossOrigin.body.error.code, "invalid_params");
      assert.equal(called, false);
    },
  );
});

test("Local API accepts same-origin JSON requests", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await postRaw(
      baseUrl,
      "/api/policy_template_minimal_sui_testnet",
      {
        "Content-Type": "application/json; charset=utf-8",
        Origin: baseUrl,
        "Sec-Fetch-Site": "same-origin",
      },
      JSON.stringify({}),
    );
    assert.equal(response.status, 200);
    assert.equal(response.body.ok, true);
    assert.deepEqual(response.body.result.policy, buildMinimalSuiTestnetPolicy());
  });
});

test("Local API fails closed when a success result carries unsupported fields", async () => {
  await withAdminServer(
    defaultCore({
      async listDevices() {
        return {
          source: "list",
          devices: [],
          activeDeviceId: null,
          activeDeviceIdsByPurpose: {},
          sessionId: "must-not-leak",
        };
      },
    }),
    async (baseUrl) => {
      const response = await postJson(baseUrl, "/api/list_devices");
      assert.equal(response.status, 500);
      assert.equal(response.body.ok, false);
      assert.equal(response.body.error.code, "internal_output_error");
      assert.doesNotMatch(JSON.stringify(response.body), /must-not-leak/);
    },
  );
});

test("Local API fails closed when a core success result is malformed", async () => {
  await withAdminServer(
    defaultCore({
      async listDevices() {
        return { source: "list", devices: [], activeDeviceId: null };
      },
    }),
    async (baseUrl) => {
      const response = await postJson(baseUrl, "/api/list_devices");
      assert.equal(response.status, 500);
      assert.equal(response.body.ok, false);
      assert.equal(response.body.error.code, "internal_output_error");
    },
  );
});

test("Admin policy templates build current policy documents", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const minimal = await postJson(baseUrl, "/api/policy_template_minimal_sui_testnet");
    assert.equal(minimal.status, 200);
    assert.equal(minimal.body.ok, true);
    assert.deepEqual(minimal.body.result.policy, buildMinimalSuiTestnetPolicy());
    const policy = minimal.body.result.policy.blockchains[0].networks[0].policies[0];
    assert.equal(policy.action, "sign");
    assert.deepEqual(policy.conditions.map((condition) => condition.field), [
      "sui.token_sources.source",
      "sui.token_totals_by_type.amount_raw",
      "sui.token_unknown_amount_present",
    ]);
    assert.deepEqual(policy.conditions[1].where, {
      type: "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI",
    });
  });
});

test("Local API does not expose policy reset shortcuts", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    for (const path of [
      "/api/policy_template_default_reject",
      "/api/policy_reset_to_default_reject",
    ]) {
      const response = await postJson(baseUrl, path, { deviceId });
      assert.equal(response.status, 404);
      assert.equal(response.body.ok, false);
      assert.equal(response.body.error.code, "unsupported_method");
    }
  });
});

test("Admin propose path forwards editor policy through Agent-Q core", async () => {
  let submitted;
  const policy = buildMinimalSuiTestnetPolicy();
  await withAdminServer(
    defaultCore({
      async policyPropose(input) {
        submitted = input;
        return {
          source: "live",
          deviceId,
          status: "applied",
          reasonCode: "device_confirmed",
          policy: {
            policyHash: policyHash,
            blockchainCount: 1,
            networkCount: 1,
            policyCount: 1,
            conditionCount: 1,
            highestAction: "sign",
          },
        };
      },
    }),
    async (baseUrl) => {
      const response = await postJson(baseUrl, "/api/policy_propose", {
        deviceId,
        policy,
      });
      assert.equal(response.status, 200);
      assert.equal(response.body.ok, true);
      assert.deepEqual(submitted.policy, policy);
      assert.equal(submitted.deviceId, deviceId);
      assert.equal(response.body.result.status, "applied");
    },
  );
});

test("Agent-Q closes the local API listener when stdio closes", { timeout: 5000 }, async () => {
  const port = await allocatePort();
  const binPath = fileURLToPath(new URL("../dist/bin/agent-q.js", import.meta.url));
  const child = spawn(process.execPath, [binPath, "--port", String(port)], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  try {
    await waitForText(() => stderr, "Agent-Q local API listening");
    child.stdin.end();
    const result = await waitForExit(child);
    assert.equal(result.signal, null);
    assert.equal(result.code, 0);
  } finally {
    if (child.exitCode === null) {
      child.kill();
    }
  }
});

async function allocatePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  const port = address.port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForText(readText, needle) {
  const deadline = Date.now() + 2000;
  while (!readText().includes(needle)) {
    if (Date.now() > deadline) {
      throw new Error(`Timed out waiting for ${needle}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function waitForExit(child) {
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("Timed out waiting for child process exit"));
    }, 2000);
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

test("Local API rejects unsupported fields instead of silently ignoring them", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await postJson(baseUrl, "/api/policy_propose", {
      policy: buildMinimalSuiTestnetPolicy(),
      privateKey: "must-not-forward",
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.ok, false);
    assert.equal(response.body.error.code, "invalid_params");
    assert.equal(response.body.error.message, "The provided method parameters are invalid.");
  });
});

test("Local API rejects policy proposals without an object policy", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await postJson(baseUrl, "/api/policy_propose", {
      deviceId,
      policy: [],
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.ok, false);
    assert.equal(response.body.error.code, "invalid_params");
  });
});

test("Local API exposes signer account and transaction-signing endpoints", async () => {
  const calls = [];
  await withAdminServer(
    defaultCore({
      async getAccounts(input) {
        calls.push(["accounts", input]);
        return {
          source: "live",
          deviceId,
          accounts: [
            {
              chain: "sui",
              address: suiAddress,
              publicKey: suiPublicKey,
              keyScheme: "ed25519",
              derivationPath: "m/44'/784'/0'/0'/0'",
            },
          ],
        };
      },
      async signTransaction(input) {
        calls.push(["sign", input]);
        return {
          source: "live",
          deviceId,
          status: "signed",
          authorization: "user",
          chain: "sui",
          method: "sign_transaction",
          signature: `${"A".repeat(130)}==`,
        };
      },
    }),
    async (baseUrl) => {
      const accounts = await postJson(baseUrl, "/api/get_accounts", {
        deviceId,
        purpose: "sui-cli",
      });
      assert.equal(accounts.status, 200, JSON.stringify(accounts.body));
      assert.equal(accounts.body.ok, true);
      assert.equal(accounts.body.result.source, "live");

      const sign = await postJson(baseUrl, "/api/sign_transaction", {
        deviceId,
        purpose: "sui-cli",
        chain: "sui",
        method: "sign_transaction",
        network: "testnet",
        txBytes: Buffer.from("tx").toString("base64"),
      });
      assert.equal(sign.status, 200, JSON.stringify(sign.body));
      assert.equal(sign.body.ok, true);
      assert.equal(sign.body.result.status, "signed");
    },
  );
  assert.deepEqual(calls.map((call) => call[0]), ["accounts", "sign"]);
  assert.equal(calls[0][1].purpose, "sui-cli");
  assert.equal(calls[1][1].purpose, "sui-cli");
});

test("Local API forwards a max-size Sui transaction body to core", async () => {
  let signedTxBytes = "";
  const txBytes = Buffer.alloc(MAX_SUI_SIGN_TRANSACTION_TX_BYTES, 0xa5).toString("base64");
  await withAdminServer(
    defaultCore({
      async signTransaction(input) {
        signedTxBytes = input.txBytes;
        return {
          source: "live",
          deviceId,
          status: "signed",
          authorization: "user",
          chain: "sui",
          method: "sign_transaction",
          signature: `${"A".repeat(130)}==`,
        };
      },
    }),
    async (baseUrl) => {
      const response = await postJson(baseUrl, "/api/sign_transaction", {
        deviceId,
        purpose: "sui-cli",
        chain: "sui",
        method: "sign_transaction",
        network: "testnet",
        txBytes,
      });
      assert.equal(response.status, 200, JSON.stringify(response.body));
      assert.equal(response.body.ok, true);
      assert.equal(response.body.result.status, "signed");
    },
  );
  assert.equal(signedTxBytes, txBytes);
});

test("Local API preserves blind-signing approval history metadata", async () => {
  await withAdminServer(
    defaultCore({
      async getApprovalHistory() {
        return {
          source: "live",
          deviceId,
          records: [
            {
              seq: "2",
              uptimeMs: "1300",
              timeSource: "uptime",
              eventKind: "signing",
              authorization: "user",
              recordKind: "confirmation",
              confirmationKind: "local_pin",
              chain: "sui",
              method: "sign_transaction",
              reasonCode: "blind_signing_confirmed",
              payloadDigest: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            },
          ],
          hasMore: false,
        };
      },
    }),
    async (baseUrl) => {
      const response = await postJson(baseUrl, "/api/get_approval_history", {
        deviceId,
      });
      assert.equal(response.status, 200, JSON.stringify(response.body));
      assert.equal(response.body.ok, true);
      assert.equal(response.body.result.source, "live");
      assert.equal(response.body.result.records.length, 1);
      assert.equal(response.body.result.records[0].authorization, "user");
      assert.equal(response.body.result.records[0].recordKind, "confirmation");
      assert.equal(response.body.result.records[0].confirmationKind, "local_pin");
      assert.equal(response.body.result.records[0].reasonCode, "blind_signing_confirmed");
    },
  );
});

test("Local API rejects an explicit invalid deviceId instead of using the default device", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await postJson(baseUrl, "/api/policy_get", {
      deviceId: "../unsafe",
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.ok, false);
    assert.equal(response.body.error.code, "invalid_device_id");
    assert.equal(response.body.error.message, "The provided deviceId is invalid.");
  });
});

test("Local API rejects active policy documents with unsupported scopes", async () => {
  await withAdminServer(
    defaultCore({
      async policyGet() {
        return {
          source: "live",
          deviceId,
          policy: {
            ...currentPolicyDocument(),
            blockchains: [
              {
                blockchain: "unknown",
                networks: [
                  {
                    network: "testnet",
                    policies: [],
                  },
                ],
              },
            ],
          },
        };
      },
    }),
    async (baseUrl) => {
      const response = await postJson(baseUrl, "/api/policy_get", {});
      assert.equal(response.status, 500);
      assert.equal(response.body.ok, false);
      assert.equal(response.body.error.code, "internal_output_error");
    },
  );
});

test("Local API projects raw core errors through the public error policy", async () => {
  await withAdminServer(
    defaultCore({
      async scanDevices() {
        throw new AgentQError("port_not_found", "raw /dev/cu.secret should not be exposed", true);
      },
    }),
    async (baseUrl) => {
      const response = await postJson(baseUrl, "/api/scan_devices");
      assert.equal(response.status, 503);
      assert.equal(response.body.ok, false);
      assert.equal(response.body.error.code, "port_not_found");
      assert.equal(response.body.error.message, "The device is not connected.");
      assert.doesNotMatch(JSON.stringify(response.body), /secret/);
    },
  );
});
