import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  buildRejectOnlySuiPolicy,
  createAdminHttpServer,
  startAdminGateway,
} from "../dist/admin.js";
import { GatewayError } from "@stelis/agent-q-client/adapter-internal";

const deviceId = "a508d833-5c83-4680-88bb-18aee976881e";

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
    async getPolicy() {
      return {
        source: "live",
        deviceId,
        policy: {
          schema: "agentq.policy.v0",
          policyId: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
          defaultAction: "reject",
          ruleCount: 0,
        },
      };
    },
    async getApprovalHistory() {
      return { source: "live", deviceId, records: [], hasMore: false };
    },
    async proposePolicyUpdate() {
      return {
        source: "live",
        deviceId,
        status: "applied",
        reasonCode: "device_confirmed",
        policy: {
          policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
          ruleCount: 1,
          highestAction: "reject",
        },
      };
    },
    ...overrides,
  };
}

async function withAdminServer(core, callback) {
  const server = createAdminHttpServer(core);
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
    assert.doesNotMatch(body, /sessionId/);
    const jsResponse = await fetch(`${baseUrl}/admin.js`);
    const jsBody = await jsResponse.text();
    assert.equal(jsResponse.status, 200);
    assert.doesNotMatch(jsBody, /sessionId/);
  });
});

test("Admin egress boundary uses shared Gateway output schemas without importing MCP", async () => {
  const adminPath = fileURLToPath(new URL("../dist/admin.js", import.meta.url));
  const source = await readFile(adminPath, "utf8");
  assert.doesNotMatch(source, /["']\.\/mcp\.js["']/);
  assert.match(source, /["']@stelis\/agent-q-client\/adapter-internal["']/);
});

test("Admin gateway rejects non-loopback bind hosts", async () => {
  await assert.rejects(
    () => startAdminGateway({ core: defaultCore(), host: "0.0.0.0", port: 0 }),
    (error) =>
      error instanceof GatewayError &&
      error.code === "invalid_params" &&
      error.retryable === false,
  );
});

test("Admin API rejects cross-origin or non-JSON POST before core dispatch", async () => {
  let called = false;
  await withAdminServer(
    defaultCore({
      async proposePolicyUpdate() {
        called = true;
        return {};
      },
    }),
    async (baseUrl) => {
      const textPlain = await postRaw(
        baseUrl,
        "/api/propose_reject_policy",
        { "Content-Type": "text/plain" },
        JSON.stringify({ network: "devnet" }),
      );
      assert.equal(textPlain.status, 400);
      assert.equal(textPlain.body.ok, false);
      assert.equal(textPlain.body.error.code, "invalid_params");

      const crossOrigin = await postRaw(
        baseUrl,
        "/api/propose_reject_policy",
        {
          "Content-Type": "application/json",
          Origin: "https://example.invalid",
          "Sec-Fetch-Site": "cross-site",
        },
        JSON.stringify({ network: "devnet" }),
      );
      assert.equal(crossOrigin.status, 400);
      assert.equal(crossOrigin.body.ok, false);
      assert.equal(crossOrigin.body.error.code, "invalid_params");
      assert.equal(called, false);
    },
  );
});

test("Admin API accepts same-origin JSON requests", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await postRaw(
      baseUrl,
      "/api/policy_preview",
      {
        "Content-Type": "application/json; charset=utf-8",
        Origin: baseUrl,
        "Sec-Fetch-Site": "same-origin",
      },
      JSON.stringify({ network: "devnet" }),
    );
    assert.equal(response.status, 200);
    assert.equal(response.body.ok, true);
    assert.deepEqual(response.body.result.policy, buildRejectOnlySuiPolicy("devnet"));
  });
});

test("Admin API sanitizes success results before returning JSON", async () => {
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
      assert.equal(response.status, 200);
      assert.equal(response.body.ok, true);
      assert.equal(response.body.result.source, "list");
      assert.equal(response.body.result.sessionId, undefined);
      assert.doesNotMatch(JSON.stringify(response.body), /must-not-leak/);
    },
  );
});

test("Admin API fails closed when a core success result is malformed", async () => {
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

test("Admin policy preview builds only the supported reject-only Sui proposal", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await postJson(baseUrl, "/api/policy_preview", { network: "mainnet" });
    assert.equal(response.status, 200);
    assert.equal(response.body.ok, true);
    assert.deepEqual(response.body.result.policy, buildRejectOnlySuiPolicy("mainnet"));
  });
});

test("Admin propose path forwards a server-built proposal through Gateway core", async () => {
  let submitted;
  await withAdminServer(
    defaultCore({
      async proposePolicyUpdate(input) {
        submitted = input;
        return {
          source: "live",
          deviceId,
          status: "applied",
          reasonCode: "device_confirmed",
          policy: {
            policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            ruleCount: 1,
            highestAction: "reject",
          },
        };
      },
    }),
    async (baseUrl) => {
      const response = await postJson(baseUrl, "/api/propose_reject_policy", {
        deviceId,
        network: "devnet",
      });
      assert.equal(response.status, 200);
      assert.equal(response.body.ok, true);
      assert.deepEqual(submitted.policy, buildRejectOnlySuiPolicy("devnet"));
      assert.equal(submitted.deviceId, deviceId);
      assert.equal(response.body.result.status, "applied");
    },
  );
});

test("Gateway closes the Admin listener when stdio closes", { timeout: 5000 }, async () => {
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
    await waitForText(() => stderr, "Agent-Q Admin listening");
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

test("Admin API rejects unsupported fields instead of silently ignoring them", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await postJson(baseUrl, "/api/propose_reject_policy", {
      network: "devnet",
      privateKey: "must-not-forward",
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.ok, false);
    assert.equal(response.body.error.code, "invalid_params");
    assert.equal(response.body.error.message, "The provided method parameters are invalid.");
  });
});

test("Admin API rejects an explicit invalid deviceId instead of using the default device", async () => {
  await withAdminServer(defaultCore(), async (baseUrl) => {
    const response = await postJson(baseUrl, "/api/get_policy", {
      deviceId: "../unsafe",
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.ok, false);
    assert.equal(response.body.error.code, "invalid_device_id");
    assert.equal(response.body.error.message, "The provided deviceId is invalid.");
  });
});

test("Admin API projects raw core errors through the public error policy", async () => {
  await withAdminServer(
    defaultCore({
      async scanDevices() {
        throw new GatewayError("port_not_found", "raw /dev/cu.secret should not be exposed", true);
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
