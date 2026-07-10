import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ConfigStore } from "../dist/config.js";
import { DeviceCore } from "../dist/core.js";
import { makeDeviceRequest } from "../dist/device-contract.js";
import { DeviceRequestError } from "../dist/errors.js";
import { MAX_SESSION_TTL_MS, SIGNING_OUTCOME_ERROR_MESSAGES } from "../dist/protocol.js";
import {
  markRequestMayHaveReachedFirmware,
  requestSigningOutcomeWithRecovery,
} from "../dist/usb.js";

const device = {
  deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
  state: "idle",
  firmwareName: "Agent-Q Firmware",
  hardware: "hardware-id",
  firmwareVersion: "0.0.0",
};

const status = {
  device,
  provisioning: {
    state: "unprovisioned",
  },
};

const secondDevice = {
  ...device,
  deviceId: "b508d833-5c83-4680-88bb-18aee976881e",
};

const secondStatus = {
  ...status,
  device: secondDevice,
};

const CANONICAL_TX_BYTES_BASE64 = "AQID";
const signTransactionParams = { network: "devnet", txBytes: CANONICAL_TX_BYTES_BASE64 };
const POLICY_HASH = "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3";

function suiEd25519Signature(fill = 1) {
  const bytes = Buffer.alloc(97, fill);
  bytes[0] = 0;
  return bytes.toString("base64");
}

function signTransactionDeviceRequest(sessionId, route, params) {
  return makeDeviceRequest({
    method: "sign_transaction",
    sessionId,
    payload: {
      chain: route.chain,
      network: params.network,
      txBytes: params.txBytes,
    },
  });
}

function signPersonalMessageDeviceRequest(sessionId, route, params) {
  return makeDeviceRequest({
    method: "sign_personal_message",
    sessionId,
    payload: {
      chain: route.chain,
      network: params.network,
      message: params.message,
    },
  });
}

function signedDeviceResult(id, responseMethod, signMethod, signature, extras = {}) {
  return {
    id,
    version: 1,
    success: true,
    method: responseMethod,
    result: {
      authorization: "user",
      chain: "sui",
      method: signMethod,
      signature,
      ...extras,
    },
  };
}

function wireKind(request) {
  if (request.type === "payload_transfer") {
    return `${request.type}:${request.action}`;
  }
  return request.method ?? request.type;
}

function deviceRequestExecutor(handler) {
  return async (requestLine, _expectedId, _requestLabel, deadlineMs, assertResponse) =>
    handler(JSON.parse(requestLine.trim()), deadlineMs, assertResponse);
}

function currentPolicyDocument(policies = []) {
  const conditionCount = policies.reduce((sum, policy) => sum + policy.conditions.length, 0);
  return {
    schema: "signing.policy",
    policyId: POLICY_HASH,
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

function currentPolicyProposeSummary(overrides = {}) {
  return {
    policyHash: POLICY_HASH,
    blockchainCount: 1,
    networkCount: 1,
    policyCount: 1,
    conditionCount: 1,
    highestAction: "reject",
    ...overrides,
  };
}

function nativePreparation() {
  return {
    address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
    publicKey: "ACJkf+7vNjBgvUIFoWcaFfEKEjZ2WRixtfY42C8zz8Rp",
    keyScheme: "ed25519",
  };
}

function identifyResponse(code, identifiedDevice = device) {
  return {
    code,
    device: identifiedDevice,
  };
}

function connectResult(extras = {}) {
  return {
    sessionId: "session_aabbccdd",
    sessionTtlMs: MAX_SESSION_TTL_MS,
    device,
    ...extras,
  };
}

function defaultDriver(overrides = {}) {
  return {
    async listPorts() {
      return [
        {
          path: "/dev/cu.usbmodem1",
          vendorId: "303a",
          productId: "1001",
          manufacturer: "Espressif",
        },
      ];
    },
    async requestStatus() {
      return status;
    },
    async identifyDevice(_portPath, code) {
      return identifyResponse(code);
    },
    async connectDevice() {
      return connectResult();
    },
    async disconnectDevice() {
      return {};
    },
    async getCapabilities() {
      return {
        chains: [
          {
            id: "sui",
            accounts: [
              {
                keyScheme: "ed25519",
                derivationPath: "m/44'/784'/0'/0'/0'",
              },
            ],
            methods: [],
          },
        ],
        signing: {
          authorization: "user",
          methods: [
            { chain: "sui", method: "sign_transaction" },
            { chain: "sui", method: "sign_personal_message" },
          ],
        },
        credentials: [
          {
            chain: "sui",
            credential: "zklogin",
            operations: ["credential_prepare", "credential_propose"],
          },
        ],
      };
    },
    async getAccounts() {
      return {
        accounts: [
          {
            chain: "sui",
            address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
            publicKey: "ACJkf+7vNjBgvUIFoWcaFfEKEjZ2WRixtfY42C8zz8Rp",
            keyScheme: "ed25519",
            derivationPath: "m/44'/784'/0'/0'/0'",
            sponsoredTransactions: {
              acceptGasSponsor: false,
            },
          },
        ],
      };
    },
    async policyGet() {
      return {
        policy: currentPolicyDocument(),
      };
    },
    async getApprovalHistory() {
      return {
        records: [
          {
            seq: "1",
            uptimeMs: "1200",
            timeSource: "uptime",
            eventKind: "signing",
            authorization: "policy",
            recordKind: "terminal",
            terminalResult: "policy_rejected",
            chain: "sui",
            method: "sign_transaction",
            reasonCode: "default_reject",
            payloadDigest: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            ruleRef: "default",
          },
        ],
        hasMore: false,
      };
    },
    async policyPropose() {
      return {
        status: "applied",
        reasonCode: "device_confirmed",
        policy: currentPolicyProposeSummary(),
      };
    },
    async credentialPrepare() {
      return {
        chain: "sui",
        credential: "zklogin",
        preparation: nativePreparation(),
      };
    },
    async credentialPropose() {
      return {
        status: "activated",
        reasonCode: "device_confirmed",
        sessionEnded: true,
      };
    },
    async signTransaction() {
      return {
        authorization: "user",
        status: "signed",
        chain: "sui",
        method: "sign_transaction",
        signature: suiEd25519Signature(1),
      };
    },
    async signPersonalMessage() {
      return {
        authorization: "user",
        status: "signed",
        chain: "sui",
        method: "sign_personal_message",
        signature: suiEd25519Signature(2),
        messageBytes: Buffer.from("hello").toString("base64"),
      };
    },
    ...overrides,
  };
}

async function withStore(callback) {
  const dir = await mkdtemp(join(tmpdir(), "signing-core-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    return await callback(store, dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

class FakeLocalTransportSession {
  requests = [];
  closed = false;

  async request(request, _deadlineMs, assertResponse) {
    this.requests.push(request);
    if (request.method === "get_status") {
      return assertResponse({
        id: request.id ?? "status",
        version: 1,
        method: "get_status",
        success: true,
        result: status,
      });
    }
    if (request.method === "connect") {
      return assertResponse({
        id: request.id ?? "connect",
        version: 1,
        method: "connect",
        success: true,
        result: connectResult(),
      });
    }
    if (request.method === "get_capabilities") {
      return assertResponse({
        id: request.id ?? "capabilities",
        version: 1,
        method: "get_capabilities",
        success: true,
        result: await defaultDriver().getCapabilities(),
      });
    }
    if (request.method === "sign_transaction") {
      return assertResponse(signedDeviceResult(
        request.id ?? "sign",
        "sign_transaction",
        "sign_transaction",
        suiEd25519Signature(1),
      ));
    }
    if (request.method === "disconnect") {
      return assertResponse({
        id: request.id ?? "disconnect",
        version: 1,
        method: "disconnect",
        success: true,
        result: {},
      });
    }
    return assertResponse({
      id: request.id ?? "unsupported",
      version: 1,
      method: request.method,
      success: false,
      error: {
        code: "unsupported_method",
        message: "Operation is unavailable.",
        retryable: false,
      },
    });
  }

  async close() {
    this.closed = true;
  }
}

test("returns no_active_device when no active device exists", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver({ async listPorts() { return []; } }));
    await assert.rejects(() => core.getDeviceStatus(), { code: "no_active_device" });
  });
});

test("returns cached status for known device when live request times out", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.usbmodem1", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });

    const core = new DeviceCore(
      store,
      defaultDriver({
        async requestStatus() {
          throw new DeviceRequestError("timeout", "Timed out.", true);
        },
      }),
    );

    const result = await core.getDeviceStatus();
    assert.equal(result.source, "cached");
    assert.equal(result.connected, false);
    assert.equal(result.unavailableReason, "timeout");
    assert.equal(result.statusObservedAt, "2026-05-28T00:00:00.000Z");
    assert.equal(result.cachedStatus.device.deviceId, device.deviceId);
    assert.equal(result.cachedStatus.provisioning.state, "unprovisioned");
  });
});

test("returns cached status with a port permission failure reason", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.usbmodem1", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });

    const core = new DeviceCore(
      store,
      defaultDriver({
        async requestStatus() {
          throw Object.assign(new Error("Operation not permitted"), { code: "EPERM" });
        },
      }),
    );

    const result = await core.getDeviceStatus();
    assert.equal(result.source, "cached");
    assert.equal(result.connected, false);
    assert.equal(result.unavailableReason, "port_permission_denied");
  });
});

test("falls back to scan when stored port hint is stale", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.stale", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });

    const requestedPorts = [];
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          return [
            {
              path: "/dev/cu.usbmodem2",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus(portPath) {
          requestedPorts.push(portPath);
          assert.notEqual(portPath, "/dev/cu.stale");
          return status;
        },
      }),
    );

    const result = await core.getDeviceStatus();
    assert.equal(result.source, "live");
    assert.equal(result.portPath, "/dev/cu.usbmodem2");
    assert.deepEqual(requestedPorts, ["/dev/cu.usbmodem2"]);
    assert.equal((await store.load()).devices[0].lastPortHint, "/dev/cu.usbmodem2");
  });
});

test("scan stores live device without selecting it", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction() {
          return {
            id: "req_sign_policy",
            version: 1,
            authorization: "policy",
            status: "policy_rejected",
            policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            ruleRef: "default",
            error: {
              code: "policy_rejected",
              message: SIGNING_OUTCOME_ERROR_MESSAGES.policy_rejected,
            },
          };
        },
      }),
    );
    const result = await core.scanDevices();
    assert.equal(result.devices.length, 1);
    assert.deepEqual(result.failures, []);
    assert.equal(result.activeDeviceId, null);
    assert.equal((await store.load()).devices[0].deviceId, device.deviceId);
    assert.equal((await store.load()).activeDeviceId, null);
  });
});

test("scan sanitizes an OS-supplied port path before returning or storing it", async () => {
  await withStore(async (store) => {
    const weirdPath = "/dev/cu." + String.fromCharCode(7) + "usbmodem9";
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          return [{ path: weirdPath, vendorId: "303a", productId: "1001", manufacturer: "Espressif" }];
        },
        async requestStatus() {
          return status;
        },
      }),
    );
    const result = await core.scanDevices();
    assert.equal(result.devices.length, 1);
    assert.deepEqual(result.failures, []);
    assert.equal(result.devices[0].portPath, "/dev/cu.usbmodem9", "control char stripped from live port path");
    assert.equal((await store.load()).devices[0].lastPortHint, "/dev/cu.usbmodem9");
  });
});

test("scan reports candidate access failures without raw OS error text", async () => {
  await withStore(async (store) => {
    const weirdPath = "/dev/cu." + String.fromCharCode(7) + "usbmodem-denied";
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          return [
            { path: weirdPath, vendorId: "303a", productId: "1001", manufacturer: "Espressif" },
            { path: "/dev/cu.usbmodem1", vendorId: "303a", productId: "1001", manufacturer: "Espressif" },
          ];
        },
        async requestStatus(portPath) {
          if (portPath === weirdPath) {
            throw Object.assign(new Error("Operation not permitted on /dev/cu.secret"), { code: "EPERM" });
          }
          return status;
        },
      }),
    );

    const result = await core.scanDevices();
    assert.equal(result.devices.length, 1);
    assert.equal(result.failures.length, 1);
    assert.equal(result.failures[0].source, "error");
    assert.equal(result.failures[0].connected, false);
    assert.equal(result.failures[0].portPath, "/dev/cu.usbmodem-denied");
    assert.equal(result.failures[0].unavailableReason, "port_permission_denied");
    assert.equal("message" in result.failures[0], false);
    assert.equal(JSON.stringify(result).includes("secret"), false);
  });
});

test("scan does not select an active device when multiple devices are found", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          return [
            {
              path: "/dev/cu.usbmodem1",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
            {
              path: "/dev/cu.usbmodem2",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus(portPath) {
          return portPath === "/dev/cu.usbmodem1" ? status : secondStatus;
        },
      }),
    );

    const result = await core.scanDevices();
    assert.equal(result.devices.length, 2);
    assert.deepEqual(result.failures, []);
    assert.equal(result.activeDeviceId, null);
    assert.equal((await store.load()).activeDeviceId, null);
  });
});

test("identifies devices without selecting one", async () => {
  await withStore(async (store) => {
    const identifiedCodes = [];
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          return [
            {
              path: "/dev/cu.usbmodem1",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
            {
              path: "/dev/cu.usbmodem2",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus(portPath) {
          return portPath === "/dev/cu.usbmodem1" ? status : secondStatus;
        },
        async identifyDevice(portPath, code) {
          identifiedCodes.push(code);
          return identifyResponse(code, portPath === "/dev/cu.usbmodem1" ? device : secondDevice);
        },
      }),
    );

    const result = await core.identifyDevices();
    assert.equal(result.devices.length, 2);
    assert.equal(result.devices.every((candidate) => candidate.source === "live" && candidate.connected), true);
    assert.equal(result.devices.every((candidate) => typeof candidate.code === "string" && candidate.device !== undefined), true);
    assert.equal(new Set(identifiedCodes).size, 2);
    assert.equal(result.activeDeviceId, null);
    assert.equal((await store.load()).activeDeviceId, null);
  });
});

test("identify reports per-device errors without failing the whole request", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          return [
            {
              path: "/dev/cu.usbmodem1",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
            {
              path: "/dev/cu.usbmodem2",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus(portPath) {
          return portPath === "/dev/cu.usbmodem1" ? status : secondStatus;
        },
        async identifyDevice(portPath, code) {
          if (portPath === "/dev/cu.usbmodem2") {
            throw new DeviceRequestError("timeout", "Timed out.", true);
          }
          return identifyResponse(code);
        },
      }),
    );

    const result = await core.identifyDevices();
    assert.equal(result.source, "live");
    assert.equal(result.devices.length, 2);
    assert.equal(result.devices[0].source, "live");
    assert.equal(result.devices[0].device.deviceId, device.deviceId);
    assert.equal(result.devices[1].status, "error");
    assert.equal(result.devices[1].error.code, "timeout");
  });
});

test("identify uses one internal deadline across multiple devices", async () => {
  await withStore(async (store) => {
    // Injected virtual clock: the first identify advances time past the budget, so
    // the second device is reported as a timeout deterministically (no real wait).
    let now = new Date("2026-05-28T00:00:00.000Z");
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          return [
            { path: "/dev/cu.usbmodem1", vendorId: "303a", productId: "1001", manufacturer: "Espressif" },
            { path: "/dev/cu.usbmodem2", vendorId: "303a", productId: "1001", manufacturer: "Espressif" },
          ];
        },
        async requestStatus(portPath) {
          return portPath === "/dev/cu.usbmodem1" ? status : secondStatus;
        },
        async identifyDevice(portPath, code) {
          now = new Date(now.getTime() + 30001);
          return identifyResponse(code, portPath === "/dev/cu.usbmodem1" ? device : secondDevice);
        },
      }),
      () => now,
    );

    const result = await core.identifyDevices();
    assert.equal(result.devices.length, 2);
    assert.equal(result.devices.filter((entry) => entry.source === "live").length, 1);
    assert.equal(result.devices.filter((entry) => entry.source === "error").length, 1);
    const errored = result.devices.find((entry) => entry.status === "error");
    assert.equal(errored.error.code, "timeout");
  });
});

test("selects default and purpose-specific active devices", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.usbmodem1");
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction() {
          return {
            id: "req_sign_policy",
            version: 1,
            authorization: "policy",
            status: "policy_rejected",
            policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            ruleRef: "default",
            error: {
              code: "policy_rejected",
              message: SIGNING_OUTCOME_ERROR_MESSAGES.policy_rejected,
            },
          };
        },
      }),
    );

    const defaultResult = await core.selectDevice({ deviceId: device.deviceId });
    assert.equal(defaultResult.purpose, null);
    assert.equal(defaultResult.activeDeviceId, device.deviceId);
    assert.equal((await store.load()).activeDeviceId, device.deviceId);

    const purposeResult = await core.selectDevice({ deviceId: device.deviceId, purpose: "payment" });
    assert.equal(purposeResult.purpose, "payment");
    assert.equal((await store.load()).activeDeviceIdsByPurpose.payment, device.deviceId);
  });
});

test("selectDevice rejects reserved purpose 'default'", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.usbmodem1");
    const core = new DeviceCore(store, defaultDriver());
    await assert.rejects(
      () => core.selectDevice({ deviceId: device.deviceId, purpose: "default" }),
      { code: "invalid_params" },
    );
  });
});

test("listDevices reports purposes and runtime session state", async () => {
  await withStore(async (store) => {
    const now = new Date("2026-05-28T00:00:00.000Z");
    const core = new DeviceCore(store, defaultDriver(), () => now);
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId, purpose: "payment" });
    await core.connectDevice({ deviceId: device.deviceId });

    const result = await core.listDevices();
    assert.equal(result.devices.length, 1);
    assert.deepEqual(result.devices[0].assignedPurposes, ["payment"]);
    assert.equal(result.devices[0].runtimeSession?.connectedAt, now.toISOString());
    assert.equal(result.devices[0].runtimeSession?.sessionTtlMs, MAX_SESSION_TTL_MS);
    // sessionId is internal to Agent-Q and must not surface in list output.
    assert.equal("sessionId" in (result.devices[0].runtimeSession ?? {}), false);
    assert.equal("expiresAt" in (result.devices[0].runtimeSession ?? {}), false);
  });
});

test("setDeviceMetadata updates label via core", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.usbmodem1");
    const core = new DeviceCore(store, defaultDriver());
    const result = await core.setDeviceMetadata({ deviceId: device.deviceId, label: "Desk device" });
    assert.equal(result.label, "Desk device");
    assert.equal((await store.load()).devices[0].label, "Desk device");
  });
});

test("connectDevice approved stores in-memory session and does not persist sessionId", async () => {
  await withStore(async (store, dir) => {
    let connectCalls = 0;
    let observedDeadlineMs = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice(_portPath, _clientName, deadlineMs) {
          connectCalls += 1;
          observedDeadlineMs = deadlineMs;
          return connectResult();
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.connectDevice({});
    assert.equal(connectCalls, 1);
    assert.equal(observedDeadlineMs, 185000);
    assert.equal(result.source, "connected");
    assert.equal("sessionId" in result, false, "connect result must not expose sessionId");
    assert.equal(result.sessionTtlMs, MAX_SESSION_TTL_MS);

    const raw = await readFile(join(dir, "config.json"), "utf8");
    assert.equal(raw.includes("session"), false, "config must not persist session state");
  });
});

test("connectDevice can open a BLE local transport session from an optical payload", async () => {
  await withStore(async (store) => {
    const opticalPayload =
      "aqlt:1?k=ble&svc=a6e31d1051a14f7a9b0a0a1c00000001&idfp=0011223344556677&non=8899aabbccddeeff&exp=120";
    const localSession = new FakeLocalTransportSession();
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          throw new Error("BLE session operations must not scan USB ports.");
        },
      }),
      () => new Date("2026-05-28T00:00:00.000Z"),
      async (payload) => {
        assert.equal(payload, opticalPayload);
        return localSession;
      },
    );

    const connected = await core.connectDevice({ transport: "ble", opticalPayload });
    assert.equal(connected.source, "connected");
    assert.equal(connected.deviceId, device.deviceId);
    assert.equal("sessionId" in connected, false);

    const listed = await core.listDevices();
    assert.equal(listed.devices[0].transport, "ble");
    assert.equal(listed.devices[0].lastPortHint, "ble:0011223344556677");

    const capabilities = await core.getCapabilities();
    assert.equal(capabilities.source, "live");
    assert.equal(capabilities.signing?.methods[0]?.method, "sign_transaction");

    const signed = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: CANONICAL_TX_BYTES_BASE64,
    });
    assert.equal(signed.source, "live");
    assert.equal(signed.status, "signed");
    assert.equal(localSession.requests.map((request) => request.method).join(","), "get_status,connect,get_capabilities,sign_transaction");
    assert.deepEqual(localSession.requests[3].payload, {
      chain: "sui",
      network: "devnet",
      txBytes: CANONICAL_TX_BYTES_BASE64,
    });

    const disconnected = await core.disconnectDevice({ deviceId: device.deviceId });
    assert.equal(disconnected.source, "disconnected");
    assert.equal(disconnected.reason, "firmware_confirmed");
    assert.equal(localSession.closed, true);
    assert.equal(
      localSession.requests.map((request) => request.method).join(","),
      "get_status,connect,get_capabilities,sign_transaction,disconnect",
    );
  });
});

test("rejected BLE connect cannot replace an existing USB route or purpose selection", async () => {
  await withStore(async (store) => {
    const opticalPayload =
      "aqlt:1?k=ble&svc=a6e31d1051a14f7a9b0a0a1c00000001&idfp=0011223344556677&non=8899aabbccddeeff&exp=120";
    const rejectedSession = new FakeLocalTransportSession();
    rejectedSession.request = async (request, deadlineMs, assertResponse) => {
      if (request.method === "connect") {
        rejectedSession.requests.push(request);
        throw new DeviceRequestError("user_rejected", "Connection rejected.", false);
      }
      return FakeLocalTransportSession.prototype.request.call(
        rejectedSession,
        request,
        deadlineMs,
        assertResponse,
      );
    };
    const core = new DeviceCore(
      store,
      defaultDriver(),
      () => new Date("2026-05-28T00:00:00.000Z"),
      async () => rejectedSession,
    );
    await core.scanDevices();
    await store.rememberUsbStatus(secondStatus, "/dev/cu.usbmodem2");
    await core.selectDevice({ deviceId: secondDevice.deviceId });
    await core.selectDevice({ deviceId: secondDevice.deviceId, purpose: "payment" });
    await core.connectDevice({ deviceId: device.deviceId });

    await assert.rejects(
      () => core.connectDevice({
        deviceId: device.deviceId,
        purpose: "payment",
        transport: "ble",
        opticalPayload,
      }),
      { code: "user_rejected" },
    );

    const config = await store.load();
    const firstDevice = config.devices.find((record) => record.deviceId === device.deviceId);
    assert.equal(firstDevice.transport, "usb");
    assert.equal(firstDevice.lastPortHint, "/dev/cu.usbmodem1");
    assert.equal(config.activeDeviceId, secondDevice.deviceId);
    assert.equal(config.activeDeviceIdsByPurpose.payment, secondDevice.deviceId);
    assert.equal(rejectedSession.closed, true);

    const capabilities = await core.getCapabilities({ deviceId: device.deviceId });
    assert.equal(capabilities.source, "live");
  });
});

test("connectDevice can restore a lost runtime session mirror from Firmware connect recovery", async () => {
  await withStore(async (store) => {
    let connectCalls = 0;
    const coreBeforeRestart = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return connectResult({ sessionId: "session_0a0b0c0d0e0f1011" });
        },
      }),
    );
    await coreBeforeRestart.scanDevices();
    await coreBeforeRestart.selectDevice({ deviceId: device.deviceId });
    await coreBeforeRestart.connectDevice({});

    const coreAfterRestart = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return connectResult({ sessionId: "session_0a0b0c0d0e0f1011" });
        },
      }),
    );

    const result = await coreAfterRestart.connectDevice({});
    assert.equal(connectCalls, 2);
    assert.equal(result.source, "connected");
    assert.equal(result.sessionTtlMs, MAX_SESSION_TTL_MS);
    assert.equal("sessionId" in result, false, "restored connect result must not expose sessionId");
    const listed = await coreAfterRestart.listDevices();
    assert.equal(listed.devices[0].runtimeSession?.sessionTtlMs, MAX_SESSION_TTL_MS);
  });
});

test("connectDevice reuses an active runtime session without fresh Firmware approval", async () => {
  await withStore(async (store) => {
    let connectCalls = 0;
    let capabilitiesCalls = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return connectResult({ sessionId: `session_${connectCalls.toString(16).padStart(2, "0")}` });
        },
        async getCapabilities(_portPath, sessionId) {
          capabilitiesCalls += 1;
          assert.equal(sessionId, "session_01");
          return defaultDriver().getCapabilities();
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const first = await core.connectDevice({});
    const second = await core.connectDevice({});
    assert.equal(first.connectedAt, second.connectedAt);
    assert.equal(connectCalls, 1);
    assert.equal(capabilitiesCalls, 1);
  });
});

test("connectDevice does not reuse a stale local session when the device disappears", async () => {
  await withStore(async (store) => {
    let listPortsCalls = 0;
    let connectCalls = 0;
    let portAvailable = true;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          listPortsCalls += 1;
          return portAvailable
            ? [
                {
                  path: "/dev/cu.usbmodem1",
                  vendorId: "303a",
                  productId: "1001",
                  manufacturer: "Espressif",
                },
              ]
            : [];
        },
        async connectDevice() {
          connectCalls += 1;
          return connectResult();
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});
    assert.equal(connectCalls, 1);

    const listPortsAfterConnect = listPortsCalls;
    portAvailable = false;
    await assert.rejects(() => core.connectDevice({}), { code: "port_not_found" });
    assert.equal(connectCalls, 1, "missing device must not receive a Firmware connect");
    assert.ok(listPortsCalls > listPortsAfterConnect, "connect must scan instead of reusing local session");

    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("scanDevices clears runtime sessions for devices absent from the live USB scan", async () => {
  await withStore(async (store) => {
    let portAvailable = true;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          return portAvailable
            ? [
                {
                  path: "/dev/cu.usbmodem1",
                  vendorId: "303a",
                  productId: "1001",
                  manufacturer: "Espressif",
                },
              ]
            : [];
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});
    assert.notEqual((await core.listDevices()).devices[0].runtimeSession, null);

    portAvailable = false;
    const scanAfterDisconnect = await core.scanDevices();
    assert.equal(scanAfterDisconnect.devices.length, 0);

    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("connectDevice clears a stale local session when reuse validation loses transport", async () => {
  await withStore(async (store) => {
    let connectCalls = 0;
    let failReuseValidation = false;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return connectResult();
        },
        async getCapabilities() {
          if (failReuseValidation) {
            throw new DeviceRequestError("transport_closed", "USB transport closed.", true);
          }
          return defaultDriver().getCapabilities();
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});
    assert.equal(connectCalls, 1);

    failReuseValidation = true;
    await assert.rejects(() => core.connectDevice({}), { code: "transport_closed" });
    assert.equal(connectCalls, 1);

    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("connectDevice asks Firmware again when reuse validation reports invalid_session", async () => {
  await withStore(async (store) => {
    let connectCalls = 0;
    let invalidateExisting = false;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return connectResult({ sessionId: `session_${connectCalls.toString(16).padStart(2, "0")}` });
        },
        async getCapabilities() {
          if (invalidateExisting) {
            throw new DeviceRequestError("invalid_session", "Session is not active.", true);
          }
          return defaultDriver().getCapabilities();
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    await core.connectDevice({});
    invalidateExisting = true;
    const result = await core.connectDevice({});
    assert.equal(connectCalls, 2);
    assert.equal(result.sessionTtlMs, MAX_SESSION_TTL_MS);
  });
});

test("connectDevice does not reapprove from advertised wire ttl while the session validates", async () => {
  await withStore(async (store) => {
    let connectCalls = 0;
    let capabilitiesCalls = 0;
    let now = new Date("2026-05-28T00:00:00.000Z");
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return connectResult({ sessionId: `session_${connectCalls.toString(16).padStart(2, "0")}` });
        },
        async getCapabilities() {
          capabilitiesCalls += 1;
          return defaultDriver().getCapabilities();
        },
      }),
      () => now,
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    await core.connectDevice({});
    // Advance past the advertised wire TTL. The target session is USB-link
    // bound, so Agent-Q validates and reuses it instead of treating local time
    // as session authority.
    now = new Date(now.getTime() + 1800001);
    await core.connectDevice({});
    assert.equal(connectCalls, 1);
    assert.equal(capabilitiesCalls, 1);
  });
});

test("connectDevice rejected does not store a session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          throw new DeviceRequestError("user_rejected", "Connection rejected.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    await assert.rejects(() => core.connectDevice({}), { code: "user_rejected" });
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
    // P1-C: the device answered the status handshake, so lastSeenAt is refreshed
    // even though the connect was rejected.
    assert.equal(typeof listed.devices[0].lastSeenAt, "string");
  });
});

test("connectDevice refreshes lastSeenAt on rejection", async () => {
  await withStore(async (store) => {
    let now = new Date("2026-05-28T00:00:00.000Z");
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          throw new DeviceRequestError("user_rejected", "Connection rejected.", false);
        },
      }),
      () => now,
    );
    await core.scanDevices();
    const firstSeen = (await store.load()).devices[0].lastSeenAt;
    await core.selectDevice({ deviceId: device.deviceId });

    now = new Date("2026-05-28T01:00:00.000Z");
    await assert.rejects(() => core.connectDevice({}), { code: "user_rejected" });

    const afterSeen = (await store.load()).devices[0].lastSeenAt;
    assert.notEqual(afterSeen, firstSeen);
    assert.equal(afterSeen, now.toISOString());
  });
});

test("getDeviceStatus resolves by purpose", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId, purpose: "payment" });

    const result = await core.getDeviceStatus({ purpose: "payment" });
    assert.equal(result.source, "live");
    assert.equal(result.status.device.deviceId, device.deviceId);
    assert.equal(result.status.provisioning.state, "unprovisioned");
  });
});

test("getDeviceStatus rejects reserved purpose 'default'", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await assert.rejects(() => core.getDeviceStatus({ purpose: "default" }), { code: "invalid_params" });
  });
});

test("connectDevice timeout does not store a session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          throw new DeviceRequestError("timeout", "Connection approval timed out.", true);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    await assert.rejects(() => core.connectDevice({}), { code: "timeout" });
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("connectDevice rejects when Firmware reports a different deviceId", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          return connectResult({ device: { ...device, deviceId: secondDevice.deviceId } });
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await assert.rejects(() => core.connectDevice({}), { code: "handshake_failed" });
  });
});

test("connectDevice resolves a device by purpose", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId, purpose: "payment" });
    const result = await core.connectDevice({ purpose: "payment" });
    assert.equal(result.deviceId, device.deviceId);
  });
});

test("connectDevice prefers explicit deviceId over purpose", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    // 'payment' purpose unset: passing deviceId still resolves.
    const result = await core.connectDevice({ deviceId: device.deviceId, purpose: "payment" });
    assert.equal(result.deviceId, device.deviceId);
  });
});

test("connectDevice without resolution rejects with no_active_device", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await assert.rejects(() => core.connectDevice({}), { code: "no_active_device" });
  });
});

test("connectDevice for unknown device rejects with device_not_found", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await assert.rejects(
      () => core.connectDevice({ deviceId: "00000000-0000-0000-0000-000000000000" }),
      { code: "device_not_found" },
    );
  });
});

test("disconnectDevice without a runtime session returns not_connected", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.disconnectDevice({});
    assert.equal(result.source, "not_connected");
    assert.equal(result.deviceId, device.deviceId);
    assert.equal(result.reason, "not_connected");
  });
});

test("disconnectDevice clears the runtime session after Firmware confirms", async () => {
  await withStore(async (store) => {
    let disconnectCalls = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async disconnectDevice() {
          disconnectCalls += 1;
          return {
            id: "req_disconnect",
            version: 1,
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.disconnectDevice({});
    assert.equal(disconnectCalls, 1);
    assert.equal(result.source, "disconnected");
    assert.equal(result.reason, "firmware_confirmed");

    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("disconnectDevice clears the runtime session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async disconnectDevice() {
          throw new DeviceRequestError("invalid_session", "Unknown session.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.disconnectDevice({});
    assert.equal(result.source, "disconnected");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("disconnectDevice clears local session when transport is gone", async () => {
  await withStore(async (store) => {
    let portAvailable = true;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          return portAvailable
            ? [
                {
                  path: "/dev/cu.usbmodem1",
                  vendorId: "303a",
                  productId: "1001",
                  manufacturer: "Espressif",
                },
              ]
            : [];
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});
    portAvailable = false;

    const result = await core.disconnectDevice({});
    assert.equal(result.source, "disconnected");
    assert.equal(result.reason, "transport_unavailable");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("disconnectDevice clears the local session and reports timeout when Firmware never confirms", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        // Firmware accepts the disconnect frame but never answers.
        disconnectDevice() {
          throw new DeviceRequestError("timeout", "Timed out.", true);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.disconnectDevice();
    assert.equal(result.source, "disconnected");
    assert.equal(result.reason, "timeout");
    // Agent-Q cannot confirm Firmware observed the disconnect, but it must not
    // keep reusing a session it cannot verify, so the local view clears.
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("after a disconnect timeout, connectDevice contacts Firmware again instead of reusing the cleared session", async () => {
  await withStore(async (store) => {
    let connectCalls = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return connectResult({
            sessionId: `session_${connectCalls.toString(16).padStart(2, "0")}`,
          });
        },
        disconnectDevice() {
          throw new DeviceRequestError("timeout", "Timed out.", true);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    await core.connectDevice({});
    assert.equal(connectCalls, 1);

    const disconnect = await core.disconnectDevice();
    assert.equal(disconnect.reason, "timeout");

    // The cleared session must not survive locally: a fresh connect re-contacts
    // Firmware rather than short-circuiting through Agent-Q process memory.
    await core.connectDevice({});
    assert.equal(connectCalls, 2);
  });
});

test("getAccounts without a runtime session returns not_connected", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.getAccounts({});
    assert.equal(result.source, "not_connected");
    assert.equal(result.reason, "not_connected");
    assert.equal(result.accounts, undefined);
  });
});

test("getCapabilities without a runtime session returns not_connected", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.getCapabilities({});
    assert.equal(result.source, "not_connected");
    assert.equal(result.reason, "not_connected");
    assert.equal(result.capabilities, undefined);
  });
});

test("getCapabilities returns Firmware-authored account identity and keeps the session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.getCapabilities({});
    assert.equal(result.source, "live");
    assert.equal(result.capabilities.length, 1);
    assert.equal(result.capabilities[0].id, "sui");
    assert.equal(result.capabilities[0].accounts[0].keyScheme, "ed25519");
    assert.deepEqual(result.capabilities[0].methods, []);
    assert.equal(result.signing.authorization, "user");
    assert.deepEqual(result.signing.methods, [
      { chain: "sui", method: "sign_transaction" },
      { chain: "sui", method: "sign_personal_message" },
    ]);
    assert.deepEqual(result.credentials, [
      {
        chain: "sui",
        credential: "zklogin",
        operations: ["credential_prepare", "credential_propose"],
      },
    ]);

    // Read-only: the session is retained after get_capabilities.
    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("getCapabilities clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async getCapabilities() {
          throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.getCapabilities({});
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("getAccounts returns the Sui account over an active session and keeps the session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.getAccounts({});
    assert.equal(result.source, "live");
    assert.equal(result.accounts.length, 1);
    assert.equal(result.accounts[0].chain, "sui");
    assert.equal(
      result.accounts[0].address,
      "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
    );
    assert.deepEqual(result.accounts[0].sponsoredTransactions, {
      acceptGasSponsor: false,
    });

    // Read-only: the session is retained after get_accounts.
    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("getAccounts clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async getAccounts() {
          throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.getAccounts({});
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("policyGet without a runtime session returns not_connected", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.policyGet({});
    assert.equal(result.source, "not_connected");
    assert.equal(result.reason, "not_connected");
    assert.equal(result.policy, undefined);
  });
});

test("policyGet returns the active Firmware policy document and keeps the session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.policyGet({});
    assert.equal(result.source, "live");
    assert.equal(result.policy.schema, "signing.policy");
    assert.equal(result.policy.policyId, POLICY_HASH);
    assert.equal(result.policy.defaultAction, "reject");
    assert.equal(result.policy.policyCount, 0);
    assert.deepEqual(result.policy.blockchains, currentPolicyDocument().blockchains);

    // Read-only: the session is retained after policy_get.
    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("policyGet clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async policyGet() {
          throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.policyGet({});
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("session-scoped APIs return not_connected before validating operation input", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const invalidSessionScopedCalls = [
      ["disconnectDevice", () => core.disconnectDevice({ unexpected: true })],
      ["getCapabilities", () => core.getCapabilities({ unexpected: true })],
      ["getAccounts", () => core.getAccounts({ unexpected: true })],
      ["policyGet", () => core.policyGet({ unexpected: true })],
      ["getApprovalHistory", () => core.getApprovalHistory({ limit: 5, unexpected: true })],
      ["policyPropose", () => core.policyPropose({ policy: { privateKey: "must-not-forward" }, unexpected: true })],
      [
        "signTransaction",
        () => core.signTransaction({
          chain: "sui",
          method: "sign_transaction",
          network: "devnet",
          txBytes: "not-base64",
          unexpected: true,
        }),
      ],
      [
        "signPersonalMessage",
        () => core.signPersonalMessage({
          chain: "sui",
          method: "sign_personal_message",
          network: "devnet",
          message: "not-base64",
          unexpected: true,
        }),
      ],
    ];

    for (const [name, call] of invalidSessionScopedCalls) {
      const result = await call();
      assert.equal(result.source, "not_connected", name);
      assert.equal(result.reason, "not_connected", name);
      assert.equal(result.deviceId, device.deviceId, name);
    }
  });
});

test("session-scoped APIs reject unsupported fields before USB live-port probing when connected", async () => {
  await withStore(async (store) => {
    let listPortsCalls = 0;
    let requestStatusCalls = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          listPortsCalls += 1;
          return [
            {
              path: "/dev/cu.usbmodem1",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus() {
          requestStatusCalls += 1;
          return status;
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    listPortsCalls = 0;
    requestStatusCalls = 0;

    const validPolicy = currentPolicyDocument();
    const validMessage = Buffer.from("hello").toString("base64");
    const invalidConnectedCalls = [
      ["disconnectDevice", () => core.disconnectDevice({ unexpected: true })],
      ["getCapabilities", () => core.getCapabilities({ unexpected: true })],
      ["getAccounts", () => core.getAccounts({ unexpected: true })],
      ["policyGet", () => core.policyGet({ unexpected: true })],
      ["getApprovalHistory", () => core.getApprovalHistory({ unexpected: true })],
      ["policyPropose", () => core.policyPropose({ policy: validPolicy, unexpected: true })],
      [
        "signTransaction",
        () => core.signTransaction({
          chain: "sui",
          method: "sign_transaction",
          network: "devnet",
          txBytes: CANONICAL_TX_BYTES_BASE64,
          unexpected: true,
        }),
      ],
      [
        "signPersonalMessage",
        () => core.signPersonalMessage({
          chain: "sui",
          method: "sign_personal_message",
          network: "devnet",
          message: validMessage,
          unexpected: true,
        }),
      ],
    ];

    for (const [name, call] of invalidConnectedCalls) {
      await assert.rejects(call, { code: "invalid_params" }, name);
      assert.equal(listPortsCalls, 0, name);
      assert.equal(requestStatusCalls, 0, name);
    }
  });
});

test("getApprovalHistory without a runtime session returns not_connected", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.getApprovalHistory({});
    assert.equal(result.source, "not_connected");
    assert.equal(result.reason, "not_connected");
    assert.equal(result.records, undefined);
  });
});

test("getApprovalHistory returns Firmware-owned history and keeps the session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.getApprovalHistory({ limit: 1, beforeSeq: "42" });
    assert.equal(result.source, "live");
    assert.equal(result.records.length, 1);
    assert.equal(result.records[0].eventKind, "signing");
    assert.equal(result.records[0].authorization, "policy");
    assert.equal(result.records[0].terminalResult, "policy_rejected");
    assert.equal(result.records[0].reasonCode, "default_reject");
    assert.equal(result.hasMore, false);

    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("getApprovalHistory preserves blind-signing confirmation reason codes", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async getApprovalHistory() {
          return {
            id: "req_approval_history",
            version: 1,
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
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.getApprovalHistory({ limit: 1 });
    assert.equal(result.source, "live");
    assert.equal(result.records.length, 1);
    assert.equal(result.records[0].eventKind, "signing");
    assert.equal(result.records[0].authorization, "user");
    assert.equal(result.records[0].recordKind, "confirmation");
    assert.equal(result.records[0].confirmationKind, "local_pin");
    assert.equal(result.records[0].reasonCode, "blind_signing_confirmed");
  });
});

test("getApprovalHistory validates pagination before USB live-port probing", async () => {
  await withStore(async (store) => {
    let listPortsCalls = 0;
    let requestStatusCalls = 0;
    let historyCalls = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          listPortsCalls += 1;
          return [
            {
              path: "/dev/cu.usbmodem1",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus() {
          requestStatusCalls += 1;
          return status;
        },
        async getApprovalHistory() {
          historyCalls += 1;
          return {
            id: "req_approval_history",
            version: 1,
            records: [],
            hasMore: false,
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    listPortsCalls = 0;
    requestStatusCalls = 0;
    historyCalls = 0;

    await assert.rejects(() => core.getApprovalHistory({ limit: 5 }), { code: "invalid_params" });
    assert.equal(listPortsCalls, 0);
    assert.equal(requestStatusCalls, 0);
    assert.equal(historyCalls, 0);
  });
});

test("getApprovalHistory clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async getApprovalHistory() {
          throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.getApprovalHistory({});
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("signTransaction without a runtime session returns not_connected before validating signable payload", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "not-base64",
    });
    assert.equal(result.source, "not_connected");
    assert.equal(result.reason, "not_connected");
    assert.equal(result.status, undefined);
  });
});

test("signing route identity is selected before runtime-session lookup", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    await assert.rejects(
      () => core.signTransaction({
        chain: "evm",
        method: "sign_transaction",
        network: "devnet",
        txBytes: "not-base64",
      }),
      { code: "unsupported_chain" },
    );
    await assert.rejects(
      () => core.signTransaction({
        chain: "sui",
        method: "sign_personal_message",
        network: "devnet",
        txBytes: "not-base64",
      }),
      { code: "unsupported_method" },
    );
    await assert.rejects(
      () => core.signPersonalMessage({
        chain: "SUI",
        method: "sign_personal_message",
        network: "devnet",
        message: "not-base64",
      }),
      { code: "invalid_params" },
    );
  });
});

test("signTransaction returns Firmware's policy_rejected signing outcome and keeps the session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction() {
          return {
            id: "req_sign_policy",
            version: 1,
            authorization: "policy",
            status: "policy_rejected",
            policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            ruleRef: "default",
            error: {
              code: "policy_rejected",
              message: SIGNING_OUTCOME_ERROR_MESSAGES.policy_rejected,
            },
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: CANONICAL_TX_BYTES_BASE64,
    });
    assert.equal(result.source, "live");
    assert.equal(result.status, "policy_rejected");
    assert.equal(result.authorization, "policy");
    assert.equal(result.error.code, "policy_rejected");

    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("signTransaction uses the internal request deadline by default", async () => {
  await withStore(async (store) => {
    let observedTimeoutMs = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction(_portPath, _sessionId, _route, _params, deadlineMs) {
          observedTimeoutMs = deadlineMs;
          return {
            id: "req_sign_policy",
            version: 1,
            authorization: "policy",
            status: "policy_rejected",
            policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            ruleRef: "default",
            error: {
              code: "policy_rejected",
              message: SIGNING_OUTCOME_ERROR_MESSAGES.policy_rejected,
            },
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: CANONICAL_TX_BYTES_BASE64,
    });
    assert.equal(result.status, "policy_rejected");
    assert.equal(observedTimeoutMs, 185000);
  });
});

test("signTransaction propagates history_unavailable without clearing the session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction() {
          throw new DeviceRequestError("history_unavailable", "Could not record policy signing approval.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    await assert.rejects(
      () => core.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: "devnet",
        txBytes: CANONICAL_TX_BYTES_BASE64,
      }),
      { code: "history_unavailable" },
    );

    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("signTransaction preserves the local session on post-write transport failure", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction() {
          throw new DeviceRequestError("transport_closed", "USB serial transport closed.", true);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    await assert.rejects(
      () => core.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: "devnet",
        txBytes: CANONICAL_TX_BYTES_BASE64,
      }),
      { code: "transport_closed" },
    );

    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("signTransaction validates input before USB live-port probing", async () => {
  await withStore(async (store) => {
    let listPortsCalls = 0;
    let requestStatusCalls = 0;
    let signTransactionCalls = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          listPortsCalls += 1;
          return [
            {
              path: "/dev/cu.usbmodem1",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus() {
          requestStatusCalls += 1;
          return status;
        },
        async signTransaction() {
          signTransactionCalls += 1;
          return {
            id: "req_sign_policy",
            version: 1,
            authorization: "policy",
            status: "policy_rejected",
            policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            ruleRef: "default",
            error: {
              code: "policy_rejected",
              message: SIGNING_OUTCOME_ERROR_MESSAGES.policy_rejected,
            },
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    listPortsCalls = 0;
    requestStatusCalls = 0;
    signTransactionCalls = 0;

    await assert.rejects(
      () => core.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: "devnet",
        txBytes: CANONICAL_TX_BYTES_BASE64,
        seed: "must-not-forward",
      }),
      { code: "invalid_params" },
    );
    assert.equal(listPortsCalls, 0);
    assert.equal(requestStatusCalls, 0);
    assert.equal(signTransactionCalls, 0);
  });
});

test("signTransaction clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction() {
          throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: CANONICAL_TX_BYTES_BASE64,
    });
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("signTransaction clears the local session when get_result reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction(_portPath, sessionId, route, params) {
          const request = signTransactionDeviceRequest(sessionId, route, params);
          return requestSigningOutcomeWithRecovery(request, 1000, deviceRequestExecutor(async (wireRequest) => {
            if (wireKind(wireRequest) === "sign_transaction") {
              throw markRequestMayHaveReachedFirmware(new DeviceRequestError("timeout", "Original sign timeout.", true));
            }
            if (wireKind(wireRequest) === "get_result") {
              throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
            }
            throw new Error(`unexpected request: ${wireKind(wireRequest)}`);
          }));
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: CANONICAL_TX_BYTES_BASE64,
    });
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("signTransaction returns recovered result and clears the local session when ack_result reports invalid_session", async () => {
  await withStore(async (store) => {
    const signature = suiEd25519Signature(3);
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction(_portPath, sessionId, route, params) {
          const request = signTransactionDeviceRequest(sessionId, route, params);
          return requestSigningOutcomeWithRecovery(request, 1000, deviceRequestExecutor(async (wireRequest, _deadlineMs, assertResponse) => {
            if (wireKind(wireRequest) === "sign_transaction") {
              throw markRequestMayHaveReachedFirmware(new DeviceRequestError("transport_closed", "Transport closed.", true));
            }
            if (wireKind(wireRequest) === "get_result") {
              return assertResponse(signedDeviceResult(
                wireRequest.id,
                "get_result",
                "sign_transaction",
                signature,
              ));
            }
            if (wireKind(wireRequest) === "ack_result") {
              throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
            }
            throw new Error(`unexpected request: ${wireKind(wireRequest)}`);
          }));
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: CANONICAL_TX_BYTES_BASE64,
    });
    assert.equal(result.source, "live");
    assert.equal(result.status, "signed");
    assert.equal(result.signature, signature);

    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
    const capabilities = await core.getCapabilities({});
    assert.equal(capabilities.source, "not_connected");
  });
});

test("signTransaction returns not_connected before validating signable payload", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "not-base64",
    });
    assert.deepEqual(result, {
      source: "not_connected",
      deviceId: device.deviceId,
      reason: "not_connected",
    });
  });
});

test("signTransaction forwards a bounded provider signing request with internal local-PIN interaction budget", async () => {
  await withStore(async (store) => {
    let observed = null;
    const signature = suiEd25519Signature(7);
    const core = new DeviceCore(
      store,
      defaultDriver({
        async getCapabilities() {
          return {
            id: "req_capabilities",
            version: 1,
            chains: [
              {
                id: "sui",
                accounts: [
                  {
                    keyScheme: "ed25519",
                    derivationPath: "m/44'/784'/0'/0'/0'",
                  },
                ],
                methods: [],
              },
            ],
            signing: {
              authorization: "user",
              methods: [
                { chain: "sui", method: "sign_transaction" },
                { chain: "sui", method: "sign_personal_message" },
              ],
            },
          };
        },
        async signTransaction(portPath, sessionId, route, params, deadlineMs) {
          observed = { portPath, sessionId, route, params, deadlineMs };
          return {
            id: "req_sign_user",
            version: 1,
            authorization: "user",
            status: "signed",
            chain: "sui",
            method: "sign_transaction",
            signature,
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const capabilities = await core.getCapabilities({});
    assert.equal(capabilities.signing.authorization, "user");
    assert.deepEqual(capabilities.signing.methods, [
      { chain: "sui", method: "sign_transaction" },
      { chain: "sui", method: "sign_personal_message" },
    ]);

    const result = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: CANONICAL_TX_BYTES_BASE64,
    });
    assert.deepEqual(result, {
      source: "live",
      deviceId: device.deviceId,
      status: "signed",
      authorization: "user",
      chain: "sui",
      method: "sign_transaction",
      signature,
    });
    assert.deepEqual(observed, {
      portPath: "/dev/cu.usbmodem1",
      sessionId: "session_aabbccdd",
      route: {
        operation: "sign_transaction",
        chain: "sui",
        method: "sign_transaction",
        route: "sui_sign_transaction",
      },
      params: {
        network: "devnet",
        txBytes: CANONICAL_TX_BYTES_BASE64,
      },
      deadlineMs: 185000,
    });
  });
});

test("signTransaction forwards canonical payload above the removed inline payload cap", async () => {
  await withStore(async (store) => {
    const txBytes = Buffer.alloc(385, 1).toString("base64");
    let observedTxBytes = null;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction(_portPath, _sessionId, _route, params) {
          observedTxBytes = params.txBytes;
          return {
            id: "req_sign_policy",
            version: 1,
            authorization: "policy",
            status: "policy_rejected",
            policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
            ruleRef: "default",
            error: {
              code: "policy_rejected",
              message: SIGNING_OUTCOME_ERROR_MESSAGES.policy_rejected,
            },
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes,
    });
    assert.equal(observedTxBytes, txBytes);
  });
});

test("signTransaction returns Firmware terminal outcomes without throwing", async () => {
  for (const terminal of [
    {
      status: "user_rejected",
      code: "user_rejected",
      message: SIGNING_OUTCOME_ERROR_MESSAGES.user_rejected,
    },
    {
      status: "user_timed_out",
      code: "user_timed_out",
      message: SIGNING_OUTCOME_ERROR_MESSAGES.user_timed_out,
    },
    {
      status: "signing_failed",
      code: "signing_failed",
      message: SIGNING_OUTCOME_ERROR_MESSAGES.signing_failed,
    },
  ]) {
    await withStore(async (store) => {
      const core = new DeviceCore(
        store,
        defaultDriver({
          async signTransaction() {
            return {
              id: "req_sign_user",
              version: 1,
              authorization: "user",
              status: terminal.status,
              error: {
                code: terminal.code,
                message: terminal.message,
              },
            };
          },
        }),
      );
      await core.scanDevices();
      await core.selectDevice({ deviceId: device.deviceId });
      await core.connectDevice({});

      const result = await core.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: "devnet",
        txBytes: CANONICAL_TX_BYTES_BASE64,
      });
      assert.equal(result.source, "live");
      assert.equal(result.status, terminal.status);
      assert.equal(result.authorization, "user");
      if (result.source === "live" && result.status !== "signed") {
        assert.equal(result.error.code, terminal.code);
      }
    });
  }
});

test("signTransaction validates params before USB live-port probing", async () => {
  await withStore(async (store) => {
    let listPortsCalls = 0;
    let requestStatusCalls = 0;
    let signTransactionCalls = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          listPortsCalls += 1;
          return [
            {
              path: "/dev/cu.usbmodem1",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus() {
          requestStatusCalls += 1;
          return status;
        },
        async signTransaction() {
          signTransactionCalls += 1;
          throw new Error("sign_transaction should not reach USB");
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    listPortsCalls = 0;
    requestStatusCalls = 0;

    await assert.rejects(
      () => core.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: "devnet",
        txBytes: CANONICAL_TX_BYTES_BASE64,
        timeoutMs: 30000,
      }),
      { code: "invalid_params" },
    );
    await assert.rejects(
      () => core.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: "devnet",
        txBytes: CANONICAL_TX_BYTES_BASE64,
        privateKey: "must-not-forward",
      }),
      { code: "invalid_params" },
    );
    assert.equal(listPortsCalls, 0);
    assert.equal(requestStatusCalls, 0);
    assert.equal(signTransactionCalls, 0);
  });
});

test("signTransaction clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signTransaction() {
          throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: CANONICAL_TX_BYTES_BASE64,
    });
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("signPersonalMessage returns not_connected before validating message payload", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.signPersonalMessage({
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: "not-base64",
    });
    assert.deepEqual(result, {
      source: "not_connected",
      deviceId: device.deviceId,
      reason: "not_connected",
    });
  });
});

test("signPersonalMessage forwards a bounded user signing request with internal local-PIN interaction budget", async () => {
  await withStore(async (store) => {
    let observed = null;
    const signature = suiEd25519Signature(9);
    const messageBytes = Buffer.from("hello").toString("base64");
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signPersonalMessage(portPath, sessionId, route, params, deadlineMs) {
          observed = { portPath, sessionId, route, params, deadlineMs };
          return {
            id: "req_sign_personal_message",
            version: 1,
            authorization: "user",
            status: "signed",
            chain: "sui",
            method: "sign_personal_message",
            signature,
            messageBytes,
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.signPersonalMessage({
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: messageBytes,
    });
    assert.deepEqual(result, {
      source: "live",
      deviceId: device.deviceId,
      status: "signed",
      authorization: "user",
      chain: "sui",
      method: "sign_personal_message",
      signature,
      messageBytes,
    });
    assert.deepEqual(observed, {
      portPath: "/dev/cu.usbmodem1",
      sessionId: "session_aabbccdd",
      route: {
        operation: "sign_personal_message",
        chain: "sui",
        method: "sign_personal_message",
        route: "sui_sign_personal_message",
      },
      params: {
        network: "devnet",
        message: messageBytes,
      },
      deadlineMs: 185000,
    });
  });
});

test("signPersonalMessage validates params before USB live-port probing", async () => {
  await withStore(async (store) => {
    let listPortsCalls = 0;
    let requestStatusCalls = 0;
    let signPersonalMessageCalls = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          listPortsCalls += 1;
          return [
            {
              path: "/dev/cu.usbmodem1",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus() {
          requestStatusCalls += 1;
          return status;
        },
        async signPersonalMessage() {
          signPersonalMessageCalls += 1;
          throw new Error("sign_personal_message should not reach USB");
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    listPortsCalls = 0;
    requestStatusCalls = 0;

    await assert.rejects(
      () => core.signPersonalMessage({
        chain: "sui",
        method: "sign_personal_message",
        network: "devnet",
        message: Buffer.from("hello").toString("base64"),
        timeoutMs: 30000,
      }),
      { code: "invalid_params" },
    );
    await assert.rejects(
      () => core.signPersonalMessage({
        chain: "sui",
        method: "sign_personal_message",
        network: "devnet",
        message: "not-base64",
      }),
      { code: "invalid_params" },
    );
    assert.equal(listPortsCalls, 0);
    assert.equal(requestStatusCalls, 0);
    assert.equal(signPersonalMessageCalls, 0);
  });
});

test("signPersonalMessage clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signPersonalMessage() {
          throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.signPersonalMessage({
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: Buffer.from("hello").toString("base64"),
    });
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("signPersonalMessage returns recovered result and clears the local session when ack_result reports invalid_session", async () => {
  await withStore(async (store) => {
    const signature = suiEd25519Signature(4);
    const messageBytes = Buffer.from("hello").toString("base64");
    const core = new DeviceCore(
      store,
      defaultDriver({
        async signPersonalMessage(_portPath, sessionId, route, params) {
          const request = signPersonalMessageDeviceRequest(sessionId, route, params);
          return requestSigningOutcomeWithRecovery(request, 1000, deviceRequestExecutor(async (wireRequest, _deadlineMs, assertResponse) => {
            if (wireKind(wireRequest) === "sign_personal_message") {
              throw markRequestMayHaveReachedFirmware(new DeviceRequestError("transport_closed", "Transport closed.", true));
            }
            if (wireKind(wireRequest) === "get_result") {
              return assertResponse(signedDeviceResult(
                wireRequest.id,
                "get_result",
                "sign_personal_message",
                signature,
                { messageBytes },
              ));
            }
            if (wireKind(wireRequest) === "ack_result") {
              throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
            }
            throw new Error(`unexpected request: ${wireKind(wireRequest)}`);
          }));
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.signPersonalMessage({
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: messageBytes,
    });
    assert.equal(result.source, "live");
    assert.equal(result.status, "signed");
    assert.equal(result.signature, signature);
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("policyPropose returns not_connected before validating policy payload", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.policyPropose({
      policy: { seed: "must-not-forward" },
    });
    assert.deepEqual(result, {
      source: "not_connected",
      deviceId: device.deviceId,
      reason: "not_connected",
    });
  });
});

test("policyPropose forwards a bounded proposal and returns Firmware terminal metadata", async () => {
  await withStore(async (store) => {
    let observed = null;
    const policy = currentPolicyDocument([
      {
        id: "reject_devnet",
        action: "reject",
        conditions: [{ field: "sui.command_kinds", op: "not_contains", values: ["publish"] }],
      },
    ]);
    const core = new DeviceCore(
      store,
      defaultDriver({
        async policyPropose(portPath, sessionId, submittedPolicy, deadlineMs) {
          observed = { portPath, sessionId, submittedPolicy, deadlineMs };
          return {
            id: "req_policy_propose",
            version: 1,
            status: "applied",
            reasonCode: "device_confirmed",
            policy: currentPolicyProposeSummary(),
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.policyPropose({ policy });
    assert.equal(result.source, "live");
    assert.equal(result.status, "applied");
    assert.equal(result.reasonCode, "device_confirmed");
    assert.equal(result.policy.policyCount, 1);
    assert.deepEqual(observed, {
      portPath: "/dev/cu.usbmodem1",
      sessionId: "session_aabbccdd",
      submittedPolicy: policy,
      deadlineMs: 185000,
    });
  });
});

test("policyPropose validates proposals before live-port probing", async () => {
  await withStore(async (store) => {
    let listPortsCalls = 0;
    let requestStatusCalls = 0;
    let proposeCalls = 0;
    const core = new DeviceCore(
      store,
      defaultDriver({
        async listPorts() {
          listPortsCalls += 1;
          return [
            {
              path: "/dev/cu.usbmodem1",
              vendorId: "303a",
              productId: "1001",
              manufacturer: "Espressif",
            },
          ];
        },
        async requestStatus() {
          requestStatusCalls += 1;
          return status;
        },
        async policyPropose() {
          proposeCalls += 1;
          throw new Error("proposal should not reach USB");
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    listPortsCalls = 0;
    requestStatusCalls = 0;

    await assert.rejects(
      () => core.policyPropose({ policy: { privateKey: "must-not-forward" } }),
      { code: "invalid_params" },
    );
    assert.equal(listPortsCalls, 0);
    assert.equal(requestStatusCalls, 0);
    assert.equal(proposeCalls, 0);

    await assert.rejects(
      () => core.policyPropose({ policy: { schema: "signing.policy" }, extra: true }),
      { code: "invalid_params" },
    );
    assert.equal(listPortsCalls, 0);
    assert.equal(requestStatusCalls, 0);
    assert.equal(proposeCalls, 0);
  });
});

test("policyPropose clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async policyPropose() {
          throw new DeviceRequestError("invalid_session", "Session is unknown or already ended.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.policyPropose({
      policy: currentPolicyDocument(),
    });
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("policyPropose clears the local session when Firmware reports consistency_error", async () => {
  await withStore(async (store) => {
    const core = new DeviceCore(
      store,
      defaultDriver({
        async policyPropose() {
          return {
            id: "req_policy_propose",
            version: 1,
            status: "consistency_error",
            reasonCode: "consistency_error",
            policy: currentPolicyProposeSummary(),
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.policyPropose({
      policy: currentPolicyDocument(),
    });
    assert.equal(result.source, "live");
    assert.equal(result.status, "consistency_error");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});
