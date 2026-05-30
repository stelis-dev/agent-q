import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ConfigStore } from "../dist/config.js";
import { GatewayCore } from "../dist/core.js";
import { GatewayError } from "../dist/errors.js";

const device = {
  deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
  state: "idle",
  firmwareName: "Agent-Q Firmware",
  hardware: "hardware-id",
  firmwareVersion: "0.0.0",
};

const status = {
  id: "req_1",
  version: 1,
  type: "status",
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

function identifyResponse(code, identifiedDevice = device) {
  return {
    id: "req_identify",
    version: 1,
    type: "identify_device_result",
    status: "displayed",
    code,
    device: identifiedDevice,
  };
}

function approvedConnectResponse(extras = {}) {
  return {
    id: "req_connect",
    version: 1,
    type: "connect_result",
    status: "approved",
    sessionId: "session_aabbccdd",
    sessionTtlMs: 1800000,
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
      return approvedConnectResponse();
    },
    async disconnectDevice() {
      return {
        id: "req_disconnect",
        version: 1,
        type: "disconnect_result",
        status: "disconnected",
      };
    },
    async getCapabilities() {
      return {
        id: "req_capabilities",
        version: 1,
        type: "capabilities",
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
      };
    },
    async getAccounts() {
      return {
        id: "req_accounts",
        version: 1,
        type: "accounts",
        accounts: [
          {
            chain: "sui",
            address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
            publicKey: "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk=",
            keyScheme: "ed25519",
            derivationPath: "m/44'/784'/0'/0'/0'",
          },
        ],
      };
    },
    async callMethod() {
      return {
        id: "req_call_method",
        version: 1,
        type: "method_result",
        status: "rejected",
        error: {
          code: "unsupported_method",
          message: "Method is not supported.",
        },
      };
    },
    ...overrides,
  };
}

async function withStore(callback) {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-core-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    return await callback(store, dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("returns no_active_device when no active device exists", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver({ async listPorts() { return []; } }));
    await assert.rejects(() => core.getDeviceStatus(), { code: "no_active_device" });
  });
});

test("returns cached status for known device when live request times out", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.usbmodem1", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });

    const core = new GatewayCore(
      store,
      defaultDriver({
        async requestStatus() {
          throw new GatewayError("timeout", "Timed out.", true);
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

test("core bounds a driver that ignores its handshake timeout", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.usbmodem1", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });
    const core = new GatewayCore(
      store,
      defaultDriver({
        requestStatus() {
          // Hangs and ignores its timeout argument; the GatewayCore driver wrapper
          // (deadlineEnforcingDriver) must still bound it within timeoutMs.
          return new Promise(() => {});
        },
      }),
    );

    const result = await core.getDeviceStatus({ timeoutMs: 50 });
    assert.equal(result.source, "cached");
    assert.equal(result.unavailableReason, "timeout");
  });
});

test("falls back to scan when stored port hint is stale", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.stale", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });

    const requestedPorts = [];
    const core = new GatewayCore(
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
    const core = new GatewayCore(store, defaultDriver());
    const result = await core.scanDevices();
    assert.equal(result.devices.length, 1);
    assert.equal(result.activeDeviceId, null);
    assert.equal((await store.load()).devices[0].deviceId, device.deviceId);
    assert.equal((await store.load()).activeDeviceId, null);
  });
});

test("scan sanitizes an OS-supplied port path before returning or storing it", async () => {
  await withStore(async (store) => {
    const weirdPath = "/dev/cu." + String.fromCharCode(7) + "usbmodem9";
    const core = new GatewayCore(
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
    assert.equal(result.devices[0].portPath, "/dev/cu.usbmodem9", "control char stripped from live port path");
    assert.equal((await store.load()).devices[0].lastPortHint, "/dev/cu.usbmodem9");
  });
});

test("scan does not select an active device when multiple devices are found", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(
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
    assert.equal(result.activeDeviceId, null);
    assert.equal((await store.load()).activeDeviceId, null);
  });
});

test("identifies devices without selecting one", async () => {
  await withStore(async (store) => {
    const identifiedCodes = [];
    const core = new GatewayCore(
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

    const result = await core.identifyDevices({ durationMs: 10000 });
    assert.equal(result.devices.length, 2);
    assert.equal(result.devices.every((candidate) => candidate.status === "displayed"), true);
    assert.equal(new Set(identifiedCodes).size, 2);
    assert.equal(result.activeDeviceId, null);
    assert.equal((await store.load()).activeDeviceId, null);
  });
});

test("identify reports per-device errors without failing the whole request", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(
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
            throw new GatewayError("timeout", "Timed out.", true);
          }
          return identifyResponse(code);
        },
      }),
    );

    const result = await core.identifyDevices({ durationMs: 10000 });
    assert.equal(result.source, "live");
    assert.equal(result.devices.length, 2);
    assert.equal(result.devices[0].status, "displayed");
    assert.equal(result.devices[1].status, "error");
    assert.equal(result.devices[1].error.code, "timeout");
  });
});

test("identify bounds the whole call to timeoutMs across multiple devices", async () => {
  await withStore(async (store) => {
    // Injected virtual clock: the first identify advances time past the budget, so
    // the second device is reported as a timeout deterministically (no real wait).
    let now = new Date("2026-05-28T00:00:00.000Z");
    const core = new GatewayCore(
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
          now = new Date(now.getTime() + 60);
          return identifyResponse(code, portPath === "/dev/cu.usbmodem1" ? device : secondDevice);
        },
      }),
      () => now,
    );

    const result = await core.identifyDevices({ timeoutMs: 50, durationMs: 10000 });
    assert.equal(result.devices.length, 2);
    assert.deepEqual(result.devices.map((entry) => entry.status).sort(), ["displayed", "error"]);
    const errored = result.devices.find((entry) => entry.status === "error");
    assert.equal(errored.error.code, "timeout");
  });
});

test("selects default and purpose-specific active devices", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.usbmodem1");
    const core = new GatewayCore(store, defaultDriver());

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
    const core = new GatewayCore(store, defaultDriver());
    await assert.rejects(
      () => core.selectDevice({ deviceId: device.deviceId, purpose: "default" }),
      { code: "reserved_purpose" },
    );
  });
});

test("listDevices reports purposes and runtime session state", async () => {
  await withStore(async (store) => {
    const now = new Date("2026-05-28T00:00:00.000Z");
    const core = new GatewayCore(store, defaultDriver(), () => now);
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId, purpose: "payment" });
    await core.connectDevice({ deviceId: device.deviceId });

    const result = await core.listDevices();
    assert.equal(result.devices.length, 1);
    assert.deepEqual(result.devices[0].assignedPurposes, ["payment"]);
    assert.equal(result.devices[0].runtimeSession?.expiresAt, new Date(now.getTime() + 1800000).toISOString());
    // sessionId is internal to Gateway and must not surface in list output.
    assert.equal("sessionId" in (result.devices[0].runtimeSession ?? {}), false);
  });
});

test("setDeviceMetadata updates label via core", async () => {
  await withStore(async (store) => {
    await store.rememberUsbStatus(status, "/dev/cu.usbmodem1");
    const core = new GatewayCore(store, defaultDriver());
    const result = await core.setDeviceMetadata({ deviceId: device.deviceId, label: "Desk device" });
    assert.equal(result.label, "Desk device");
    assert.equal((await store.load()).devices[0].label, "Desk device");
  });
});

test("connectDevice approved stores in-memory session and does not persist sessionId", async () => {
  await withStore(async (store, dir) => {
    let connectCalls = 0;
    const core = new GatewayCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return approvedConnectResponse();
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.connectDevice({});
    assert.equal(connectCalls, 1);
    assert.equal(result.source, "connected");
    assert.equal(result.reused, false);
    assert.equal("sessionId" in result, false, "connect result must not expose sessionId");
    assert.equal(result.sessionTtlMs, 1800000);

    const raw = await readFile(join(dir, "config.json"), "utf8");
    assert.equal(raw.includes("session"), false, "config must not persist session state");
  });
});

test("connectDevice reuses a non-expired runtime session without contacting Firmware again", async () => {
  await withStore(async (store) => {
    let connectCalls = 0;
    const core = new GatewayCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return approvedConnectResponse();
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const first = await core.connectDevice({});
    const second = await core.connectDevice({});
    assert.equal(connectCalls, 1);
    assert.equal(second.reused, true);
    assert.equal(second.connectedAt, first.connectedAt);
    assert.equal(second.expiresAt, first.expiresAt);
  });
});

test("connectDevice reuse is local: it does not scan ports or contact Firmware", async () => {
  await withStore(async (store) => {
    let listPortsCalls = 0;
    let connectCalls = 0;
    let portAvailable = true;
    const core = new GatewayCore(
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
          return approvedConnectResponse();
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});
    assert.equal(connectCalls, 1);

    const listPortsAfterConnect = listPortsCalls;
    // Device physically disappears, but reuse must not scan or contact Firmware:
    // it returns Gateway's local session view. Firmware-side loss only surfaces
    // later on disconnect or a session-scoped request.
    portAvailable = false;
    const reused = await core.connectDevice({});
    assert.equal(reused.reused, true);
    assert.equal(connectCalls, 1, "reuse must not send a Firmware connect");
    assert.equal(listPortsCalls, listPortsAfterConnect, "reuse must not scan ports");

    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("connectDevice asks Firmware again after local TTL expiry", async () => {
  await withStore(async (store) => {
    let connectCalls = 0;
    let now = new Date("2026-05-28T00:00:00.000Z");
    const core = new GatewayCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return approvedConnectResponse({ sessionId: `session_${connectCalls.toString(16).padStart(2, "0")}` });
        },
      }),
      () => now,
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    await core.connectDevice({});
    // Advance past the session TTL.
    now = new Date(now.getTime() + 1800001);
    const second = await core.connectDevice({});
    assert.equal(connectCalls, 2);
    assert.equal(second.reused, false);
  });
});

test("connectDevice rejected does not store a session", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(
      store,
      defaultDriver({
        async connectDevice() {
          return {
            id: "req_connect",
            version: 1,
            type: "connect_result",
            status: "rejected",
            error: { code: "rejected", message: "Connection rejected." },
          };
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    await assert.rejects(() => core.connectDevice({}), { code: "rejected" });
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
    const core = new GatewayCore(
      store,
      defaultDriver({
        async connectDevice() {
          return {
            id: "req_connect",
            version: 1,
            type: "connect_result",
            status: "rejected",
            error: { code: "rejected", message: "Connection rejected." },
          };
        },
      }),
      () => now,
    );
    await core.scanDevices();
    const firstSeen = (await store.load()).devices[0].lastSeenAt;
    await core.selectDevice({ deviceId: device.deviceId });

    now = new Date("2026-05-28T01:00:00.000Z");
    await assert.rejects(() => core.connectDevice({}), { code: "rejected" });

    const afterSeen = (await store.load()).devices[0].lastSeenAt;
    assert.notEqual(afterSeen, firstSeen);
    assert.equal(afterSeen, now.toISOString());
  });
});

test("getDeviceStatus resolves by purpose", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId, purpose: "payment" });

    const result = await core.getDeviceStatus({ purpose: "payment" });
    assert.equal(result.source, "live");
    assert.equal(result.protocolResponse.device.deviceId, device.deviceId);
    assert.equal(result.protocolResponse.provisioning.state, "unprovisioned");
  });
});

test("getDeviceStatus rejects reserved purpose 'default'", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
    await core.scanDevices();
    await assert.rejects(() => core.getDeviceStatus({ purpose: "default" }), { code: "reserved_purpose" });
  });
});

test("connectDevice timeout does not store a session", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(
      store,
      defaultDriver({
        async connectDevice() {
          return {
            id: "req_connect",
            version: 1,
            type: "connect_result",
            status: "rejected",
            error: { code: "timeout", message: "Connection approval timed out." },
          };
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
    const core = new GatewayCore(
      store,
      defaultDriver({
        async connectDevice() {
          return approvedConnectResponse({ device: { ...device, deviceId: secondDevice.deviceId } });
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
    const core = new GatewayCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId, purpose: "payment" });
    const result = await core.connectDevice({ purpose: "payment" });
    assert.equal(result.deviceId, device.deviceId);
  });
});

test("connectDevice prefers explicit deviceId over purpose", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    // 'payment' purpose unset: passing deviceId still resolves.
    const result = await core.connectDevice({ deviceId: device.deviceId, purpose: "payment" });
    assert.equal(result.deviceId, device.deviceId);
  });
});

test("connectDevice without resolution rejects with no_active_device", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
    await assert.rejects(() => core.connectDevice({}), { code: "no_active_device" });
  });
});

test("connectDevice for unknown device rejects with device_not_found", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
    await assert.rejects(
      () => core.connectDevice({ deviceId: "00000000-0000-0000-0000-000000000000" }),
      { code: "device_not_found" },
    );
  });
});

test("disconnectDevice without a runtime session returns not_connected", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
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
    const core = new GatewayCore(
      store,
      defaultDriver({
        async disconnectDevice() {
          disconnectCalls += 1;
          return {
            id: "req_disconnect",
            version: 1,
            type: "disconnect_result",
            status: "disconnected",
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
    const core = new GatewayCore(
      store,
      defaultDriver({
        async disconnectDevice() {
          throw new GatewayError("invalid_session", "Unknown session.", false);
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
    const core = new GatewayCore(
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
    const core = new GatewayCore(
      store,
      defaultDriver({
        // Firmware accepts the disconnect frame but never answers. The driver
        // ignores its timeout; deadlineEnforcingDriver (wired in GatewayCore's
        // constructor) bounds the hang and surfaces a GatewayError("timeout").
        disconnectDevice() {
          return new Promise(() => {});
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.disconnectDevice({ timeoutMs: 50 });
    assert.equal(result.source, "disconnected");
    assert.equal(result.reason, "timeout");
    // Gateway cannot confirm Firmware observed the disconnect, but it must not
    // keep reusing a session it can no longer verify, so the local view clears.
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});

test("after a disconnect timeout, connectDevice contacts Firmware again instead of reusing the cleared session", async () => {
  await withStore(async (store) => {
    let connectCalls = 0;
    const core = new GatewayCore(
      store,
      defaultDriver({
        async connectDevice() {
          connectCalls += 1;
          return approvedConnectResponse({
            sessionId: `session_${connectCalls.toString(16).padStart(2, "0")}`,
          });
        },
        disconnectDevice() {
          return new Promise(() => {});
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const first = await core.connectDevice({});
    assert.equal(connectCalls, 1);
    assert.equal(first.reused, false);

    const disconnect = await core.disconnectDevice({ timeoutMs: 50 });
    assert.equal(disconnect.reason, "timeout");

    // The cleared session must not be reused: a fresh connect re-contacts
    // Firmware rather than short-circuiting to reused: true.
    const second = await core.connectDevice({});
    assert.equal(connectCalls, 2);
    assert.equal(second.reused, false);
  });
});

test("getAccounts without a runtime session returns not_connected", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
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
    const core = new GatewayCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.getCapabilities({});
    assert.equal(result.source, "not_connected");
    assert.equal(result.reason, "not_connected");
    assert.equal(result.capabilities, undefined);
  });
});

test("getCapabilities returns Firmware-authored methods and keeps the session", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.getCapabilities({});
    assert.equal(result.source, "live");
    assert.equal(result.capabilities.length, 1);
    assert.equal(result.capabilities[0].id, "sui");
    assert.equal(result.capabilities[0].accounts[0].keyScheme, "ed25519");
    assert.deepEqual(result.capabilities[0].methods, []);

    // Read-only: the session is retained after get_capabilities.
    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("getCapabilities clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(
      store,
      defaultDriver({
        async getCapabilities() {
          throw new GatewayError("invalid_session", "Session is unknown or already ended.", false);
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
    const core = new GatewayCore(store, defaultDriver());
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

    // Read-only: the session is retained after get_accounts.
    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("getAccounts clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(
      store,
      defaultDriver({
        async getAccounts() {
          throw new GatewayError("invalid_session", "Session is unknown or already ended.", false);
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

test("callMethod without a runtime session returns not_connected before validating method params", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });

    const result = await core.callMethod({
      chain: "sui",
      method: "sign_transaction",
      params: { seed: "state gate wins" },
    });
    assert.equal(result.source, "not_connected");
    assert.equal(result.reason, "not_connected");
    assert.equal(result.status, undefined);
  });
});

test("callMethod returns Firmware's rejected method_result and keeps the session", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(store, defaultDriver());
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.callMethod({ chain: "sui", method: "sign_transaction", params: {} });
    assert.equal(result.source, "live");
    assert.equal(result.status, "rejected");
    assert.equal(result.error.code, "unsupported_method");

    const listed = await core.listDevices();
    assert.notEqual(listed.devices[0].runtimeSession, null);
  });
});

test("callMethod validates input before USB live-port probing", async () => {
  await withStore(async (store) => {
    let listPortsCalls = 0;
    let requestStatusCalls = 0;
    let callMethodCalls = 0;
    const core = new GatewayCore(
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
        async callMethod() {
          callMethodCalls += 1;
          return {
            id: "req_call_method",
            version: 1,
            type: "method_result",
            status: "rejected",
            error: {
              code: "unsupported_method",
              message: "Method is not supported.",
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
    callMethodCalls = 0;

    await assert.rejects(
      () => core.callMethod({ chain: "sui", method: "sign_transaction", params: { seed: "must-not-forward" } }),
      { code: "invalid_params" },
    );
    assert.equal(listPortsCalls, 0);
    assert.equal(requestStatusCalls, 0);
    assert.equal(callMethodCalls, 0);
  });
});

test("callMethod clears the local session when Firmware reports invalid_session", async () => {
  await withStore(async (store) => {
    const core = new GatewayCore(
      store,
      defaultDriver({
        async callMethod() {
          throw new GatewayError("invalid_session", "Session is unknown or already ended.", false);
        },
      }),
    );
    await core.scanDevices();
    await core.selectDevice({ deviceId: device.deviceId });
    await core.connectDevice({});

    const result = await core.callMethod({ chain: "sui", method: "sign_transaction", params: {} });
    assert.equal(result.source, "session_ended");
    assert.equal(result.reason, "invalid_session");
    const listed = await core.listDevices();
    assert.equal(listed.devices[0].runtimeSession, null);
  });
});
