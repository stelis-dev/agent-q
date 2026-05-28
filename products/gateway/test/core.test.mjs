import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
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

test("returns no_active_device when no active device exists", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-core-test-"));
  try {
    const core = new GatewayCore(new ConfigStore(join(dir, "config.json")), {
      async listPorts() {
        return [];
      },
      async requestStatus() {
        return status;
      },
      async identifyDevice(_portPath, code) {
        return identifyResponse(code);
      },
    });

    await assert.rejects(() => core.getDeviceStatus(), {
      code: "no_active_device",
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("returns cached status for known device when live request times out", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-core-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(device, "/dev/cu.usbmodem1", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });

    const core = new GatewayCore(store, {
      async listPorts() {
        return [];
      },
      async requestStatus() {
        throw new GatewayError("timeout", "Timed out.", true);
      },
      async identifyDevice(_portPath, code) {
        return identifyResponse(code);
      },
    });

    const result = await core.getDeviceStatus();
    assert.equal(result.source, "cached");
    assert.equal(result.connected, false);
    assert.equal(result.unavailableReason, "timeout");
    assert.equal(result.statusObservedAt, "2026-05-28T00:00:00.000Z");
    assert.equal(result.cachedStatus.device.deviceId, device.deviceId);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("falls back to scan when stored port hint is stale", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-core-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(device, "/dev/cu.stale", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });

    const core = new GatewayCore(store, {
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
        if (portPath === "/dev/cu.stale") {
          throw new GatewayError("port_not_found", "Stale port.", true);
        }
        return status;
      },
      async identifyDevice(_portPath, code) {
        return identifyResponse(code);
      },
    });

    const result = await core.getDeviceStatus();
    assert.equal(result.source, "live");
    assert.equal(result.portPath, "/dev/cu.usbmodem2");
    assert.equal((await store.load()).devices[0].lastPortHint, "/dev/cu.usbmodem2");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan stores live device without selecting it", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-core-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    const core = new GatewayCore(store, {
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
    });

    const result = await core.scanDevices();
    assert.equal(result.devices.length, 1);
    assert.equal(result.activeDeviceId, null);
    assert.equal((await store.load()).devices[0].deviceId, device.deviceId);
    assert.equal((await store.load()).activeDeviceId, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan does not select an active device when multiple devices are found", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-core-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    const core = new GatewayCore(store, {
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
      async identifyDevice(_portPath, code) {
        return identifyResponse(code);
      },
    });

    const result = await core.scanDevices();
    assert.equal(result.devices.length, 2);
    assert.equal(result.activeDeviceId, null);
    assert.equal((await store.load()).activeDeviceId, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("identifies devices without selecting one", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-core-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    const identifiedCodes = [];
    const core = new GatewayCore(store, {
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
    });

    const result = await core.identifyDevices({ durationMs: 10000 });
    assert.equal(result.devices.length, 2);
    assert.equal(new Set(identifiedCodes).size, 2);
    assert.equal(result.activeDeviceId, null);
    assert.equal((await store.load()).activeDeviceId, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("selects a previously discovered device", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-core-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(device, "/dev/cu.usbmodem1");

    const core = new GatewayCore(store, {
      async listPorts() {
        return [];
      },
      async requestStatus() {
        return status;
      },
      async identifyDevice(_portPath, code) {
        return identifyResponse(code);
      },
    });

    const result = await core.selectDevice({ deviceId: device.deviceId });
    assert.equal(result.source, "selected");
    assert.equal(result.activeDeviceId, device.deviceId);
    assert.equal((await store.load()).activeDeviceId, device.deviceId);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
