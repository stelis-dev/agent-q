import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ConfigStore, getConfigPath } from "../dist/config.js";

const sampleDevice = {
  deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
  state: "idle",
  firmwareName: "Agent-Q Firmware",
  hardware: "hardware-id",
  firmwareVersion: "0.0.0",
};

test("uses XDG config path with home fallback", () => {
  assert.equal(
    getConfigPath({ env: { XDG_CONFIG_HOME: "/tmp/xdg" }, homeDir: "/home/test" }),
    "/tmp/xdg/agent-q-gateway/config.json",
  );
  assert.equal(
    getConfigPath({ env: {}, homeDir: "/home/test" }),
    "/home/test/.config/agent-q-gateway/config.json",
  );
});

test("loads defaults and remembers usb status", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    assert.deepEqual(await store.load(), {
      schemaVersion: 1,
      activeDeviceId: null,
      devices: [],
    });

    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });
    const config = await store.load();
    assert.equal(config.activeDeviceId, sampleDevice.deviceId);
    assert.equal(config.devices.length, 1);
    assert.equal(config.devices[0].lastPortHint, "/dev/cu.usbmodem1");
    assert.equal(config.devices[0].lastStatus.device.deviceId, sampleDevice.deviceId);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("remembers usb status without changing active device unless requested", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1");

    const config = await store.load();
    assert.equal(config.activeDeviceId, null);
    assert.equal(config.devices.length, 1);

    const selected = await store.setActiveDevice(sampleDevice.deviceId);
    assert.equal(selected?.deviceId, sampleDevice.deviceId);
    assert.equal((await store.load()).activeDeviceId, sampleDevice.deviceId);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
