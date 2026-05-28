import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  CONFIG_SCHEMA_VERSION,
  ConfigError,
  ConfigStore,
  defaultGatewayConfig,
  getConfigPath,
  isValidLabel,
  isValidPurpose,
} from "../dist/config.js";

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

test("loads defaults at v2 and remembers usb status", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    assert.deepEqual(await store.load(), {
      schemaVersion: CONFIG_SCHEMA_VERSION,
      activeDeviceId: null,
      activeDeviceIdsByPurpose: {},
      devices: [],
    });

    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1", {
      observedAt: new Date("2026-05-28T00:00:00.000Z"),
      setActive: true,
    });
    const config = await store.load();
    assert.equal(config.schemaVersion, CONFIG_SCHEMA_VERSION);
    assert.equal(config.activeDeviceId, sampleDevice.deviceId);
    assert.equal(config.devices.length, 1);
    assert.equal(config.devices[0].lastPortHint, "/dev/cu.usbmodem1");
    assert.equal(config.devices[0].label, null);
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
    assert.equal(selected.deviceId, sampleDevice.deviceId);
    assert.equal((await store.load()).activeDeviceId, sampleDevice.deviceId);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("migrates v1 config to v2 preserving devices and active device", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const path = join(dir, "config.json");
    const v1Config = {
      schemaVersion: 1,
      activeDeviceId: sampleDevice.deviceId,
      devices: [
        {
          deviceId: sampleDevice.deviceId,
          transport: "usb",
          lastPortHint: "/dev/cu.usbmodem1",
          lastSeenAt: "2026-05-28T00:00:00.000Z",
          lastStatus: { device: sampleDevice },
        },
      ],
    };
    await writeFile(path, JSON.stringify(v1Config), "utf8");

    const store = new ConfigStore(path);
    const config = await store.load();
    assert.equal(config.schemaVersion, CONFIG_SCHEMA_VERSION);
    assert.equal(config.activeDeviceId, sampleDevice.deviceId);
    assert.deepEqual(config.activeDeviceIdsByPurpose, {});
    assert.equal(config.devices.length, 1);
    assert.equal(config.devices[0].label, null);
    assert.equal(config.devices[0].lastPortHint, "/dev/cu.usbmodem1");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("falls back to default v2 for malformed config json", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const path = join(dir, "config.json");
    await writeFile(path, "{ not valid json", "utf8");

    const store = new ConfigStore(path);
    const config = await store.load();
    assert.deepEqual(config, defaultGatewayConfig());
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("falls back to default v2 for unknown schema version", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const path = join(dir, "config.json");
    await writeFile(path, JSON.stringify({ schemaVersion: 99 }), "utf8");

    const store = new ConfigStore(path);
    const config = await store.load();
    assert.deepEqual(config, defaultGatewayConfig());
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("setDeviceMetadata sets and clears label", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1");

    const labeled = await store.setDeviceMetadata({
      deviceId: sampleDevice.deviceId,
      label: "Desk device",
    });
    assert.equal(labeled.label, "Desk device");
    assert.equal((await store.load()).devices[0].label, "Desk device");

    const cleared = await store.setDeviceMetadata({
      deviceId: sampleDevice.deviceId,
      label: null,
    });
    assert.equal(cleared.label, null);
    assert.equal((await store.load()).devices[0].label, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("setDeviceMetadata rejects unknown device and oversized label", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1");

    await assert.rejects(
      () =>
        store.setDeviceMetadata({
          deviceId: "00000000-0000-0000-0000-000000000000",
          label: "label",
        }),
      (error) => error instanceof ConfigError && error.code === "device_not_found",
    );

    await assert.rejects(
      () =>
        store.setDeviceMetadata({
          deviceId: sampleDevice.deviceId,
          label: "x".repeat(65),
        }),
      (error) => error instanceof ConfigError && error.code === "invalid_label",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("label survives a subsequent rememberUsbStatus call", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1");
    await store.setDeviceMetadata({ deviceId: sampleDevice.deviceId, label: "Desk device" });
    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem2", {
      observedAt: new Date("2026-05-29T00:00:00.000Z"),
    });

    const config = await store.load();
    assert.equal(config.devices[0].label, "Desk device");
    assert.equal(config.devices[0].lastPortHint, "/dev/cu.usbmodem2");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("setActiveDevice routes by purpose and rejects reserved or invalid purpose", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1");

    await store.setActiveDevice(sampleDevice.deviceId, "payment");
    let config = await store.load();
    assert.deepEqual(config.activeDeviceIdsByPurpose, { payment: sampleDevice.deviceId });
    assert.equal(config.activeDeviceId, null);

    await store.setActiveDevice(sampleDevice.deviceId);
    config = await store.load();
    assert.equal(config.activeDeviceId, sampleDevice.deviceId);
    assert.deepEqual(config.activeDeviceIdsByPurpose, { payment: sampleDevice.deviceId });

    await assert.rejects(
      () => store.setActiveDevice(sampleDevice.deviceId, "default"),
      (error) => error instanceof ConfigError && error.code === "reserved_purpose",
    );
    await assert.rejects(
      () => store.setActiveDevice(sampleDevice.deviceId, "has space"),
      (error) => error instanceof ConfigError && error.code === "invalid_purpose",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("getActiveDevice returns default or purpose-specific record", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1");
    await store.setActiveDevice(sampleDevice.deviceId);
    await store.setActiveDevice(sampleDevice.deviceId, "payment");

    const byDefault = await store.getActiveDevice();
    assert.equal(byDefault?.deviceId, sampleDevice.deviceId);
    const byPurpose = await store.getActiveDevice("payment");
    assert.equal(byPurpose?.deviceId, sampleDevice.deviceId);
    const missingPurpose = await store.getActiveDevice("missing");
    assert.equal(missingPurpose, undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("listDevices reports assigned purposes and default-active flag", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1");
    await store.setActiveDevice(sampleDevice.deviceId);
    await store.setActiveDevice(sampleDevice.deviceId, "payment");

    const listing = await store.listDevices();
    assert.equal(listing.length, 1);
    assert.deepEqual(listing[0].assignedPurposes, ["payment"]);
    assert.equal(listing[0].isDefaultActive, true);
    assert.equal(listing[0].label, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("rememberUsbStatus does not write sessionId to config", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const path = join(dir, "config.json");
    const store = new ConfigStore(path);
    await store.rememberUsbStatus(sampleDevice, "/dev/cu.usbmodem1");
    const raw = await readFile(path, "utf8");
    assert.equal(raw.includes("session"), false, "config must not persist session state");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("prunes dangling active device and purpose references on load", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const path = join(dir, "config.json");
    const danglingConfig = {
      schemaVersion: CONFIG_SCHEMA_VERSION,
      activeDeviceId: "ghost-default",
      activeDeviceIdsByPurpose: {
        payment: sampleDevice.deviceId,
        trading: "ghost-purpose",
      },
      devices: [
        {
          deviceId: sampleDevice.deviceId,
          transport: "usb",
          lastPortHint: "/dev/cu.usbmodem1",
          lastSeenAt: "2026-05-28T00:00:00.000Z",
          label: null,
          lastStatus: { device: sampleDevice },
        },
      ],
    };
    await writeFile(path, JSON.stringify(danglingConfig), "utf8");

    const config = await new ConfigStore(path).load();
    assert.equal(config.activeDeviceId, null, "dangling activeDeviceId is nulled");
    assert.deepEqual(
      config.activeDeviceIdsByPurpose,
      { payment: sampleDevice.deviceId },
      "purpose mapping to a missing device is pruned, valid one kept",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("isValidLabel and isValidPurpose accept and reject expected inputs", () => {
  assert.equal(isValidLabel(null), true);
  assert.equal(isValidLabel("a"), true);
  assert.equal(isValidLabel("a".repeat(64)), true);
  assert.equal(isValidLabel("a".repeat(65)), false);
  assert.equal(isValidLabel(""), false);

  assert.equal(isValidPurpose("payment"), true);
  assert.equal(isValidPurpose("p1.0_a-b"), true);
  assert.equal(isValidPurpose("default"), false);
  assert.equal(isValidPurpose("with space"), false);
  assert.equal(isValidPurpose("x".repeat(33)), false);
});
