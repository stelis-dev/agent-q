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
  assert.equal(isValidLabel("Desk device"), true, "spaces are allowed in a display label");
  assert.equal(isValidLabel("a".repeat(64)), true);
  assert.equal(isValidLabel("a".repeat(65)), false);
  assert.equal(isValidLabel(""), false);
  assert.equal(isValidLabel("line\nbreak"), false, "newlines are rejected");
  assert.equal(isValidLabel("tab\tchar"), false, "tabs are rejected");
  assert.equal(isValidLabel("bell\u0007"), false, "control chars are rejected");

  assert.equal(isValidPurpose("payment"), true);
  assert.equal(isValidPurpose("p1.0_a-b"), true);
  assert.equal(isValidPurpose("default"), false);
  assert.equal(isValidPurpose("with space"), false);
  assert.equal(isValidPurpose("x".repeat(33)), false);
});

// --- Disk-ingress (stored registry) normalization via the safe-text SoT ---
// A config file is untrusted input: it can be hand-edited. The load path is a
// trust boundary that must sanitize stored display strings, drop records whose
// identity is unsafe, and reset malformed metadata, so the stored registry can
// never carry unsafe text into MCP output. Control bytes are built from char
// codes (and verified by a code-point scan) to keep this source file text.
const CTRL_NL = String.fromCharCode(10);
const CTRL_BEL = String.fromCharCode(7);
const CTRL_DEL = String.fromCharCode(127);

function hasControlOrHighByte(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) {
      return true;
    }
  }
  return false;
}

function storedRecord(overrides = {}) {
  return {
    deviceId: sampleDevice.deviceId,
    transport: "usb",
    lastPortHint: "/dev/cu.usbmodem1",
    lastSeenAt: "2026-05-28T00:00:00.000Z",
    label: null,
    lastStatus: { device: { ...sampleDevice } },
    ...overrides,
  };
}

function storedConfig(devices, extra = {}) {
  return {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    activeDeviceId: null,
    activeDeviceIdsByPurpose: {},
    devices,
    ...extra,
  };
}

async function loadStored(config) {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  const path = join(dir, "config.json");
  await writeFile(path, JSON.stringify(config), "utf8");
  try {
    return await new ConfigStore(path).load();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// Capture the one-shot "normalized stored config" warnings emitted while `run`
// executes, so a test can assert both the normalized result and the counts the
// operator is told about. Only the normalization lines are returned.
async function captureNormalizeWarnings(run) {
  const realWarn = console.warn;
  const captured = [];
  console.warn = (...parts) => {
    captured.push(parts.map(String).join(" "));
  };
  try {
    const result = await run();
    return {
      result,
      warnings: captured.filter((line) => line.includes("normalized stored config")),
    };
  } finally {
    console.warn = realWarn;
  }
}

test("load sanitizes untrusted stored device display strings", async () => {
  const config = await loadStored(
    storedConfig([
      storedRecord({
        lastStatus: {
          device: {
            ...sampleDevice,
            firmwareName: "EVIL" + CTRL_NL + "IGNORE " + "x".repeat(200),
            hardware: "hw" + CTRL_BEL + "id",
            firmwareVersion: "v" + CTRL_DEL + "1.0",
          },
        },
      }),
    ]),
  );
  assert.equal(config.devices.length, 1);
  const device = config.devices[0].lastStatus.device;
  assert.equal(device.firmwareName.length <= 64, true);
  assert.equal(hasControlOrHighByte(device.firmwareName), false);
  assert.equal(device.hardware, "hwid");
  assert.equal(device.firmwareVersion, "v1.0");
});

test("load drops a stored record whose deviceId is unsafe and keeps valid ones", async () => {
  const unsafeId = "INJECT" + CTRL_NL + "ID";
  const config = await loadStored(
    storedConfig([
      storedRecord({ deviceId: unsafeId, lastStatus: { device: { ...sampleDevice, deviceId: unsafeId } } }),
      storedRecord(),
    ]),
  );
  assert.equal(config.devices.length, 1, "the unsafe-id record is dropped");
  assert.equal(config.devices[0].deviceId, sampleDevice.deviceId);
});

test("load drops a stored record whose cached device identity is unsafe", async () => {
  const config = await loadStored(
    storedConfig([
      storedRecord({ lastStatus: { device: { ...sampleDevice, state: "not_a_state" } } }),
      storedRecord({ deviceId: "b508d833-5c83-4680-88bb-18aee976881e", lastStatus: { device: { ...sampleDevice, deviceId: "b508d833-5c83-4680-88bb-18aee976881e" } } }),
    ]),
  );
  assert.equal(config.devices.length, 1, "record with an invalid cached state is dropped");
  assert.equal(config.devices[0].deviceId, "b508d833-5c83-4680-88bb-18aee976881e");
});

test("load drops a non-usb transport record but keeps the rest of the registry", async () => {
  const config = await loadStored(
    storedConfig([
      storedRecord({ transport: "bluetooth" }),
      storedRecord({ deviceId: "b508d833-5c83-4680-88bb-18aee976881e", lastStatus: { device: { ...sampleDevice, deviceId: "b508d833-5c83-4680-88bb-18aee976881e" } } }),
    ]),
  );
  assert.equal(config.devices.length, 1);
  assert.equal(config.devices[0].deviceId, "b508d833-5c83-4680-88bb-18aee976881e");
});

test("load resets an invalid stored label to null but preserves a valid one", async () => {
  const invalid = await loadStored(storedConfig([storedRecord({ label: "bad" + CTRL_NL + "label" })]));
  assert.equal(invalid.devices[0].label, null);

  const valid = await loadStored(storedConfig([storedRecord({ label: "Desk device" })]));
  assert.equal(valid.devices[0].label, "Desk device");
});

test("load coerces a malformed stored lastSeenAt to a valid ISO instant", async () => {
  const config = await loadStored(storedConfig([storedRecord({ lastSeenAt: "whenever" + CTRL_NL })]));
  assert.equal(config.devices.length, 1);
  assert.equal(Number.isFinite(Date.parse(config.devices[0].lastSeenAt)), true);
  assert.equal(hasControlOrHighByte(config.devices[0].lastSeenAt), false);
});

test("load sanitizes a stored lastPortHint with control characters", async () => {
  const config = await loadStored(storedConfig([storedRecord({ lastPortHint: "/dev/cu." + CTRL_BEL + "x" })]));
  assert.equal(config.devices[0].lastPortHint, "/dev/cu.x");
});

test("load drops malformed activeDeviceIdsByPurpose entries", async () => {
  const config = await loadStored(
    storedConfig([storedRecord()], {
      activeDeviceId: sampleDevice.deviceId,
      activeDeviceIdsByPurpose: {
        payment: sampleDevice.deviceId,
        "bad purpose": sampleDevice.deviceId,
        trading: "unsafe" + CTRL_NL + "id",
      },
    }),
  );
  assert.deepEqual(
    config.activeDeviceIdsByPurpose,
    { payment: sampleDevice.deviceId },
    "invalid purpose name and unsafe device id are dropped",
  );
  assert.equal(config.activeDeviceId, sampleDevice.deviceId);
});

test("load drops a stored record whose record id and cached device id disagree", async () => {
  const config = await loadStored(
    storedConfig([
      storedRecord({
        lastStatus: { device: { ...sampleDevice, deviceId: "b508d833-5c83-4680-88bb-18aee976881e" } },
      }),
      storedRecord({
        deviceId: "c508d833-5c83-4680-88bb-18aee976881e",
        lastStatus: { device: { ...sampleDevice, deviceId: "c508d833-5c83-4680-88bb-18aee976881e" } },
      }),
    ]),
  );
  assert.equal(config.devices.length, 1, "split-identity record dropped, matching one kept");
  assert.equal(config.devices[0].deviceId, "c508d833-5c83-4680-88bb-18aee976881e");
});

test("load de-duplicates stored records that share a deviceId", async () => {
  const config = await loadStored(
    storedConfig([storedRecord({ label: "first" }), storedRecord({ label: "second" })]),
  );
  assert.equal(config.devices.length, 1, "duplicate deviceId collapsed to the first record");
  assert.equal(config.devices[0].label, "first");
});

test("rememberUsbStatus refuses to store a device with an unsafe identity", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const store = new ConfigStore(join(dir, "config.json"));
    await assert.rejects(
      () => store.rememberUsbStatus({ ...sampleDevice, deviceId: "bad" + CTRL_NL + "id" }, "/dev/cu.usbmodem1"),
      (error) => error instanceof ConfigError && error.code === "invalid_device",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("normalization warning is deduped for the same unchanged config", async () => {
  const realWarn = console.warn;
  const captured = [];
  console.warn = (...parts) => {
    captured.push(parts.map(String).join(" "));
  };
  const dir = await mkdtemp(join(tmpdir(), "agent-q-gateway-test-"));
  try {
    const path = join(dir, "config.json");
    await writeFile(path, JSON.stringify(storedConfig([storedRecord({ label: "bad" + CTRL_NL + "label" })])), "utf8");
    const store = new ConfigStore(path);
    await store.load();
    await store.load();
    await store.load();
    const normalizeWarns = captured.filter((line) => line.includes("normalized stored config"));
    assert.equal(normalizeWarns.length, 1, "same corrupt config warns once per ConfigStore instance");
  } finally {
    console.warn = realWarn;
    await rm(dir, { recursive: true, force: true });
  }
});

// A well-formed but absent deviceId: passes the safe-id charset check (so
// assembleConfig keeps it), then is pruned by reference normalization.
const danglingId = "ghost-device-0001";

test("load warns and nulls a malformed activeDeviceId via assembleConfig", async () => {
  // A space is outside the safe-id charset, so assembleConfig (not reference
  // pruning) clears it and is the one that counts clearedActiveDeviceId.
  const { result, warnings } = await captureNormalizeWarnings(() =>
    loadStored(storedConfig([storedRecord()], { activeDeviceId: "ghost default" })),
  );
  assert.equal(result.activeDeviceId, null);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /clearedActiveDeviceId=1[,)]/);
});

test("load warns and nulls a well-formed but dangling activeDeviceId via reference pruning", async () => {
  const { result, warnings } = await captureNormalizeWarnings(() =>
    loadStored(storedConfig([storedRecord()], { activeDeviceId: danglingId })),
  );
  assert.equal(result.activeDeviceId, null);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /clearedActiveDeviceId=1[,)]/);
});

test("load warns and prunes a well-formed but dangling purpose route", async () => {
  const { result, warnings } = await captureNormalizeWarnings(() =>
    loadStored(
      storedConfig([storedRecord()], {
        activeDeviceIdsByPurpose: { payment: sampleDevice.deviceId, trading: danglingId },
      }),
    ),
  );
  assert.deepEqual(result.activeDeviceIdsByPurpose, { payment: sampleDevice.deviceId });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /droppedRoutes=1,/);
});

test("load reports sanitized device display text in the normalization warning", async () => {
  // A stored firmwareName carrying a control byte is silently stripped to safe
  // text; the warning must report that as a normalization, not stay silent.
  const { result, warnings } = await captureNormalizeWarnings(() =>
    loadStored(
      storedConfig([
        storedRecord({
          lastStatus: {
            device: { ...sampleDevice, firmwareName: "Agent-Q" + CTRL_BEL + "Firmware" },
          },
        }),
      ]),
    ),
  );
  // The stored value was sanitized to safe text...
  assert.equal(hasControlOrHighByte(result.devices[0].lastStatus.device.firmwareName), false);
  assert.notEqual(result.devices[0].lastStatus.device.firmwareName, "Agent-Q" + CTRL_BEL + "Firmware");
  // ...and that sanitization is reported (exactly one display field changed).
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /sanitizedDeviceDisplayText=1[,)]/);
});

test("load reports a sanitized port hint in the normalization warning", async () => {
  const { result, warnings } = await captureNormalizeWarnings(() =>
    loadStored(storedConfig([storedRecord({ lastPortHint: "/dev/cu.usbmodem1" + CTRL_DEL })])),
  );
  assert.equal(hasControlOrHighByte(result.devices[0].lastPortHint), false);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /sanitizedPortHints=1[,)]/);
});

test("load does not warn for an already-clean stored config", async () => {
  // The contrapositive of the report contract: when nothing is transformed, the
  // report is empty and no normalization warning is emitted. This guards against
  // a future change that silently rewrites a clean value without recording it.
  const { warnings } = await captureNormalizeWarnings(() =>
    loadStored(
      storedConfig([storedRecord()], {
        activeDeviceId: sampleDevice.deviceId,
        activeDeviceIdsByPurpose: { payment: sampleDevice.deviceId },
      }),
    ),
  );
  assert.equal(warnings.length, 0);
});

test("a normalized config is a fixpoint: re-loading its output triggers no further normalization", async () => {
  // Structural backing for "empty report iff no change": normalizing the output of
  // a previous normalization must change nothing and report nothing. A transform
  // that mutates without recording (or that is not idempotent) would warn on the
  // second pass and fail here, even if its own per-field test were forgotten.
  const messy = storedConfig([storedRecord({ lastPortHint: "/dev/cu.x" + CTRL_DEL, label: "ok" })], {
    activeDeviceId: danglingId,
    activeDeviceIdsByPurpose: { trading: danglingId },
  });
  const first = await captureNormalizeWarnings(() => loadStored(messy));
  assert.equal(first.warnings.length, 1, "the messy config is normalized and warns once");

  // The loaded result is itself a valid stored config shape; feed it back in.
  const second = await captureNormalizeWarnings(() => loadStored(first.result));
  assert.equal(second.warnings.length, 0, "a normalized config needs no further normalization");
  assert.deepEqual(second.result, first.result, "re-loading a normalized config returns it unchanged");
});
