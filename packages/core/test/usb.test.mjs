import assert from "node:assert/strict";
import test from "node:test";
import {
  deadlineEnforcingDriver,
  isLikelyAgentQUsbPort,
  mapErrorToUnavailableReason,
  resolveUsbCalloutPath,
  scanUsbDeviceStatuses,
  scanUsbDevices,
  tryParseMatchingResponseLine,
  validateInternalDeadlineMs,
} from "../dist/usb.js";
import {
  assertPolicyProposeResultResponse,
  assertStatusResponse,
  consumeProtocolResponseChunk,
  MAX_PROTOCOL_RESPONSE_LINE_BYTES,
} from "../dist/protocol.js";
import { AgentQError } from "../dist/errors.js";

const status = {
  id: "req_1",
  version: 1,
  type: "status",
  device: {
    deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
    state: "idle",
    firmwareName: "Agent-Q Firmware",
    hardware: "hardware-id",
    firmwareVersion: "0.0.0",
  },
  provisioning: {
    state: "unprovisioned",
  },
};

test("prefilters likely usb ports before handshake", async () => {
  const requestedPorts = [];
  const driver = {
    async listPorts() {
      return [
        {
          path: "/dev/cu.random",
          vendorId: "10c4",
          productId: "ea60",
          manufacturer: "Other",
        },
        {
          path: "/dev/cu.usbmodem1",
          vendorId: "303A",
          productId: "1001",
          manufacturer: "Espressif",
        },
      ];
    },
    async requestStatus(portPath) {
      requestedPorts.push(portPath);
      return status;
    },
  };

  const results = await scanUsbDevices(driver, 2000);
  assert.deepEqual(requestedPorts, ["/dev/cu.usbmodem1"]);
  assert.equal(results.length, 1);
});

test("resolves macOS tty usbmodem ports to callout cu ports when available", () => {
  assert.equal(
    resolveUsbCalloutPath("/dev/tty.usbmodem21301", "darwin", (path) => path === "/dev/cu.usbmodem21301"),
    "/dev/cu.usbmodem21301",
  );
  assert.equal(
    resolveUsbCalloutPath("/dev/tty.usbmodem21301", "darwin", () => false),
    "/dev/tty.usbmodem21301",
  );
  assert.equal(
    resolveUsbCalloutPath("/dev/tty.usbmodem21301", "linux", () => true),
    "/dev/tty.usbmodem21301",
  );
});

test("recognizes observed Espressif USB serial metadata", () => {
  assert.equal(
    isLikelyAgentQUsbPort({
      path: "/dev/cu.usbmodem1",
      vendorId: "0x303a",
      productId: "0x1001",
      manufacturer: "Espressif",
    }),
    true,
  );

  assert.equal(
    isLikelyAgentQUsbPort({
      path: "/dev/tty.usbmodem21301",
      manufacturer: "Espressif",
      serialNumber: "44:1B:F6:E4:05:24",
    }),
    true,
  );

  assert.equal(
    isLikelyAgentQUsbPort({
      path: "/dev/tty.usbmodem21301",
      manufacturer: "Espressif",
    }),
    false,
  );
});

test("validates internal USB deadline values", () => {
  assert.equal(validateInternalDeadlineMs(undefined), 30000);
  assert.throws(() => validateInternalDeadlineMs(0), /Internal USB deadline/);
  assert.throws(() => validateInternalDeadlineMs(30001), /Internal USB deadline/);
});

test("surfaces id-less Firmware error responses for the in-flight request", () => {
  assert.throws(
    () =>
      tryParseMatchingResponseLine(
        JSON.stringify({
          version: 1,
          type: "error",
          error: {
            code: "invalid_json",
            message: "Invalid JSON.",
          },
        }),
        "req_1",
        assertStatusResponse,
      ),
    {
      code: "invalid_json",
    },
  );
});

test("ignores terminal responses for a different in-flight request id", () => {
  const policyProposeError = JSON.stringify({
    id: "req_policy_propose",
    version: 1,
    type: "error",
    error: {
      code: "invalid_session",
      message: "Policy update session is unknown or already ended.",
    },
  });

  assert.equal(
    tryParseMatchingResponseLine(policyProposeError, "req_disconnect", assertStatusResponse),
    undefined,
  );
  assert.throws(
    () =>
      tryParseMatchingResponseLine(
        policyProposeError,
        "req_policy_propose",
        assertPolicyProposeResultResponse,
      ),
    {
      code: "invalid_session",
    },
  );
});

test("rejects oversized protocol response lines before parsing", () => {
  assert.throws(
    () => consumeProtocolResponseChunk("", `${"x".repeat(MAX_PROTOCOL_RESPONSE_LINE_BYTES + 1)}\n`),
    {
      code: "protocol_error",
    },
  );
});

test("scan applies a shrinking per-candidate timeout under one shared deadline", async () => {
  // Injected virtual clock: each handshake advances time by 100ms, so the test is
  // deterministic instead of depending on real scheduler timing.
  let now = 1000;
  const seenTimeouts = [];
  const driver = {
    async listPorts() {
      return ["1", "2", "3"].map((suffix) => ({
        path: `/dev/cu.usbmodem${suffix}`,
        vendorId: "303a",
        productId: "1001",
        manufacturer: "Espressif",
      }));
    },
    async requestStatus(_portPath, deadlineMs) {
      seenTimeouts.push(deadlineMs);
      now += 100;
      return status;
    },
  };

  await scanUsbDeviceStatuses(driver, 2000, () => now);
  // deadline = 1000 + 2000 = 3000; each handshake's timeout is the time remaining
  // until that shared deadline, so it shrinks rather than resetting to 2000.
  assert.deepEqual(seenTimeouts, [2000, 1900, 1800]);
});

test("scan surfaces a port-enumeration error instead of silently reporting no devices", async () => {
  const driver = {
    async listPorts() {
      throw new AgentQError("transport_closed", "enumeration failed", true);
    },
    async requestStatus() {
      return status;
    },
  };
  // The error propagates (it is not swallowed to an empty port list), so the
  // caller can distinguish "enumeration failed" from "no device present".
  await assert.rejects(
    () => scanUsbDeviceStatuses(driver, 2000),
    (error) => error instanceof AgentQError && error.code === "transport_closed",
  );
});

test("deadlineEnforcingDriver bounds a call whose driver ignores its deadline", async () => {
  // Single enforcement boundary: a hanging call is bounded by its deadline argument
  // even though this driver ignores it. AgentQCore wraps its driver with this, so
  // every deadline-bearing transport call is bounded in one place.
  const driver = {
    requestStatus() {
      return new Promise(() => {});
    },
  };
  const bounded = deadlineEnforcingDriver(driver);
  await assert.rejects(
    () => bounded.requestStatus("/dev/cu.usbmodem1", 50),
    (error) => error instanceof AgentQError && error.code === "timeout",
  );
});

test("scanUsbDeviceStatuses self-enforces the scan budget on a raw driver", async () => {
  // No AgentQCore wrapper here: the scan function owns its budget and must bound
  // a hanging handshake itself, so a direct/raw export caller is also safe.
  const driver = {
    async listPorts() {
      return [{ path: "/dev/cu.usbmodem1", vendorId: "303a", productId: "1001", manufacturer: "Espressif" }];
    },
    requestStatus() {
      return new Promise(() => {});
    },
  };

  const result = await scanUsbDeviceStatuses(driver, 50);
  assert.equal(result.devices.length, 0);
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0].unavailableReason, "timeout");
});

test("maps serial permission failures separately from missing devices", () => {
  const eperm = Object.assign(new Error("Operation not permitted"), { code: "EPERM" });
  assert.equal(mapErrorToUnavailableReason(eperm), "port_permission_denied");

  const eacces = Object.assign(new Error("Cannot open /dev/cu.usbmodem1: permission denied"), { code: "EACCES" });
  assert.equal(mapErrorToUnavailableReason(eacces), "port_permission_denied");

  assert.equal(mapErrorToUnavailableReason(new Error("No such file or directory")), "port_not_found");
});

test("scan records serial permission failures as candidate access failures", async () => {
  const driver = {
    async listPorts() {
      return [{ path: "/dev/cu.usbmodem1", vendorId: "303a", productId: "1001", manufacturer: "Espressif" }];
    },
    async requestStatus() {
      throw Object.assign(new Error("Operation not permitted"), { code: "EPERM" });
    },
  };

  const result = await scanUsbDeviceStatuses(driver, 2000);
  assert.equal(result.devices.length, 0);
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0].portPath, "/dev/cu.usbmodem1");
  assert.equal(result.failures[0].unavailableReason, "port_permission_denied");
});
