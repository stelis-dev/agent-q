import assert from "node:assert/strict";
import test from "node:test";
import {
  isLikelyAgentQUsbPort,
  scanUsbDevices,
  validateTimeoutMs,
} from "../dist/usb.js";

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
});

test("rejects invalid timeout values", () => {
  assert.equal(validateTimeoutMs(undefined), 2000);
  assert.throws(() => validateTimeoutMs(0), /timeoutMs/);
  assert.throws(() => validateTimeoutMs(10001), /timeoutMs/);
});
