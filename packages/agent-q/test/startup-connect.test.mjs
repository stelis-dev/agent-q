import assert from "node:assert/strict";
import test from "node:test";
import { AgentQError } from "@stelis/agent-q-core/adapter-internal";
import { requestDeviceConnectionOnStart } from "../dist/startup-connect.js";

const deviceId = "a508d833-5c83-4680-88bb-18aee976881e";

test("startup --request-connect selects the only live device and sends a Firmware connection request", async () => {
  const calls = [];
  const diagnostics = [];
  await requestDeviceConnectionOnStart(
    {
      async scanDevices() {
        calls.push(["scan"]);
        return startupScanResult([startupLiveDevice(deviceId)]);
      },
      async selectDevice(input) {
        calls.push(["select", input]);
        return {
          source: "selected",
          activeDeviceId: input.deviceId,
          purpose: input.purpose ?? null,
          device: startupDevice(input.deviceId),
        };
      },
      async connectDevice(input) {
        calls.push(["connect", input]);
        return {
          source: "connected",
          deviceId,
          sessionTtlMs: 4294967295,
          connectedAt: "2026-05-28T00:00:00.000Z",
          device: startupDevice(input.deviceId),
        };
      },
    },
    { purpose: "sui-cli" },
    (line) => diagnostics.push(line),
  );

  assert.deepEqual(calls, [
    ["scan"],
    ["select", { deviceId, purpose: "sui-cli" }],
    ["connect", { deviceId, purpose: "sui-cli", clientName: "Agent-Q" }],
  ]);
  assert.match(diagnostics.join("\n"), /Confirm it on the device/);
  assert.match(diagnostics.join("\n"), /connection approved/);
});

test("startup --request-connect does not choose between multiple devices without deviceId", async () => {
  const calls = [];
  const diagnostics = [];
  await requestDeviceConnectionOnStart(
    {
      async scanDevices() {
        calls.push(["scan"]);
        return startupScanResult([
          startupLiveDevice(deviceId),
          startupLiveDevice("b508d833-5c83-4680-88bb-18aee976881e"),
        ]);
      },
      async selectDevice(input) {
        calls.push(["select", input]);
        throw new Error("must not select");
      },
      async connectDevice(input) {
        calls.push(["connect", input]);
        throw new Error("must not connect");
      },
    },
    {},
    (line) => diagnostics.push(line),
  );

  assert.deepEqual(calls, [["scan"]]);
  assert.match(diagnostics.join("\n"), /invalid_params/);
});

test("startup --request-connect reports port occupancy from scan failures", async () => {
  const calls = [];
  const diagnostics = [];
  await requestDeviceConnectionOnStart(
    {
      async scanDevices() {
        calls.push(["scan"]);
        return {
          source: "live",
          devices: [],
          failures: [
            {
              source: "error",
              connected: false,
              portPath: "/dev/cu.usbmodem21301",
              unavailableReason: "port_in_use",
            },
          ],
          activeDeviceId: null,
        };
      },
      async selectDevice(input) {
        calls.push(["select", input]);
        throw new Error("must not select");
      },
      async connectDevice(input) {
        calls.push(["connect", input]);
        throw new Error("must not connect");
      },
    },
    {},
    (line) => diagnostics.push(line),
  );

  assert.deepEqual(calls, [["scan"]]);
  assert.match(diagnostics.join("\n"), /port_in_use/);
  assert.doesNotMatch(diagnostics.join("\n"), /port_not_found/);
});

test("startup --request-connect keeps the server path alive when connect is rejected", async () => {
  const calls = [];
  const diagnostics = [];
  await requestDeviceConnectionOnStart(
    {
      async scanDevices() {
        calls.push(["scan"]);
        return startupScanResult([startupLiveDevice(deviceId)]);
      },
      async selectDevice(input) {
        calls.push(["select", input]);
        return {
          source: "selected",
          activeDeviceId: input.deviceId,
          purpose: input.purpose ?? null,
          device: startupDevice(input.deviceId),
        };
      },
      async connectDevice(input) {
        calls.push(["connect", input]);
        throw new AgentQError("rejected", "raw rejection text must not leak", false);
      },
    },
    {},
    (line) => diagnostics.push(line),
  );

  assert.deepEqual(calls.map((call) => call[0]), ["scan", "select", "connect"]);
  assert.match(diagnostics.join("\n"), /rejected/);
  assert.doesNotMatch(diagnostics.join("\n"), /raw rejection text/);
});

function startupScanResult(devices, activeDeviceId = null) {
  return {
    source: "live",
    devices,
    failures: [],
    activeDeviceId,
  };
}

function startupLiveDevice(id) {
  return {
    source: "live",
    connected: true,
    portPath: `/dev/cu.${id}`,
    protocolResponse: {
      protocolVersion: 1,
      device: startupDevice(id),
      provisioning: { state: "provisioned" },
    },
  };
}

function startupDevice(id) {
  return {
    deviceId: id,
    state: "idle",
    firmwareName: "Agent-Q Firmware",
    hardware: "stackchan-cores3",
    firmwareVersion: "0.0.0",
  };
}
