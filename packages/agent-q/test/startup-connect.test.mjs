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
      async getCapabilities(input) {
        calls.push(["getCapabilities", input]);
        return startupCapabilities(input.deviceId);
      },
      async getAccounts(input) {
        calls.push(["getAccounts", input]);
        return startupAccounts(input.deviceId);
      },
    },
    { purpose: "sui-cli" },
    (line) => diagnostics.push(line),
  );

  assert.deepEqual(calls, [
    ["scan"],
    ["select", { deviceId, purpose: "sui-cli" }],
    ["connect", { deviceId, purpose: "sui-cli", clientName: "Agent-Q" }],
    ["getCapabilities", { deviceId, purpose: "sui-cli" }],
    ["getAccounts", { deviceId, purpose: "sui-cli" }],
  ]);
  assert.match(diagnostics.join("\n"), /Confirm it on the device/);
  assert.match(diagnostics.join("\n"), /connection approved/);
  assert.match(diagnostics.join("\n"), /signing mode: user/);
  assert.match(diagnostics.join("\n"), /sui:sign_transaction/);
  assert.match(
    diagnostics.join("\n"),
    /Sui address: 0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133/,
  );
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

test("startup --request-connect reports sanitized connection summary failures", async () => {
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
      async getCapabilities(input) {
        calls.push(["getCapabilities", input]);
        throw new AgentQError("transport_closed", "raw port path must not leak", true);
      },
      async getAccounts(input) {
        calls.push(["getAccounts", input]);
        return startupAccounts(input.deviceId);
      },
    },
    {},
    (line) => diagnostics.push(line),
  );

  assert.deepEqual(calls.map((call) => call[0]), [
    "scan",
    "select",
    "connect",
    "getCapabilities",
    "getAccounts",
  ]);
  assert.match(diagnostics.join("\n"), /connection approved/);
  assert.match(diagnostics.join("\n"), /connection summary unavailable: transport_closed/);
  assert.doesNotMatch(diagnostics.join("\n"), /raw port path/);
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

function startupCapabilities(id) {
  return {
    source: "live",
    deviceId: id,
    capabilities: [
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
}

function startupAccounts(id) {
  return {
    source: "live",
    deviceId: id,
    accounts: [
      {
        chain: "sui",
        address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
        publicKey: "AAq+Xr89q49TF0t6vCBe2vNY7V2KnqIOxBGteq0dv2WV",
        keyScheme: "ed25519",
        derivationPath: "m/44'/784'/0'/0'/0'",
      },
    ],
  };
}
