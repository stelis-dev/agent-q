import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, createHash, createHmac } from "node:crypto";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import test from "node:test";
import { x25519 } from "@noble/curves/ed25519.js";
import { DeviceRequestError } from "../dist/errors.js";
import { ProtocolError } from "../dist/protocol-error.js";
import {
  LocalTransportBleGateway,
  parseLocalTransportOpticalPayload,
} from "../dist/local-transport.js";
import {
  LocalTransportNoiseXxInitiator,
  runLocalTransportOperation,
} from "../dist/local-transport-protocol.js";

const SERVICE_UUID = "a6e31d1051a14f7a9b0a0a1c00000001";
const CONTROL_UUID = "a6e31d1051a14f7a9b0a0a1c00000002";
const DATA_UUID = "a6e31d1051a14f7a9b0a0a1c00000003";
const DEVICE_STATIC_SECRET = Buffer.from("11".repeat(32), "hex");
const DEVICE_EPHEMERAL_SECRET = Buffer.from("22".repeat(32), "hex");
const DEVICE_STATIC_PUBLIC = Buffer.from(x25519.getPublicKey(DEVICE_STATIC_SECRET));
const IDFP = sha256(DEVICE_STATIC_PUBLIC).subarray(0, 8);
const OPTICAL_PAYLOAD = `aqlt:1?k=ble&svc=${SERVICE_UUID}&idfp=${IDFP.toString("hex")}&non=0011223344556677&exp=120`;
const HW_GET_STATUS_ENABLED = process.env.LOCAL_TRANSPORT_HW_GET_STATUS === "1";
const HW_OPTICAL_PAYLOAD = process.env.LOCAL_TRANSPORT_HW_OPTICAL_PAYLOAD ?? "";
const require = createRequire(import.meta.url);

function makeGatewayRandomBytes() {
  let nextByte = 0x44;
  return (length) => {
    assert.equal(length, 32);
    const secret = Buffer.alloc(length, nextByte);
    nextByte += 1;
    return secret;
  };
}

test("parses bounded BLE optical payloads", () => {
  const parsed = parseLocalTransportOpticalPayload(OPTICAL_PAYLOAD);
  assert.equal(parsed.kind, "ble");
  assert.equal(parsed.serviceUuid, SERVICE_UUID);
  assert.equal(parsed.controlCharacteristicUuid, CONTROL_UUID);
  assert.equal(parsed.dataCharacteristicUuid, DATA_UUID);
  assert.equal(Buffer.from(parsed.identityFingerprint).toString("hex"), IDFP.toString("hex"));
  assert.equal(parsed.expiresInSeconds, 120);
});

test("rejects unsupported local transport kinds", () => {
  assert.throws(
    () => parseLocalTransportOpticalPayload(OPTICAL_PAYLOAD.replace("k=ble", "k=iroh")),
    (error) => error instanceof DeviceRequestError && error.code === "unsupported_transport",
  );
});

test("accepts only the current canonical optical payload and endpoint", () => {
  const noncanonicalPayloads = [
    OPTICAL_PAYLOAD.replace(`svc=${SERVICE_UUID}`, `svc=${"ff".repeat(16)}`),
    `${OPTICAL_PAYLOAD}&extra=1`,
    OPTICAL_PAYLOAD.replace("&svc=", "&extra=1&svc="),
    OPTICAL_PAYLOAD.replace("&idfp=", "&idfp=0011223344556677&idfp="),
    OPTICAL_PAYLOAD.replace("&non=", "&exp=120&non="),
    OPTICAL_PAYLOAD.replace("exp=120", "exp=600"),
  ];
  for (const payload of noncanonicalPayloads) {
    assert.throws(
      () => parseLocalTransportOpticalPayload(payload),
      (error) => error instanceof DeviceRequestError &&
        (error.code === "invalid_params" || error.code === "unsupported_transport"),
    );
  }
});

test("Noise initiator owns and wipes every generated private input", () => {
  const secrets = [];
  const noise = new LocalTransportNoiseXxInitiator({
    opticalPayload: OPTICAL_PAYLOAD,
    randomBytes: (length) => {
      const secret = Buffer.alloc(length, 0x70 + secrets.length);
      secrets.push(secret);
      return secret;
    },
  });
  assert.equal(secrets.length, 2);
  assert.equal(secrets.every((secret) => secret.some((byte) => byte !== 0)), true);
  noise.wipe();
  assert.equal(secrets.every((secret) => secret.every((byte) => byte === 0)), true);
});

test("Noise constructor wipes the first private input when the second input is invalid", () => {
  const first = Buffer.alloc(32, 0x7a);
  let calls = 0;
  assert.throws(
    () => new LocalTransportNoiseXxInitiator({
      opticalPayload: OPTICAL_PAYLOAD,
      randomBytes: () => {
        calls += 1;
        return calls === 1 ? first : Buffer.alloc(31, 0x7b);
      },
    }),
    { code: "invalid_params" },
  );
  assert.equal(first.every((byte) => byte === 0), true);
});

test("bounds never-settling carrier work and cleans up a late success", async () => {
  let resolveOperation;
  let lateCleanupValue = null;
  const operation = runLocalTransportOperation(
    "test operation",
    5,
    () => new Promise((resolve) => {
      resolveOperation = resolve;
    }),
    (value) => {
      lateCleanupValue = value;
    },
  );
  await assert.rejects(operation, { code: "timeout" });
  resolveOperation("late");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(lateCleanupValue, "late");
});

test("carries get_status over a BLE local transport gateway session", async () => {
  const responder = new FakeLocalTransportResponder();
  const peripheral = new FakePeripheral(responder);
  const noble = new FakeNoble(peripheral);
  const gateway = new LocalTransportBleGateway({
    noble,
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
  });

  const session = await gateway.connect(OPTICAL_PAYLOAD);
  await assert.rejects(
    () => gateway.connect(OPTICAL_PAYLOAD),
    (error) => error instanceof DeviceRequestError && error.code === "invalid_state",
  );
  const result = await session.request(
    { id: "req_status", method: "get_status" },
    1000,
    (response) => {
      assert.equal(response.success, true);
      return response.result;
    },
  );

  assert.equal(result.device.state, "ready");
  assert.equal(result.provisioning.state, "provisioned");
  assert.equal(responder.receivedRequests.length, 1);
  assert.equal(responder.receivedRequests[0].method, "get_status");
  await session.close();
  assert.equal(peripheral.disconnected, true);
});

test("fragments request frames from negotiated BLE ATT MTU", async () => {
  const responder = new FakeLocalTransportResponder();
  const peripheral = new FakePeripheral(responder, { mtu: 64 });
  const noble = new FakeNoble(peripheral);
  const gateway = new LocalTransportBleGateway({
    noble,
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
  });

  const session = await gateway.connect(OPTICAL_PAYLOAD);
  const result = await session.request(
    { id: "req_fragment", method: "get_status" },
    1000,
    (response) => {
      assert.equal(response.success, true);
      return response.result;
    },
  );

  assert.equal(result.device.state, "ready");
  assert.equal(peripheral.data.writes.length > 1, true);
  assert.equal(peripheral.data.writes.every((chunk) => chunk.length <= peripheral.mtu - 3), true);
  await session.close();
});

test("uses the contract MTU when the BLE adapter does not expose a negotiated MTU", async () => {
  const responder = new FakeLocalTransportResponder();
  const peripheral = new FakePeripheral(responder, { mtu: null });
  const noble = new FakeNoble(peripheral);
  const gateway = new LocalTransportBleGateway({
    noble,
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
  });

  const session = await gateway.connect(OPTICAL_PAYLOAD);
  const result = await session.request(
    { id: "req_status_unknown_mtu", method: "get_status" },
    1000,
    (response) => {
      assert.equal(response.success, true);
      return response.result;
    },
  );

  assert.equal(result.device.state, "ready");
  assert.equal(peripheral.data.writes.every((chunk) => chunk.length <= 506), true);
  await session.close();
});

test("cleans up handshake listeners after a control indication timeout", async () => {
  const responder = new SilentLocalTransportResponder();
  const peripheral = new FakePeripheral(responder);
  const noble = new FakeNoble(peripheral);
  const gateway = new LocalTransportBleGateway({
    noble,
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    handshakeTimeoutMs: 1,
    responseTimeoutMs: 1000,
  });

  await assert.rejects(
    () => gateway.connect(OPTICAL_PAYLOAD),
    (error) => error instanceof DeviceRequestError && error.code === "timeout",
  );
  assert.equal(peripheral.control.listenerCount("data"), 0);
  assert.equal(peripheral.disconnected, true);
});

test("uses the request deadline for local transport response waits", async () => {
  const responder = new NoResponseLocalTransportResponder();
  const peripheral = new FakePeripheral(responder);
  const noble = new FakeNoble(peripheral);
  const gateway = new LocalTransportBleGateway({
    noble,
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
  });

  const session = await gateway.connect(OPTICAL_PAYLOAD);
  const started = Date.now();
  await assert.rejects(
    () => session.request({ id: "req_status", method: "get_status" }, 10, (response) => response),
    (error) => error instanceof DeviceRequestError && error.code === "timeout",
  );
  assert.equal(Date.now() - started < 500, true);
  assert.equal(peripheral.data.listenerCount("data"), 0);
  await session.close();
});

test("recovers a timed-out signing response through get_result and ack_result", async () => {
  const responder = new RetainedSigningResponseResponder();
  const peripheral = new FakePeripheral(responder);
  const gateway = new LocalTransportBleGateway({
    noble: new FakeNoble(peripheral),
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
    cleanupTimeoutMs: 100,
  });
  const session = await gateway.connect(OPTICAL_PAYLOAD);

  const response = await session.request(
    {
      method: "sign_transaction",
      sessionId: "session_aabbccdd",
      payload: { chain: "sui", network: "testnet", txBytes: "AQ==" },
    },
    10,
    (value) => value,
  );

  assert.equal(response.success, true);
  assert.deepEqual(
    responder.receivedRequests.map((request) => request.method),
    ["sign_transaction", "get_result", "ack_result"],
  );
  assert.equal(
    responder.receivedRequests[1].payload.retainedRequestId,
    responder.receivedRequests[0].id,
  );
  assert.equal(
    responder.receivedRequests[2].payload.retainedRequestId,
    responder.receivedRequests[0].id,
  );
  await session.close();
});

test("rejects response fragments that exceed the declared total length before the last frame", async () => {
  const responder = new OverflowingResponseLocalTransportResponder();
  const peripheral = new FakePeripheral(responder);
  const noble = new FakeNoble(peripheral);
  const gateway = new LocalTransportBleGateway({
    noble,
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
  });

  const session = await gateway.connect(OPTICAL_PAYLOAD);
  await assert.rejects(
    () => session.request({ id: "req_status", method: "get_status" }, 1000, (response) => response),
    (error) => error instanceof DeviceRequestError && error.code === "invalid_response",
  );
  assert.equal(peripheral.data.listenerCount("data"), 0);
  await session.close();
});

test("preserves shared protocol validation errors at the local transport boundary", async () => {
  const peripheral = new FakePeripheral(new FakeLocalTransportResponder());
  const gateway = new LocalTransportBleGateway({
    noble: new FakeNoble(peripheral),
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
  });
  const session = await gateway.connect(OPTICAL_PAYLOAD);

  await assert.rejects(
    () => session.request(
      { id: "protocol_validation", method: "get_status" },
      1000,
      () => {
        throw new ProtocolError("invalid_response", "Status result is malformed.");
      },
    ),
    (error) => error instanceof DeviceRequestError &&
      error.code === "invalid_response" &&
      error.message === "Status result is malformed." &&
      error.retryable === false,
  );
  await session.close();
  assert.equal(peripheral.disconnected, true);
});

test("serializes complete requests within one BLE session", async () => {
  const responder = new FakeLocalTransportResponder();
  const peripheral = new FakePeripheral(responder);
  const gateway = new LocalTransportBleGateway({
    noble: new FakeNoble(peripheral),
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
  });
  const session = await gateway.connect(OPTICAL_PAYLOAD);

  const [first, second] = await Promise.all([
    session.request({ id: "request_one", method: "get_status" }, 1000, (response) => response),
    session.request({ id: "request_two", method: "get_status" }, 1000, (response) => response),
  ]);

  assert.equal(first.id, "request_one");
  assert.equal(second.id, "request_two");
  assert.deepEqual(responder.receivedRequests.map((request) => request.id), ["request_one", "request_two"]);
  await session.close();
});

test("cancels the active response wait when the peripheral disconnects", async () => {
  const peripheral = new FakePeripheral(new NoResponseLocalTransportResponder());
  const gateway = new LocalTransportBleGateway({
    noble: new FakeNoble(peripheral),
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 10_000,
  });
  const session = await gateway.connect(OPTICAL_PAYLOAD);
  const request = session.request({ id: "disconnect_wait", method: "get_status" }, 10_000, (response) => response);
  setTimeout(() => peripheral.emit("disconnect", null), 0);

  await assert.rejects(request, { code: "transport_closed" });
  assert.equal(peripheral.data.listenerCount("data"), 0);
  await session.close();
});

test("cleans the active response wait when a BLE write fails", async () => {
  const peripheral = new FakePeripheral(new NoResponseLocalTransportResponder());
  const gateway = new LocalTransportBleGateway({
    noble: new FakeNoble(peripheral),
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
  });
  const session = await gateway.connect(OPTICAL_PAYLOAD);
  peripheral.data.writeError = new Error("simulated write failure");

  await assert.rejects(
    () => session.request({ id: "write_failure", method: "get_status" }, 1000, (response) => response),
    { code: "transport_error" },
  );
  assert.equal(peripheral.data.listenerCount("data"), 0);
  await session.close();
});

test("bounds a never-settling BLE request write and cleanup", async () => {
  const peripheral = new FakePeripheral(new NoResponseLocalTransportResponder());
  const gateway = new LocalTransportBleGateway({
    noble: new FakeNoble(peripheral),
    randomBytes: makeGatewayRandomBytes(),
    scanTimeoutMs: 1000,
    responseTimeoutMs: 1000,
    cleanupTimeoutMs: 10,
  });
  const session = await gateway.connect(OPTICAL_PAYLOAD);
  peripheral.data.writePromise = new Promise(() => {});
  peripheral.data.unsubscribePromise = new Promise(() => {});
  peripheral.control.unsubscribePromise = new Promise(() => {});
  peripheral.disconnectPromise = new Promise(() => {});

  const requestStarted = Date.now();
  await assert.rejects(
    () => session.request({ id: "hung_write", method: "get_status" }, 10, (response) => response),
    { code: "timeout" },
  );
  assert.equal(Date.now() - requestStarted < 500, true);
  assert.equal(peripheral.data.listenerCount("data"), 0);

  const closeStarted = Date.now();
  await session.close();
  assert.equal(Date.now() - closeStarted < 500, true);
});

test("bounds BLE connection, discovery, and subscription setup", async () => {
  const cases = [
    {
      label: "connection",
      configure: (peripheral) => {
        peripheral.connectPromise = new Promise(() => {});
      },
    },
    {
      label: "discovery",
      configure: (peripheral) => {
        peripheral.discoverPromise = new Promise(() => {});
      },
    },
    {
      label: "subscription",
      configure: (peripheral) => {
        peripheral.control.subscribePromise = new Promise(() => {});
      },
    },
  ];
  for (const entry of cases) {
    const peripheral = new FakePeripheral(new FakeLocalTransportResponder());
    entry.configure(peripheral);
    const gateway = new LocalTransportBleGateway({
      noble: new FakeNoble(peripheral),
      randomBytes: makeGatewayRandomBytes(),
      scanTimeoutMs: 1000,
      handshakeTimeoutMs: 10,
      cleanupTimeoutMs: 10,
    });
    const started = Date.now();
    await assert.rejects(
      () => gateway.connect(OPTICAL_PAYLOAD),
      (error) => error instanceof DeviceRequestError && error.code === "timeout",
      entry.label,
    );
    assert.equal(Date.now() - started < 500, true, entry.label);
  }
});

test("coordinates scans and keeps sibling sessions alive on one BLE adapter", async () => {
  const firstPeripheral = new FakePeripheral(new FakeLocalTransportResponder());
  const secondPeripheral = new FakePeripheral(new FakeLocalTransportResponder());
  const noble = new FakeNoble([firstPeripheral, secondPeripheral]);
  const firstGateway = new LocalTransportBleGateway({
    noble,
    randomBytes: makeGatewayRandomBytes(),
  });
  const secondGateway = new LocalTransportBleGateway({
    noble,
    randomBytes: makeGatewayRandomBytes(),
  });

  const [firstSession, secondSession] = await Promise.all([
    firstGateway.connect(OPTICAL_PAYLOAD),
    secondGateway.connect(OPTICAL_PAYLOAD),
  ]);
  assert.equal(noble.maxConcurrentScans, 1);

  await firstSession.close();
  const response = await secondSession.request(
    { id: "sibling_status", method: "get_status" },
    1000,
    (value) => value,
  );
  assert.equal(response.id, "sibling_status");
  await secondSession.close();
});

test(
  "hardware: BLE local transport product gateway get_status",
  { skip: localTransportHardwareSkipReason() },
  async () => {
    const noble = require("@stoprocent/noble");
    const gateway = new LocalTransportBleGateway({
      noble,
      scanTimeoutMs: 30_000,
      responseTimeoutMs: 30_000,
    });
    let session = null;
    try {
      session = await gateway.connect(HW_OPTICAL_PAYLOAD);
      const result = await session.request(
        { id: "hw_status", method: "get_status" },
        30_000,
        (response) => {
          assert.equal(response.success, true);
          return response.result;
        },
      );
      assert.equal(typeof result.device?.deviceId, "string");
      assert.equal(typeof result.device?.state, "string");
      assert.equal(typeof result.provisioning?.state, "string");
    } finally {
      await session?.close();
      await noble.stopScanningAsync().catch(() => {});
      noble.removeAllListeners?.();
      noble.reset?.();
      noble.stop?.();
    }
  },
);

class FakeNoble extends EventEmitter {
  state = "poweredOn";

  constructor(peripheral = null) {
    super();
    this.peripherals = Array.isArray(peripheral) ? [...peripheral] : peripheral === null ? [] : [peripheral];
    this.scanning = false;
    this.concurrentScans = 0;
    this.maxConcurrentScans = 0;
  }

  async startScanningAsync(serviceUuids) {
    assert.deepEqual(serviceUuids, [SERVICE_UUID]);
    assert.equal(this.scanning, false, "BLE scans must be serialized by the adapter coordinator");
    this.scanning = true;
    this.concurrentScans += 1;
    this.maxConcurrentScans = Math.max(this.maxConcurrentScans, this.concurrentScans);
    const peripheral = this.peripherals.shift();
    if (peripheral !== undefined) {
      queueMicrotask(() => this.emit("discover", peripheral));
    }
  }

  async stopScanningAsync() {
    if (this.scanning) {
      this.concurrentScans -= 1;
    }
    this.scanning = false;
  }
}

class FakePeripheral extends EventEmitter {
  advertisement = {
    serviceData: [{ uuid: SERVICE_UUID, data: Buffer.from(IDFP) }],
  };

  constructor(responder, options = {}) {
    super();
    this.mtu = Object.hasOwn(options, "mtu") ? options.mtu : 509;
    this.responder = responder;
    this.control = new FakeCharacteristic(CONTROL_UUID, ["indicate", "write"], (chunk) =>
      this.responder.handleControlWrite(chunk, this.control));
    this.data = new FakeCharacteristic(DATA_UUID, ["indicate", "write"], (chunk) =>
      this.responder.handleDataWrite(chunk, this.data));
    this.connected = false;
    this.disconnected = false;
  }

  async connectAsync() {
    if (this.connectPromise !== undefined) {
      return this.connectPromise;
    }
    this.connected = true;
  }

  async disconnectAsync() {
    if (this.disconnectPromise !== undefined) {
      return this.disconnectPromise;
    }
    this.disconnected = true;
    this.emit("disconnect", null);
  }

  async discoverSomeServicesAndCharacteristicsAsync(serviceUuids, characteristicUuids) {
    if (this.discoverPromise !== undefined) {
      return this.discoverPromise;
    }
    assert.deepEqual(serviceUuids, [SERVICE_UUID]);
    assert.deepEqual(characteristicUuids, [CONTROL_UUID, DATA_UUID]);
    return { services: [], characteristics: [this.control, this.data] };
  }
}

class FakeCharacteristic extends EventEmitter {
  constructor(uuid, properties, onWrite) {
    super();
    this.uuid = uuid;
    this.properties = properties;
    this.onWrite = onWrite;
    this.subscribed = false;
    this.writes = [];
  }

  async subscribeAsync() {
    if (this.subscribePromise !== undefined) {
      return this.subscribePromise;
    }
    this.subscribed = true;
  }

  async unsubscribeAsync() {
    if (this.unsubscribePromise !== undefined) {
      return this.unsubscribePromise;
    }
    this.subscribed = false;
  }

  async writeAsync(data) {
    if (this.writePromise !== undefined) {
      return this.writePromise;
    }
    if (this.writeError !== undefined) {
      const error = this.writeError;
      this.writeError = undefined;
      throw error;
    }
    const chunk = Buffer.from(data);
    this.writes.push(chunk);
    this.onWrite(chunk);
  }
}

class FakeLocalTransportResponder {
  constructor() {
    this.handshake = new NoiseXxResponder();
    this.keys = null;
    this.rxCounter = 0n;
    this.txCounter = 0n;
    this.receivedRequests = [];
    this.requestChunks = [];
    this.requestTotal = null;
    this.nextSequence = 0;
  }

  handleControlWrite(chunk, control) {
    if (chunk.length === 32) {
      setTimeout(() => control.emit("data", this.handshake.readMessage1AndWriteMessage2(chunk)), 0);
      return;
    }
    this.keys = this.handshake.readMessage3(chunk);
    setTimeout(() => control.emit("data", Buffer.from([0x01])), 0);
  }

  handleDataWrite(chunk, data) {
    assert.notEqual(this.keys, null, "session keys must exist before data frames");
    const frame = decryptFrame(this.keys.gatewayToDevice, 0x01, this.rxCounter++, chunk);
    assert.equal(frame.type, 0x01);
    assert.equal(frame.sequence, this.nextSequence++);
    if (this.requestTotal === null) {
      this.requestTotal = frame.totalLen;
    }
    assert.equal(frame.totalLen, this.requestTotal);
    this.requestChunks.push(frame.payload);
    if ((frame.flags & 0x01) === 0) {
      return;
    }
    const requestBytes = Buffer.concat(this.requestChunks);
    assert.equal(requestBytes.length, this.requestTotal);
    this.requestChunks = [];
    this.requestTotal = null;
    this.nextSequence = 0;
    const requestLine = requestBytes.toString("utf8");
    const request = JSON.parse(requestLine);
    this.receivedRequests.push(request);
    const responseValues = this.responsesForRequest(request);
    if (responseValues.length === 0) {
      return;
    }
    const encryptedResponses = responseValues.map((responseValue) => {
      const response = JSON.stringify(responseValue);
      const payload = Buffer.from(response, "utf8");
      const plain = encodePlainFrame(0x01, 0x01, 0, payload.length, payload);
      return encryptFrame(this.keys.deviceToGateway, 0x02, this.txCounter++, plain);
    });
    setTimeout(() => {
      for (const encrypted of encryptedResponses) {
        data.emit("data", encrypted);
      }
    }, 0);
  }

  responsesForRequest(request) {
    return [this.successResponse(request)];
  }

  successResponse(request) {
    return {
      id: request.id,
      version: 1,
      method: request.method,
      success: true,
      result: {
        device: { state: "ready" },
        provisioning: { state: "provisioned" },
        transport: { connected: true },
      },
    };
  }
}

class RetainedSigningResponseResponder extends FakeLocalTransportResponder {
  originalSigningRequest = null;

  responsesForRequest(request) {
    if (request.method === "sign_transaction") {
      this.originalSigningRequest = request;
      return [];
    }
    if (request.method === "get_result") {
      assert.notEqual(this.originalSigningRequest, null);
      return [
        this.successResponse(this.originalSigningRequest),
        {
          id: request.id,
          version: 1,
          method: "get_result",
          success: true,
          result: { status: "signed" },
        },
      ];
    }
    if (request.method === "ack_result") {
      return [{
        id: request.id,
        version: 1,
        method: "ack_result",
        success: true,
        result: {},
      }];
    }
    return super.responsesForRequest(request);
  }
}

class NoResponseLocalTransportResponder extends FakeLocalTransportResponder {
  handleDataWrite(chunk) {
    assert.notEqual(this.keys, null, "session keys must exist before data frames");
    decryptFrame(this.keys.gatewayToDevice, 0x01, this.rxCounter++, chunk);
  }
}

class OverflowingResponseLocalTransportResponder extends FakeLocalTransportResponder {
  handleDataWrite(chunk, data) {
    assert.notEqual(this.keys, null, "session keys must exist before data frames");
    decryptFrame(this.keys.gatewayToDevice, 0x01, this.rxCounter++, chunk);
    const first = encodePlainFrame(0x01, 0x00, 0, 1, Buffer.from("a"));
    const second = encodePlainFrame(0x01, 0x00, 1, 1, Buffer.from("b"));
    const encryptedFirst = encryptFrame(this.keys.deviceToGateway, 0x02, this.txCounter++, first);
    const encryptedSecond = encryptFrame(this.keys.deviceToGateway, 0x02, this.txCounter++, second);
    setTimeout(() => {
      data.emit("data", encryptedFirst);
      data.emit("data", encryptedSecond);
    }, 0);
  }
}

class SilentLocalTransportResponder {
  handleControlWrite() {}

  handleDataWrite() {}
}

class NoiseXxResponder {
  constructor() {
    this.h = Buffer.alloc(32);
    Buffer.from("Noise_XX_25519_AESGCM_SHA256", "ascii").copy(this.h);
    this.ck = Buffer.from(this.h);
    this.k = null;
    this.n = 0n;
    this.e = DEVICE_EPHEMERAL_SECRET;
    this.ePub = Buffer.from(x25519.getPublicKey(this.e));
    this.s = DEVICE_STATIC_SECRET;
    this.sPub = DEVICE_STATIC_PUBLIC;
    this.mixHash(Buffer.concat([Buffer.from("Agent-Q local transport pairing v1\0", "ascii"), Buffer.from(OPTICAL_PAYLOAD, "ascii")]));
  }

  readMessage1AndWriteMessage2(message1) {
    assert.equal(message1.length, 32);
    this.gatewayEphemeral = Buffer.from(message1);
    this.mixHash(this.gatewayEphemeral);
    this.mixHash(this.ePub);
    this.mixKey(x25519Shared(this.e, this.gatewayEphemeral));
    const encryptedStatic = this.encryptAndHash(this.sPub);
    this.mixKey(x25519Shared(this.s, this.gatewayEphemeral));
    const encryptedIdfp = this.encryptAndHash(Buffer.from(IDFP));
    return Buffer.concat([this.ePub, encryptedStatic, encryptedIdfp]);
  }

  readMessage3(message3) {
    assert.equal(message3.length, 64);
    const gatewayStatic = this.decryptAndHash(message3.subarray(0, 48));
    this.mixKey(x25519Shared(this.e, gatewayStatic));
    const empty = this.decryptAndHash(message3.subarray(48));
    assert.equal(empty.length, 0);
    const [gatewayToDevice, deviceToGateway] = hkdf2(this.ck, Buffer.alloc(0));
    return { gatewayToDevice, deviceToGateway };
  }

  mixHash(data) {
    this.h = sha256(this.h, data);
  }

  mixKey(ikm) {
    const [nextCk, tempK] = hkdf2(this.ck, ikm);
    this.ck = nextCk;
    this.k = tempK;
    this.n = 0n;
  }

  encryptAndHash(plaintext) {
    const output = this.k === null
      ? Buffer.from(plaintext)
      : aesGcmEncrypt(this.k, noiseNonce(this.n++), this.h, plaintext);
    this.mixHash(output);
    return output;
  }

  decryptAndHash(input) {
    const plaintext = this.k === null
      ? Buffer.from(input)
      : aesGcmDecrypt(this.k, noiseNonce(this.n++), this.h, input);
    this.mixHash(input);
    return plaintext;
  }
}

function sha256(...parts) {
  const hash = createHash("sha256");
  for (const part of parts) {
    hash.update(part);
  }
  return hash.digest();
}

function hmacSha256(key, ...parts) {
  const hmac = createHmac("sha256", key);
  for (const part of parts) {
    hmac.update(part);
  }
  return hmac.digest();
}

function hkdf2(salt, ikm) {
  const tempKey = hmacSha256(salt, ikm);
  const out1 = hmacSha256(tempKey, Buffer.from([0x01]));
  const out2 = hmacSha256(tempKey, out1, Buffer.from([0x02]));
  return [out1, out2];
}

function noiseNonce(counter) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(counter, 4);
  return nonce;
}

function aesGcmEncrypt(key, nonce, aad, plaintext) {
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ciphertext, cipher.getAuthTag()]);
}

function aesGcmDecrypt(key, nonce, aad, input) {
  const body = input.subarray(0, input.length - 16);
  const tag = input.subarray(input.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

function x25519Shared(secret, publicKey) {
  const shared = Buffer.from(x25519.getSharedSecret(secret, publicKey));
  assert.equal(shared.every((byte) => byte === 0), false);
  return shared;
}

function frameNonce(counter) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(counter, 4);
  return nonce;
}

function frameAad(direction, counter) {
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(counter, 0);
  return Buffer.concat([Buffer.from("Agent-Q local transport frame v1\0", "ascii"), Buffer.from([direction]), counterBytes]);
}

function encodePlainFrame(type, flags, sequence, totalLen, payload) {
  const header = Buffer.alloc(10);
  header[0] = type;
  header[1] = flags;
  header.writeUInt16BE(sequence, 2);
  header.writeUInt32BE(totalLen, 4);
  header.writeUInt16BE(payload.length, 8);
  return Buffer.concat([header, payload]);
}

function decodePlainFrame(plain) {
  const type = plain[0] ?? 0;
  const flags = plain[1] ?? 0;
  const sequence = plain.readUInt16BE(2);
  const totalLen = plain.readUInt32BE(4);
  const payloadLen = plain.readUInt16BE(8);
  assert.equal(plain.length, 10 + payloadLen);
  return { type, flags, sequence, totalLen, payload: plain.subarray(10) };
}

function encryptFrame(key, direction, counter, plainFrame) {
  return aesGcmEncrypt(key, frameNonce(counter), frameAad(direction, counter), plainFrame);
}

function decryptFrame(key, direction, counter, encryptedFrame) {
  return decodePlainFrame(aesGcmDecrypt(key, frameNonce(counter), frameAad(direction, counter), encryptedFrame));
}

function localTransportHardwareSkipReason() {
  if (!HW_GET_STATUS_ENABLED) {
    return "set LOCAL_TRANSPORT_HW_GET_STATUS=1 with a StackChan QR pairing window open";
  }
  if (HW_OPTICAL_PAYLOAD.length === 0) {
    return "set LOCAL_TRANSPORT_HW_OPTICAL_PAYLOAD to the aqlt:1 QR payload shown by Firmware";
  }
  return false;
}
