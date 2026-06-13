import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  consumeFirmwareSessionInvalidated,
  deadlineEnforcingDriver,
  INTERNAL_USB_DEADLINE_MS,
  isLikelyAgentQUsbPort,
  markRequestMayHaveReachedFirmware,
  mapErrorToUnavailableReason,
  requestSignResultWithRecovery,
  resolveUsbCalloutPath,
  scanUsbDeviceStatuses,
  scanUsbDevices,
  SerialPortUsbDriver,
  setSerialPortFactoryForTest,
  tryParseMatchingResponseLine,
  validateInternalDeadlineMs,
  withSerialPortTransaction,
} from "../dist/usb.js";
import {
  assertPolicyProposeResultResponse,
  assertStatusResponse,
  consumeProtocolResponseChunk,
  makeSignTransactionRequest,
  MAX_PROTOCOL_RESPONSE_LINE_BYTES,
} from "../dist/protocol.js";
import { PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES } from "../dist/provider-protocol.js";
import { AgentQError } from "../dist/errors.js";

const SUI_SIGNATURE = Buffer.alloc(97, 1).toString("base64");
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

function signedTransactionResult(id) {
  return {
    id,
    version: 1,
    type: "sign_result",
    authorization: "user",
    status: "signed",
    chain: "sui",
    method: "sign_transaction",
    signature: SUI_SIGNATURE,
  };
}

function capabilitiesResult(id, { payload = false, payloadCapability = null } = {}) {
  return {
    id,
    version: 1,
    type: "capabilities",
    chains: [
      {
        id: "sui",
        accounts: [{ keyScheme: "ed25519", derivationPath: "m/44'/784'/0'/0'/0'" }],
        methods: [],
      },
    ],
    signing: {
      authorization: "user",
      methods: [
        {
          chain: "sui",
          method: "sign_transaction",
          ...(payload
            ? {
              payload: {
                kind: "transaction",
                inlineMaxBytes: "384",
                chunkMaxBytes: "2048",
                payloadMaxBytes: "131072",
                ...(payloadCapability ?? {}),
              },
            }
            : {}),
        },
        { chain: "sui", method: "sign_personal_message" },
      ],
    },
  };
}

function signTransactionRequest() {
  return makeSignTransactionRequest(
    "session_abcdef",
    "sui",
    "sign_transaction",
    { network: "mainnet", txBytes: "AQID" },
    "req_sign",
  );
}

function waitMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class FakeSerialPort {
  isOpen = false;
  openCalls = 0;
  flushCalls = 0;
  writeCalls = 0;
  drainCalls = 0;
  closeCalls = 0;
  writes = [];
  #listeners = new Map();
  #behavior;
  #openCallback = null;
  #flushCallback = null;

  constructor(behavior = {}) {
    this.#behavior = behavior;
  }

  open(callback) {
    this.openCalls += 1;
    this.#openCallback = callback;
    if (this.#behavior.open === "pending") {
      return;
    }
    setTimeout(() => this.resolveOpen(), this.#behavior.openDelayMs ?? 0);
  }

  resolveOpen(error = null) {
    if (this.#openCallback === null) {
      return;
    }
    const callback = this.#openCallback;
    this.#openCallback = null;
    if (error === null) {
      this.isOpen = true;
    }
    callback(error);
  }

  flush(callback) {
    this.flushCalls += 1;
    this.#flushCallback = callback;
    if (this.#behavior.flush === "pending") {
      return;
    }
    setTimeout(() => this.resolveFlush(), this.#behavior.flushDelayMs ?? 0);
  }

  resolveFlush(error = null) {
    if (this.#flushCallback === null) {
      return;
    }
    const callback = this.#flushCallback;
    this.#flushCallback = null;
    callback(error);
  }

  write(data, callback) {
    this.writeCalls += 1;
    this.writes.push(data);
    const request = JSON.parse(String(data).trim());
    const result = this.#behavior.write?.(request, this);
    if (result?.pending === true) {
      return;
    }
    setTimeout(() => {
      if (result?.error !== undefined) {
        callback(result.error);
        return;
      }
      callback(null);
      if (result?.response !== undefined) {
        this.emit("data", Buffer.from(`${JSON.stringify(result.response)}\n`, "utf8"));
      }
    }, result?.delayMs ?? 0);
  }

  drain(callback) {
    this.drainCalls += 1;
    setTimeout(() => callback(null), this.#behavior.drainDelayMs ?? 0);
  }

  close(callback) {
    this.closeCalls += 1;
    this.isOpen = false;
    setTimeout(() => callback(null), this.#behavior.closeDelayMs ?? 0);
  }

  on(event, listener) {
    const listeners = this.#listeners.get(event) ?? new Set();
    listeners.add(listener);
    this.#listeners.set(event, listeners);
  }

  off(event, listener) {
    this.#listeners.get(event)?.delete(listener);
  }

  emit(event, value) {
    for (const listener of this.#listeners.get(event) ?? []) {
      listener(value);
    }
  }
}

test("requestSignResultWithRecovery fetches and acks a retained sign result by original id", async () => {
  const requests = [];
  const request = signTransactionRequest();
  const result = await requestSignResultWithRecovery(request, 1234, async (wireRequest, deadlineMs, assertResponse) => {
    requests.push({ request: wireRequest, deadlineMs });
    if (wireRequest.type === "sign_transaction") {
      throw markRequestMayHaveReachedFirmware(new AgentQError("timeout", "Lost sign response.", true));
    }
    if (wireRequest.type === "get_result") {
      return assertResponse(signedTransactionResult(wireRequest.id));
    }
    if (wireRequest.type === "ack_result") {
      return assertResponse({ id: wireRequest.id, version: 1, type: "ack_result", status: "acked" });
    }
    throw new Error(`unexpected request: ${wireRequest.type}`);
  });

  assert.equal(result.status, "signed");
  assert.deepEqual(requests.map((entry) => entry.request.type), [
    "sign_transaction",
    "get_result",
    "ack_result",
  ]);
  assert.equal(requests[1].request.id, request.id);
  assert.equal(requests[2].request.id, request.id);
  assert.equal(requests[1].deadlineMs, INTERNAL_USB_DEADLINE_MS);
  assert.equal(requests[2].deadlineMs, INTERNAL_USB_DEADLINE_MS);
});

test("requestSignResultWithRecovery waits for ack_result ordering before resolving", async () => {
  const request = signTransactionRequest();
  let releaseAck;
  let resolved = false;
  const resultPromise = requestSignResultWithRecovery(request, 1234, async (wireRequest, _deadlineMs, assertResponse) => {
    if (wireRequest.type === "sign_transaction") {
      throw markRequestMayHaveReachedFirmware(new AgentQError("timeout", "Lost sign response.", true));
    }
    if (wireRequest.type === "get_result") {
      return assertResponse(signedTransactionResult(wireRequest.id));
    }
    if (wireRequest.type === "ack_result") {
      await new Promise((resolve) => {
        releaseAck = resolve;
      });
      return assertResponse({ id: wireRequest.id, version: 1, type: "ack_result", status: "acked" });
    }
    throw new Error(`unexpected request: ${wireRequest.type}`);
  });
  resultPromise.then(() => {
    resolved = true;
  }, () => {
    resolved = true;
  });

  await waitMs(0);
  assert.equal(resolved, false, "recovered result must not resolve before ack_result cleanup settles");
  releaseAck();
  const result = await resultPromise;
  assert.equal(result.status, "signed");
  assert.equal(resolved, true);
});

test("requestSignResultWithRecovery ignores ack_result failure after recovery", async () => {
  const request = signTransactionRequest();
  const result = await requestSignResultWithRecovery(request, 1234, async (wireRequest, _deadlineMs, assertResponse) => {
    if (wireRequest.type === "sign_transaction") {
      throw markRequestMayHaveReachedFirmware(new AgentQError("transport_closed", "Transport closed.", true));
    }
    if (wireRequest.type === "get_result") {
      return assertResponse(signedTransactionResult(wireRequest.id));
    }
    if (wireRequest.type === "ack_result") {
      throw new AgentQError("transport_closed", "Ack failed.", true);
    }
    throw new Error(`unexpected request: ${wireRequest.type}`);
  });

  assert.equal(result.status, "signed");
});

test("requestSignResultWithRecovery propagates get_result invalid_session", async () => {
  const request = signTransactionRequest();
  const original = markRequestMayHaveReachedFirmware(new AgentQError("timeout", "Original sign timeout.", true));
  const seen = [];

  await assert.rejects(
    () => requestSignResultWithRecovery(request, 1234, async (wireRequest) => {
      seen.push(wireRequest.type);
      if (wireRequest.type === "sign_transaction") {
        throw original;
      }
      if (wireRequest.type === "get_result") {
        throw new AgentQError("invalid_session", "Session is unknown or already ended.", false);
      }
      throw new Error(`unexpected request: ${wireRequest.type}`);
    }),
    (error) => error instanceof AgentQError && error.code === "invalid_session",
  );
  assert.deepEqual(seen, ["sign_transaction", "get_result"]);
});

test("requestSignResultWithRecovery marks recovered result when ack_result invalidates the session", async () => {
  const request = signTransactionRequest();
  const result = await requestSignResultWithRecovery(request, 1234, async (wireRequest, _deadlineMs, assertResponse) => {
    if (wireRequest.type === "sign_transaction") {
      throw markRequestMayHaveReachedFirmware(new AgentQError("transport_closed", "Transport closed.", true));
    }
    if (wireRequest.type === "get_result") {
      return assertResponse(signedTransactionResult(wireRequest.id));
    }
    if (wireRequest.type === "ack_result") {
      throw new AgentQError("invalid_session", "Session is unknown or already ended.", false);
    }
    throw new Error(`unexpected request: ${wireRequest.type}`);
  });

  assert.equal(result.status, "signed");
  assert.equal(consumeFirmwareSessionInvalidated(result), true);
  assert.equal(consumeFirmwareSessionInvalidated(result), false, "metadata is consumed once");
});

test("requestSignResultWithRecovery does not recover write-before-open failures", async () => {
  const request = signTransactionRequest();
  const original = new AgentQError("port_not_found", "No port.", true);
  const seen = [];

  await assert.rejects(
    () => requestSignResultWithRecovery(request, 1234, async (wireRequest) => {
      seen.push(wireRequest.type);
      throw original;
    }),
    (error) => error === original,
  );
  assert.deepEqual(seen, ["sign_transaction"]);
});

test("requestSignResultWithRecovery preserves original sign error when get_result fails", async () => {
  const request = signTransactionRequest();
  const original = markRequestMayHaveReachedFirmware(new AgentQError("timeout", "Original sign timeout.", true));
  const seen = [];

  await assert.rejects(
    () => requestSignResultWithRecovery(request, 1234, async (wireRequest) => {
      seen.push(wireRequest.type);
      if (wireRequest.type === "sign_transaction") {
        throw original;
      }
      if (wireRequest.type === "get_result") {
        throw new AgentQError("unknown_request", "No retained result.", false);
      }
      throw new Error(`unexpected request: ${wireRequest.type}`);
    }),
    (error) => error === original,
  );
  assert.deepEqual(seen, ["sign_transaction", "get_result"]);
});

test("requestSignResultWithRecovery preserves original sign error when get_result is malformed", async () => {
  const request = signTransactionRequest();
  const original = markRequestMayHaveReachedFirmware(new AgentQError("timeout", "Original sign timeout.", true));

  await assert.rejects(
    () => requestSignResultWithRecovery(request, 1234, async (wireRequest, _deadlineMs, assertResponse) => {
      if (wireRequest.type === "sign_transaction") {
        throw original;
      }
      if (wireRequest.type === "get_result") {
        return assertResponse({ id: wireRequest.id, version: 1, type: "ack_result", status: "acked" });
      }
      throw new Error(`unexpected request: ${wireRequest.type}`);
    }),
    (error) => error === original,
  );
});

test("withSerialPortTransaction keeps a queued request out of an active signing transaction", async () => {
  const events = [];
  let releaseTransaction;

  const signingTransaction = withSerialPortTransaction("/dev/cu.agentq-test", 1000, async () => {
    events.push("sign");
    await new Promise((resolve) => {
      releaseTransaction = resolve;
    });
    events.push("get_result");
    events.push("ack_result");
    return "signed";
  });
  const queuedRequest = withSerialPortTransaction("/dev/cu.agentq-test", 1000, async () => {
    events.push("get_capabilities");
    return "capabilities";
  });

  await waitMs(0);
  assert.deepEqual(events, ["sign"], "queued request must not enter the active signing transaction");
  releaseTransaction();
  assert.equal(await signingTransaction, "signed");
  assert.equal(await queuedRequest, "capabilities");
  assert.deepEqual(events, ["sign", "get_result", "ack_result", "get_capabilities"]);
});

test("withSerialPortTransaction drops an expired queued request before the operation can write", async () => {
  let releaseTransaction;
  let lateOperationStarted = false;
  const active = withSerialPortTransaction("/dev/cu.agentq-deadline", 1000, async () => {
    await new Promise((resolve) => {
      releaseTransaction = resolve;
    });
  });
  const expired = withSerialPortTransaction("/dev/cu.agentq-deadline", 5, async () => {
    lateOperationStarted = true;
  });

  await waitMs(10);
  releaseTransaction();
  await active;
  await assert.rejects(
    () => expired,
    (error) => error instanceof AgentQError && error.code === "timeout",
  );
  assert.equal(lateOperationStarted, false, "expired queued requests must not run later and write to USB");
});

test("node USB lease canceled after open timeout never writes and late open closes only", async () => {
  const ports = [];
  setSerialPortFactoryForTest(() => {
    const port = ports.length === 0
      ? new FakeSerialPort({ open: "pending" })
      : new FakeSerialPort({
        write: (request) => ({
          response: {
            ...status,
            id: request.id,
          },
        }),
      });
    ports.push(port);
    return port;
  });
  try {
    const driver = new SerialPortUsbDriver();
    const portPath = "/dev/cu.agentq-open-timeout";
    await assert.rejects(
      () => driver.requestStatus(portPath, 5),
      (error) => error instanceof AgentQError && error.code === "timeout",
    );
    assert.equal(ports.length, 1);
    assert.equal(ports[0].writeCalls, 0, "timed-out open must not continue into write");

    await assert.rejects(
      () => driver.requestStatus(portPath, 5),
      (error) => error instanceof AgentQError && error.code === "port_in_use",
    );
    assert.equal(ports.length, 1, "quarantined portPath must not start another physical open");

    ports[0].resolveOpen();
    await waitMs(5);
    assert.equal(ports[0].writeCalls, 0, "late open must still not write");
    assert.equal(ports[0].closeCalls, 1, "late open must enter close-only cleanup");

    const recovered = await driver.requestStatus(portPath, 30);
    assert.equal(recovered.type, "status", "late cleanup completion releases the portPath quarantine");
    assert.equal(ports.length, 2);
  } finally {
    setSerialPortFactoryForTest(null);
  }
});

test("node USB flush timeout does not start write", async () => {
  const ports = [];
  setSerialPortFactoryForTest(() => {
    const port = new FakeSerialPort({ flush: "pending" });
    ports.push(port);
    return port;
  });
  try {
    const driver = new SerialPortUsbDriver();
    await assert.rejects(
      () => driver.requestStatus("/dev/cu.agentq-flush-timeout", 5),
      (error) => error instanceof AgentQError && error.code === "timeout",
    );
    assert.equal(ports.length, 1);
    assert.equal(ports[0].flushCalls, 1);
    assert.equal(ports[0].writeCalls, 0, "timed-out flush must not continue into write");
    assert.equal(ports[0].closeCalls, 1, "timed-out flush cleanup must have one close owner");
  } finally {
    setSerialPortFactoryForTest(null);
  }
});

test("node USB write-started failure is recovery eligible", async () => {
  const seen = [];
  setSerialPortFactoryForTest(() => new FakeSerialPort({
    write: (request) => {
      seen.push(request.type);
      if (request.type === "sign_transaction") {
        return { error: new Error("write failed after start") };
      }
      if (request.type === "get_result") {
        return { response: signedTransactionResult(request.id) };
      }
      if (request.type === "ack_result") {
        return { response: { id: request.id, version: 1, type: "ack_result", status: "acked" } };
      }
      if (request.type === "get_capabilities") {
        return { response: capabilitiesResult(request.id) };
      }
      return { response: status };
    },
  }));
  try {
    const driver = new SerialPortUsbDriver();
    const result = await driver.signTransaction(
      "/dev/cu.agentq-write-failed",
      "session_abcdef",
      { operation: "sign_transaction", chain: "sui", method: "sign_transaction" },
      { network: "mainnet", txBytes: "AQID" },
      100,
    );
    assert.equal(result.status, "signed");
    assert.deepEqual(seen, ["get_capabilities", "sign_transaction", "get_result", "ack_result"]);
  } finally {
    setSerialPortFactoryForTest(null);
  }
});

test("node USB validates sign_transaction params before serial I/O", async () => {
  const ports = [];
  setSerialPortFactoryForTest(() => {
    ports.push(new FakeSerialPort());
    return ports.at(-1);
  });
  try {
    const driver = new SerialPortUsbDriver();
    await assert.rejects(
      () => driver.signTransaction(
        "/dev/cu.agentq-invalid-sign-params",
        "session_abcdef",
        { operation: "sign_transaction", chain: "sui", method: "sign_transaction" },
        { network: "mainnet", txBytes: "%%%" },
        100,
      ),
      (error) => error?.code === "invalid_params",
    );
    assert.equal(ports.length, 0, "invalid sign params must fail before opening the serial port");
  } finally {
    setSerialPortFactoryForTest(null);
  }
});

test("node USB uploads a synthetic large transaction payload before staged signing", async () => {
  const payload = Buffer.alloc(128 * 1024);
  for (let index = 0; index < payload.length; index += 1) {
    payload[index] = (index * 31 + 17) & 0xff;
  }
  const payloadDigest = `sha256:${createHash("sha256").update(payload).digest("hex")}`;
  const chunkMaxBytes = 2048;
  const seen = [];
  const chunks = [];
  let receivedBytes = 0;
  setSerialPortFactoryForTest(() => new FakeSerialPort({
    write: (request) => {
      seen.push(request.type);
      if (request.type === "get_capabilities") {
        return { response: capabilitiesResult(request.id, { payload: true }) };
      }
      if (request.type === "payload_upload_begin") {
        assert.equal(request.chain, "sui");
        assert.equal(request.method, "sign_transaction");
        assert.equal(request.payloadKind, "transaction");
        assert.equal(request.sizeBytes, String(payload.length));
        assert.equal(request.payloadDigest, payloadDigest);
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_begin_result",
            uploadId: "upload_synthetic_0001",
            receivedBytes: "0",
            chunkMaxBytes: String(chunkMaxBytes),
          },
        };
      }
      if (request.type === "payload_upload_chunk") {
        assert.equal(request.uploadId, "upload_synthetic_0001");
        assert.equal(request.offsetBytes, String(receivedBytes));
        const chunk = Buffer.from(request.chunk, "base64");
        chunks.push(chunk);
        receivedBytes += chunk.length;
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_chunk_result",
            receivedBytes: String(receivedBytes),
          },
        };
      }
      if (request.type === "payload_upload_finish") {
        assert.equal(request.uploadId, "upload_synthetic_0001");
        assert.equal(receivedBytes, payload.length);
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_finish_result",
            payloadRef: "payload_synthetic_0001",
            chain: "sui",
            method: "sign_transaction",
            payloadKind: "transaction",
            sizeBytes: String(payload.length),
            payloadDigest,
          },
        };
      }
      if (request.type === "sign_transaction") {
        assert.deepEqual(request.params, {
          network: "mainnet",
          payloadRef: "payload_synthetic_0001",
          payloadKind: "transaction",
          sizeBytes: String(payload.length),
          payloadDigest,
        });
        return { response: signedTransactionResult(request.id) };
      }
      return { response: status };
    },
  }));
  try {
    const driver = new SerialPortUsbDriver();
    const result = await driver.signTransaction(
      "/dev/cu.agentq-staged-sign",
      "session_abcdef",
      { operation: "sign_transaction", chain: "sui", method: "sign_transaction" },
      { network: "mainnet", txBytes: payload.toString("base64") },
      1000,
    );
    assert.equal(result.status, "signed");
    assert.equal(seen[0], "get_capabilities");
    assert.equal(seen[1], "payload_upload_begin");
    assert.equal(seen.at(-2), "payload_upload_finish");
    assert.equal(seen.at(-1), "sign_transaction");
    assert.equal(
      seen.filter((type) => type === "payload_upload_chunk").length,
      Math.ceil(payload.length / chunkMaxBytes),
    );
    assert.deepEqual(Buffer.concat(chunks), payload);
  } finally {
    setSerialPortFactoryForTest(null);
  }
});

test("node USB aborts finalized staged payload by payloadRef after descriptor mismatch", async () => {
  const payload = Buffer.alloc(PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES + 1, 0x44);
  const seen = [];
  let receivedBytes = 0;
  let abortRequest = null;
  setSerialPortFactoryForTest(() => new FakeSerialPort({
    write: (request) => {
      seen.push(request.type);
      if (request.type === "get_capabilities") {
        return { response: capabilitiesResult(request.id, { payload: true }) };
      }
      if (request.type === "payload_upload_begin") {
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_begin_result",
            uploadId: "upload_descriptor_mismatch",
            receivedBytes: "0",
            chunkMaxBytes: String(payload.length),
          },
        };
      }
      if (request.type === "payload_upload_chunk") {
        receivedBytes += Buffer.from(request.chunk, "base64").length;
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_chunk_result",
            receivedBytes: String(receivedBytes),
          },
        };
      }
      if (request.type === "payload_upload_finish") {
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_finish_result",
            payloadRef: "payload_descriptor_mismatch",
            chain: "sui",
            method: "sign_transaction",
            payloadKind: "transaction",
            sizeBytes: String(payload.length),
            payloadDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
          },
        };
      }
      if (request.type === "payload_upload_abort") {
        abortRequest = request;
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_abort_result",
            status: "aborted",
          },
        };
      }
      return { response: signedTransactionResult(request.id) };
    },
  }));
  try {
    const driver = new SerialPortUsbDriver();
    await assert.rejects(
      () => driver.signTransaction(
        "/dev/cu.agentq-descriptor-mismatch",
        "session_abcdef",
        { operation: "sign_transaction", chain: "sui", method: "sign_transaction" },
        { network: "mainnet", txBytes: payload.toString("base64") },
        1000,
      ),
      (error) => error instanceof AgentQError && error.code === "protocol_error",
    );
    assert.equal(seen.at(-1), "payload_upload_abort");
    assert.equal(abortRequest.payloadRef, "payload_descriptor_mismatch");
    assert.equal("uploadId" in abortRequest, false);
  } finally {
    setSerialPortFactoryForTest(null);
  }
});

test("node USB preserves staged failure and marks session invalidated when abort reports invalid_session", async () => {
  const payload = Buffer.alloc(PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES + 1, 0x45);
  let receivedBytes = 0;
  setSerialPortFactoryForTest(() => new FakeSerialPort({
    write: (request) => {
      if (request.type === "get_capabilities") {
        return { response: capabilitiesResult(request.id, { payload: true }) };
      }
      if (request.type === "payload_upload_begin") {
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_begin_result",
            uploadId: "upload_abort_invalid_session",
            receivedBytes: "0",
            chunkMaxBytes: String(payload.length),
          },
        };
      }
      if (request.type === "payload_upload_chunk") {
        receivedBytes += Buffer.from(request.chunk, "base64").length;
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_chunk_result",
            receivedBytes: String(receivedBytes),
          },
        };
      }
      if (request.type === "payload_upload_finish") {
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_finish_result",
            payloadRef: "payload_abort_invalid_session",
            chain: "sui",
            method: "sign_transaction",
            payloadKind: "transaction",
            sizeBytes: String(payload.length),
            payloadDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
          },
        };
      }
      if (request.type === "payload_upload_abort") {
        return {
          response: {
            id: request.id,
            version: 1,
            type: "error",
            error: { code: "invalid_session", message: "Session is unknown or already ended." },
          },
        };
      }
      return { response: signedTransactionResult(request.id) };
    },
  }));
  try {
    const driver = new SerialPortUsbDriver();
    let thrown = null;
    try {
      await driver.signTransaction(
        "/dev/cu.agentq-abort-invalid-session",
        "session_abcdef",
        { operation: "sign_transaction", chain: "sui", method: "sign_transaction" },
        { network: "mainnet", txBytes: payload.toString("base64") },
        1000,
      );
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown instanceof AgentQError);
    assert.equal(thrown.code, "protocol_error");
    assert.equal(consumeFirmwareSessionInvalidated(thrown), true);
    assert.equal(consumeFirmwareSessionInvalidated(thrown), false);
  } finally {
    setSerialPortFactoryForTest(null);
  }
});

test("node USB aborts active staged upload by uploadId after progress mismatch", async () => {
  const payload = Buffer.alloc(PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES + 1, 0x61);
  let abortRequest = null;
  setSerialPortFactoryForTest(() => new FakeSerialPort({
    write: (request) => {
      if (request.type === "get_capabilities") {
        return { response: capabilitiesResult(request.id, { payload: true }) };
      }
      if (request.type === "payload_upload_begin") {
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_begin_result",
            uploadId: "upload_progress_mismatch",
            receivedBytes: "0",
            chunkMaxBytes: String(payload.length),
          },
        };
      }
      if (request.type === "payload_upload_chunk") {
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_chunk_result",
            receivedBytes: "1",
          },
        };
      }
      if (request.type === "payload_upload_abort") {
        abortRequest = request;
        return {
          response: {
            id: request.id,
            version: 1,
            type: "payload_upload_abort_result",
            status: "aborted",
          },
        };
      }
      return { response: signedTransactionResult(request.id) };
    },
  }));
  try {
    const driver = new SerialPortUsbDriver();
    await assert.rejects(
      () => driver.signTransaction(
        "/dev/cu.agentq-progress-mismatch",
        "session_abcdef",
        { operation: "sign_transaction", chain: "sui", method: "sign_transaction" },
        { network: "mainnet", txBytes: payload.toString("base64") },
        1000,
      ),
      (error) => error instanceof AgentQError && error.code === "protocol_error",
    );
    assert.equal(abortRequest.uploadId, "upload_progress_mismatch");
    assert.equal("payloadRef" in abortRequest, false);
  } finally {
    setSerialPortFactoryForTest(null);
  }
});

test("node USB rejects chunk capabilities below the staged deadline lower bound before upload", async () => {
  const payload = Buffer.alloc(PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES + 1, 0x5a);
  const advertisedChunkMaxBytes = PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES - 1;
  const seen = [];
  setSerialPortFactoryForTest(() => new FakeSerialPort({
    write: (request) => {
      seen.push(request.type);
      if (request.type === "get_capabilities") {
        return {
          response: capabilitiesResult(request.id, {
            payload: true,
            payloadCapability: { chunkMaxBytes: String(advertisedChunkMaxBytes) },
          }),
        };
      }
      return { response: signedTransactionResult(request.id) };
    },
  }));
  try {
    const driver = new SerialPortUsbDriver();
    await assert.rejects(
      () => driver.signTransaction(
        "/dev/cu.agentq-small-chunk-capability",
        "session_abcdef",
        { operation: "sign_transaction", chain: "sui", method: "sign_transaction" },
        { network: "mainnet", txBytes: payload.toString("base64") },
        1000,
      ),
      (error) => error instanceof AgentQError && error.code === "protocol_error",
    );
    assert.deepEqual(seen, ["get_capabilities"]);
  } finally {
    setSerialPortFactoryForTest(null);
  }
});

test("node USB rejects payloads above advertised payload max before upload", async () => {
  const payload = Buffer.alloc(PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES + 1, 0x33);
  const seen = [];
  setSerialPortFactoryForTest(() => new FakeSerialPort({
    write: (request) => {
      seen.push(request.type);
      if (request.type === "get_capabilities") {
        return {
          response: capabilitiesResult(request.id, {
            payload: true,
            payloadCapability: { payloadMaxBytes: String(PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES) },
          }),
        };
      }
      return { response: signedTransactionResult(request.id) };
    },
  }));
  try {
    const driver = new SerialPortUsbDriver();
    await assert.rejects(
      () => driver.signTransaction(
        "/dev/cu.agentq-payload-max-capability",
        "session_abcdef",
        { operation: "sign_transaction", chain: "sui", method: "sign_transaction" },
        { network: "mainnet", txBytes: payload.toString("base64") },
        1000,
      ),
      (error) => error instanceof AgentQError && error.code === "unsupported_payload_size",
    );
    assert.deepEqual(seen, ["get_capabilities"]);
  } finally {
    setSerialPortFactoryForTest(null);
  }
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

test("deadlineEnforcingDriver preserves signing success metadata before its deadline", async () => {
  const driver = {
    async signTransaction() {
      const request = signTransactionRequest();
      return requestSignResultWithRecovery(request, 1234, async (wireRequest, _deadlineMs, assertResponse) => {
        if (wireRequest.type === "sign_transaction") {
          throw markRequestMayHaveReachedFirmware(new AgentQError("transport_closed", "Transport closed.", true));
        }
        if (wireRequest.type === "get_result") {
          return assertResponse(signedTransactionResult(wireRequest.id));
        }
        if (wireRequest.type === "ack_result") {
          throw new AgentQError("invalid_session", "Session is unknown or already ended.", false);
        }
        throw new Error(`unexpected request: ${wireRequest.type}`);
      });
    },
  };
  const bounded = deadlineEnforcingDriver(driver);
  const result = await bounded.signTransaction(
    "/dev/cu.agentq-metadata",
    "session_abcdef",
    { operation: "sign_transaction", chain: "sui", method: "sign_transaction" },
    { network: "mainnet", txBytes: "AQID" },
    100,
  );

  assert.equal(result.status, "signed");
  assert.equal(consumeFirmwareSessionInvalidated(result), true);
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
