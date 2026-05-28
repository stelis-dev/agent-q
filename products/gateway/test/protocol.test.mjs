import assert from "node:assert/strict";
import test from "node:test";
import {
  assertConnectResponse,
  assertDisconnectResponse,
  assertStatusResponse,
  createRequestId,
  isGatewayName,
  isSafeDeviceId,
  isSafeRequestId,
  isSessionId,
  makeConnectRequest,
  makeDisconnectRequest,
  makeIdentifyDeviceRequest,
  makeGetStatusRequest,
  MAX_SESSION_TTL_MS,
  parseProtocolResponse,
  sanitizeDisplayText,
  serializeRequest,
} from "../dist/protocol.js";

test("creates safe request ids and get_status requests", () => {
  const id = createRequestId();
  assert.equal(isSafeRequestId(id), true);
  assert.match(id, /^req_[0-9a-f]+$/);

  const request = makeGetStatusRequest(id);
  assert.deepEqual(request, {
    id,
    version: 1,
    type: "get_status",
  });
  assert.equal(serializeRequest(request), `${JSON.stringify(request)}\n`);
});

test("rejects unsafe request ids", () => {
  assert.equal(isSafeRequestId("req_ok-1.2"), true);
  assert.equal(isSafeRequestId(""), false);
  assert.equal(isSafeRequestId("req/unsafe"), false);
  assert.equal(isSafeRequestId("a".repeat(80)), false);
  assert.throws(() => makeGetStatusRequest("req/unsafe"), /Invalid request id/);
});

test("creates and parses identify_device messages", () => {
  const request = makeIdentifyDeviceRequest("1234", 10000, "req_identify");
  assert.deepEqual(request, {
    id: "req_identify",
    version: 1,
    type: "identify_device",
    params: {
      code: "1234",
      durationMs: 10000,
    },
  });

  const response = parseProtocolResponse(
    JSON.stringify({
      id: "req_identify",
      version: 1,
      type: "identify_device_result",
      status: "displayed",
      code: "1234",
      device: {
        deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
        state: "idle",
        firmwareName: "Agent-Q Firmware",
        hardware: "hardware-id",
        firmwareVersion: "0.0.0",
      },
    }),
    "req_identify",
  );

  assert.equal(response.type, "identify_device_result");
  assert.equal(response.code, "1234");
});

test("preserves Firmware protocol error codes", () => {
  for (const code of ["unsupported_type", "busy"]) {
    const response = parseProtocolResponse(
      JSON.stringify({
        id: "req_1",
        version: 1,
        type: "error",
        error: {
          code,
          message: `${code} message`,
        },
      }),
      "req_1",
    );

    assert.equal(response.type, "error");
    assert.equal(response.error.code, code);
    assert.throws(() => assertStatusResponse(response), {
      code,
    });
  }
});

test("parses status response and rejects incompatible version", () => {
  const response = parseProtocolResponse(
    JSON.stringify({
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
    }),
    "req_1",
  );

  assert.equal(response.type, "status");
  assert.equal(response.device.state, "idle");

  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_1",
          version: 2,
          type: "status",
          device: {},
        }),
        "req_1",
      ),
    /Unsupported protocol response version/,
  );
});

test("makeConnectRequest validates gatewayName and approvalTimeoutMs", () => {
  const request = makeConnectRequest("Agent-Q Gateway", 30000, "req_connect_1");
  assert.deepEqual(request, {
    id: "req_connect_1",
    version: 1,
    type: "connect",
    params: {
      gatewayName: "Agent-Q Gateway",
      approvalTimeoutMs: 30000,
    },
  });

  assert.throws(() => makeConnectRequest("", 30000), /gatewayName/);
  assert.throws(() => makeConnectRequest("a".repeat(65), 30000), /gatewayName/);
  assert.throws(() => makeConnectRequest("Hello ÿ", 30000), /gatewayName/);
  assert.throws(() => makeConnectRequest("Agent-Q Gateway", 0), /approvalTimeoutMs/);
  assert.throws(() => makeConnectRequest("Agent-Q Gateway", 60001), /approvalTimeoutMs/);
  assert.throws(() => makeConnectRequest("Agent-Q Gateway", 1.5), /approvalTimeoutMs/);
});

test("makeDisconnectRequest validates sessionId", () => {
  const request = makeDisconnectRequest("session_abcdef0123456789", "req_disconnect_1");
  assert.deepEqual(request, {
    id: "req_disconnect_1",
    version: 1,
    type: "disconnect",
    sessionId: "session_abcdef0123456789",
  });

  assert.throws(() => makeDisconnectRequest("not_a_session"), /Invalid sessionId/);
  assert.throws(() => makeDisconnectRequest("session_AABB"), /Invalid sessionId/);
  assert.throws(() => makeDisconnectRequest("session_"), /Invalid sessionId/);
});

test("parses connect_result approved and rejected responses", () => {
  const approved = parseProtocolResponse(
    JSON.stringify({
      id: "req_connect_1",
      version: 1,
      type: "connect_result",
      status: "approved",
      sessionId: "session_aabbccdd",
      sessionTtlMs: 1800000,
      device: {
        deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
        state: "idle",
        firmwareName: "Agent-Q Firmware",
        hardware: "hardware-id",
        firmwareVersion: "0.0.0",
      },
    }),
    "req_connect_1",
  );
  const approvedTyped = assertConnectResponse(approved);
  assert.equal(approvedTyped.status, "approved");
  assert.equal(approvedTyped.sessionId, "session_aabbccdd");
  assert.equal(approvedTyped.sessionTtlMs, 1800000);

  const rejected = parseProtocolResponse(
    JSON.stringify({
      id: "req_connect_1",
      version: 1,
      type: "connect_result",
      status: "rejected",
      error: {
        code: "rejected",
        message: "Connection rejected.",
      },
    }),
    "req_connect_1",
  );
  const rejectedTyped = assertConnectResponse(rejected);
  assert.equal(rejectedTyped.status, "rejected");
  assert.equal(rejectedTyped.error.code, "rejected");
});

test("rejects malformed connect_result", () => {
  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_connect_1",
          version: 1,
          type: "connect_result",
          status: "approved",
          sessionId: "not_session",
          sessionTtlMs: 1800000,
          device: {
            deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
            state: "idle",
            firmwareName: "Agent-Q Firmware",
            hardware: "hardware-id",
            firmwareVersion: "0.0.0",
          },
        }),
        "req_connect_1",
      ),
    /sessionId/,
  );
});

function approvedConnectLine(sessionTtlMs) {
  return JSON.stringify({
    id: "req_connect_1",
    version: 1,
    type: "connect_result",
    status: "approved",
    sessionId: "session_aabbccdd",
    sessionTtlMs,
    device: {
      deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
      state: "idle",
      firmwareName: "Agent-Q Firmware",
      hardware: "hardware-id",
      firmwareVersion: "0.0.0",
    },
  });
}

test("rejects a connect_result whose sessionTtlMs exceeds the uint32 wire range", () => {
  // A value past the protocol's uint32 ms range cannot come from a conformant
  // device. Rejecting it here (rather than recording it) keeps Gateway's
  // session-expiry date math from overflowing into a RangeError after approval.
  assert.throws(
    () => parseProtocolResponse(approvedConnectLine(MAX_SESSION_TTL_MS + 1), "req_connect_1"),
    /sessionTtlMs/,
  );
  assert.throws(
    () => parseProtocolResponse(approvedConnectLine(Number.MAX_SAFE_INTEGER), "req_connect_1"),
    /sessionTtlMs/,
  );
});

test("accepts a connect_result at the maximum representable sessionTtlMs", () => {
  const parsed = parseProtocolResponse(approvedConnectLine(MAX_SESSION_TTL_MS), "req_connect_1");
  const typed = assertConnectResponse(parsed);
  assert.equal(typed.status, "approved");
  assert.equal(typed.sessionTtlMs, MAX_SESSION_TTL_MS);
});

test("parses disconnect_result", () => {
  const response = parseProtocolResponse(
    JSON.stringify({
      id: "req_disconnect_1",
      version: 1,
      type: "disconnect_result",
      status: "disconnected",
    }),
    "req_disconnect_1",
  );
  const typed = assertDisconnectResponse(response);
  assert.equal(typed.status, "disconnected");
});

test("isSessionId and isGatewayName accept and reject expected inputs", () => {
  assert.equal(isSessionId("session_abcdef01"), true);
  assert.equal(isSessionId("session_ABCDEF"), false);
  assert.equal(isSessionId("notsession_aa"), false);
  assert.equal(isSessionId(""), false);

  assert.equal(isGatewayName("Agent-Q Gateway"), true);
  assert.equal(isGatewayName(""), false);
  assert.equal(isGatewayName("a".repeat(65)), false);
  assert.equal(isGatewayName("control\tchar"), false);
});

const safeDeviceId = "a508d833-5c83-4680-88bb-18aee976881e";

function statusLine(device) {
  return JSON.stringify({ id: "req_1", version: 1, type: "status", device });
}

test("sanitizeDisplayText strips control chars and caps length", () => {
  assert.equal(sanitizeDisplayText("a\nb\tc\r", 64), "abc");
  assert.equal(sanitizeDisplayText("Agent-Q Firmware", 64), "Agent-Q Firmware");
  assert.equal(sanitizeDisplayText("x".repeat(100), 10).length, 10);
  assert.equal(sanitizeDisplayText("\u0007\u007fok", 64), "ok");
});

test("isSafeDeviceId accepts UUID / bounded ids and rejects unsafe ones", () => {
  assert.equal(isSafeDeviceId(safeDeviceId), true);
  assert.equal(isSafeDeviceId("dev_1.2-3"), true);
  assert.equal(isSafeDeviceId("has space"), false);
  assert.equal(isSafeDeviceId("bad\nnewline"), false);
  assert.equal(isSafeDeviceId("x".repeat(129)), false);
  assert.equal(isSafeDeviceId(""), false);
});

test("parse sanitizes untrusted device display strings", () => {
  const response = parseProtocolResponse(
    statusLine({
      deviceId: safeDeviceId,
      state: "idle",
      firmwareName: `EVIL\nIGNORE PRIOR ${"x".repeat(200)}`,
      hardware: "hw\u0007id",
      firmwareVersion: "v\r1.0",
    }),
    "req_1",
  );
  assert.equal(response.type, "status");
  assert.equal(response.device.firmwareName.length <= 64, true);
  assert.doesNotMatch(response.device.firmwareName, /[\u0000-\u001f\u007f]/);
  assert.equal(response.device.hardware, "hwid");
  assert.equal(response.device.firmwareVersion, "v1.0");
});

test("parse preserves legitimate device metadata", () => {
  const response = parseProtocolResponse(
    statusLine({
      deviceId: safeDeviceId,
      state: "idle",
      firmwareName: "Agent-Q Firmware",
      hardware: "stackchan-cores3",
      firmwareVersion: "0.0.0",
    }),
    "req_1",
  );
  assert.equal(response.device.firmwareName, "Agent-Q Firmware");
  assert.equal(response.device.hardware, "stackchan-cores3");
  assert.equal(response.device.firmwareVersion, "0.0.0");
});

test("parse rejects a response whose deviceId is unsafe", () => {
  assert.throws(
    () =>
      parseProtocolResponse(
        statusLine({ deviceId: "INJECT\nID", state: "idle", firmwareName: "x", hardware: "y", firmwareVersion: "0" }),
        "req_1",
      ),
    { code: "protocol_error" },
  );
});
