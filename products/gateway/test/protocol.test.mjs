import assert from "node:assert/strict";
import test from "node:test";
import {
  assertStatusResponse,
  createRequestId,
  isSafeRequestId,
  makeIdentifyDeviceRequest,
  makeGetStatusRequest,
  parseProtocolResponse,
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
