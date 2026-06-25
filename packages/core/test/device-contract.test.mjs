import assert from "node:assert/strict";
import test from "node:test";
import {
  DEVICE_ERROR_ROWS,
  DEVICE_METHOD_ROWS,
  DEVICE_RESPONSE_ENVELOPE_FIELDS,
  createCoreContractManifest,
  deviceErrorRow,
  makeDeviceError,
  makeDeviceFailureResponse,
  makeDeviceRequest,
  makeDeviceSuccessResponse,
  makeUnknownDeviceError,
  parseDeviceRequest,
  parseDeviceResponse,
  serializeDeviceRequest,
} from "../dist/device-contract.js";

test("validates DeviceRequest session and payload rules from the method table", () => {
  assert.deepEqual(parseDeviceRequest({
    id: "req_get_status",
    version: 1,
    method: "get_status",
  }), {
    id: "req_get_status",
    version: 1,
    method: "get_status",
  });

  assert.deepEqual(makeDeviceRequest({
    id: "req_sign",
    sessionId: "session_abc123",
    method: "sign_transaction",
    payload: { chain: "sui", network: "testnet", txBytes: "AA==" },
  }), {
    id: "req_sign",
    version: 1,
    sessionId: "session_abc123",
    method: "sign_transaction",
    payload: { chain: "sui", network: "testnet", txBytes: "AA==" },
  });

  assert.throws(
    () => parseDeviceRequest({ id: "req_missing_session", version: 1, method: "get_accounts" }),
    { code: "invalid_session" },
  );
  assert.throws(
    () => parseDeviceRequest({ id: "req_extra_session", version: 1, method: "get_status", sessionId: "session_abc123" }),
    { code: "invalid_request" },
  );
  assert.throws(
    () => parseDeviceRequest({ id: "req_missing_payload", version: 1, method: "connect" }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => parseDeviceRequest({ id: "req_undefined_payload", version: 1, method: "connect", payload: undefined }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => parseDeviceRequest({ id: "req_extra_payload", version: 1, method: "disconnect", sessionId: "session_abc123", payload: {} }),
    { code: "invalid_request" },
  );
  assert.throws(
    () => parseDeviceRequest({ id: "req_bad_method", version: 1, method: "debug_upload" }),
    { code: "unsupported_method" },
  );
  assert.throws(
    () => parseDeviceRequest({ id: "req_bad_version", version: 2, method: "get_status" }),
    { code: "unsupported_version" },
  );
});

test("serializes DeviceRequest through the same validation path", () => {
  assert.equal(
    serializeDeviceRequest({ id: "req_status", version: 1, method: "get_status" }),
    "{\"id\":\"req_status\",\"version\":1,\"method\":\"get_status\"}\n",
  );
  assert.throws(
    () => serializeDeviceRequest({ id: "bad id", version: 1, method: "get_status" }),
    { code: "invalid_request" },
  );
});

test("validates DeviceResponse envelope before method-specific result parsing", () => {
  let parseCount = 0;
  const response = parseDeviceResponse({
    id: "req_status",
    version: 1,
    success: true,
    method: "get_status",
    result: { device: { state: "idle" } },
  }, {
    expectedId: "req_status",
    expectedMethod: "get_status",
    resultParsers: {
      get_status(result) {
        parseCount += 1;
        return { parsed: result };
      },
    },
  });

  assert.equal(parseCount, 1);
  assert.deepEqual(response, {
    id: "req_status",
    version: 1,
    success: true,
    method: "get_status",
    result: { parsed: { device: { state: "idle" } } },
  });

  assert.throws(
    () => parseDeviceResponse({
      id: "req_status",
      version: 1,
      success: true,
      method: "unknown_method",
      result: {},
    }, {
      resultParsers: {
        get_status() {
          parseCount += 1;
          return {};
        },
      },
    }),
    { code: "invalid_response" },
  );
  assert.equal(parseCount, 1);
});

test("validates DeviceResponse failure errors against the single error table", () => {
  const timeout = deviceErrorRow("timeout");
  assert.deepEqual(parseDeviceResponse({
    id: "req_timeout",
    version: 1,
    success: false,
    method: "sign_transaction",
    error: { code: timeout.code, message: timeout.message, retryable: timeout.retryable },
  }), {
    id: "req_timeout",
    version: 1,
    success: false,
    method: "sign_transaction",
    error: { code: timeout.code, message: timeout.message, retryable: timeout.retryable },
  });

  assert.deepEqual(makeDeviceSuccessResponse({
    id: "req_ok",
    method: "get_status",
    result: { ok: true },
  }), {
    id: "req_ok",
    version: 1,
    success: true,
    method: "get_status",
    result: { ok: true },
  });

  assert.deepEqual(makeDeviceFailureResponse({
    id: "req_size",
    method: "sign_personal_message",
    code: "payload_too_large",
  }), {
    id: "req_size",
    version: 1,
    success: false,
    method: "sign_personal_message",
    error: makeDeviceError("payload_too_large"),
  });

  assert.throws(
    () => parseDeviceResponse({
      id: "req_bad_error",
      version: 1,
      success: false,
      method: "sign_transaction",
      error: { code: "timeout", message: "raw timeout", retryable: true },
    }),
    { code: "invalid_response" },
  );
});

test("builds public errors only from DeviceErrorCode outcomes", () => {
  const tableCodes = new Set(DEVICE_ERROR_ROWS.map((row) => row.code));
  assert.equal(tableCodes.size, DEVICE_ERROR_ROWS.length);

  for (const row of DEVICE_ERROR_ROWS) {
    assert.equal(typeof row.message, "string");
    assert.notEqual(row.message.length, 0);
    assert.equal(typeof row.retryable, "boolean");
    assert.deepEqual(makeDeviceError(row.code), {
      code: row.code,
      message: row.message,
      retryable: row.retryable,
    });
  }

  assert.deepEqual(makeUnknownDeviceError(), makeDeviceError("unknown_error"));

  assert.throws(
    () => makeDeviceFailureResponse({ code: "unsupported_payload_size" }),
    { code: "invalid_response" },
  );
  assert.throws(
    () => parseDeviceResponse({
      version: 1,
      success: false,
      error: { code: "raw_os_error", message: "raw", retryable: false },
    }),
    { code: "invalid_response" },
  );
});

test("generates the Core contract manifest from runtime contract sources", () => {
  const manifest = createCoreContractManifest();
  assert.equal(manifest.protocolVersion, 1);
  assert.equal(manifest.methods, DEVICE_METHOD_ROWS);
  assert.equal(manifest.errors, DEVICE_ERROR_ROWS);
  assert.equal(manifest.responseEnvelope, DEVICE_RESPONSE_ENVELOPE_FIELDS);
  assert.deepEqual(manifest.responseEnvelope.success, ["id", "version", "success", "method", "result"]);
  assert.deepEqual(manifest.responseEnvelope.failure, ["id", "version", "success", "method", "error"]);
  assert.deepEqual(manifest.responseEnvelope.error, ["code", "message", "retryable"]);
});
