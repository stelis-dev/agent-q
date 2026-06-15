import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  assertAccountsResponse,
  assertApprovalHistoryResponse,
  assertCapabilitiesResponse,
  assertPolicyResponse,
  assertPolicyProposeResultResponse,
  assertAckResultResponse,
  assertSignResultResponse,
  assertConnectResponse,
  assertDisconnectResponse,
  assertStatusResponse,
  createRequestId,
  FORBIDDEN_SECRET_FIELD_NAMES,
  isClientName,
  isSafeDeviceId,
  isSafeRequestId,
  isSessionId,
  isSuiAddressForPublicKey,
  identifySignRoute,
  makeConnectRequest,
  makeDisconnectRequest,
  makeGetCapabilitiesRequest,
  makeGetAccountsRequest,
  makeAckResultRequest,
  makeGetApprovalHistoryRequest,
  makeGetResultRequest,
  makePayloadUploadAbortRequest,
  makePayloadUploadBeginRequest,
  makePayloadUploadChunkRequest,
  makePayloadUploadFinishRequest,
  makePolicyGetRequest,
  makeIdentifyDeviceRequest,
  makeGetStatusRequest,
  makePolicyProposeRequest,
  makeStagedSignTransactionRequest,
  makeSignPersonalMessageRequest,
  makeSignTransactionRequest,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_POLICY_UPDATE_REQUEST_JSON_BYTES,
  MAX_SESSION_TTL_MS,
  MAX_SIGN_RESULT_PAYLOAD_BASE64_CHARS,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES,
  normalizePayloadUploadRequest,
  parseProtocolResponse,
  sanitizeDisplayText,
  serializeRequest,
} from "../dist/protocol.js";
import { normalizeRecoveryRequest } from "../dist/protocol-recovery.js";

const SIGN_ROUTE_VECTORS = readFileSync(
  new URL("../../../specs/sign-route-vectors.tsv", import.meta.url),
  "utf8",
)
  .split(/\r?\n/)
  .filter((line) => line && !line.startsWith("#"))
  .map((line) => {
    const [operation, chain, method, expected] = line.split("\t");
    return { operation, chain, method, expected };
  });

const POLICY_OPERATOR_ORDER = [
  "eq",
  "in",
  "not_in",
  "lte",
  "contains",
  "not_contains",
  "all_in",
  "none_in",
];

function parseFirmwarePolicyFieldDescriptors() {
  const source = readFileSync(
    new URL(
      "../../../firmware/src/common/agent_q/policy/agent_q_policy_document.cpp",
      import.meta.url,
    ),
    "utf8",
  );
  const descriptors = new Map();
  const rowPattern =
    /\{"([^"]+)", AgentQCurrentPolicyValueKind::([a-z0-9_]+), AgentQCurrentPolicyWhereTypeRequirement::[a-z0-9_]+, AgentQCurrentPolicyEvaluationKind::[a-z0-9_]+, (true|false), (true|false), (true|false), (true|false), (true|false), (true|false), (true|false), (true|false)\}/g;
  for (const match of source.matchAll(rowPattern)) {
    const [, field, type, ...allowed] = match;
    descriptors.set(field, {
      type,
      operators: POLICY_OPERATOR_ORDER.filter((_, index) => allowed[index] === "true"),
    });
  }
  assert.notEqual(descriptors.size, 0, "Firmware policy field descriptors parsed");
  return descriptors;
}

function parseCorePolicyFieldDescriptors() {
  const source = readFileSync(new URL("../src/protocol.ts", import.meta.url), "utf8");
  const table = source.match(/const CURRENT_POLICY_FIELD_DESCRIPTORS:[\s\S]*?= \{([\s\S]*?)\n\};/);
  assert.notEqual(table, null, "Core policy field descriptor table exists");
  const descriptors = new Map();
  const rowPattern =
    /"([^"]+)": \{ type: "([^"]+)", operators: \[([^\]]*)\](?:, whereType: "required")? \}/g;
  for (const match of table[1].matchAll(rowPattern)) {
    const [, field, type, operators] = match;
    descriptors.set(field, {
      type,
      operators: [...operators.matchAll(/"([^"]+)"/g)].map((operator) => operator[1]),
    });
  }
  assert.notEqual(descriptors.size, 0, "Core policy field descriptors parsed");
  return descriptors;
}

function parseDocumentedPolicyFieldOperators() {
  const source = readFileSync(new URL("../../../docs/POLICY_SCHEMA.md", import.meta.url), "utf8");
  const descriptors = new Map();
  for (const line of source.split(/\r?\n/)) {
    const columns = line.split("|").map((column) => column.trim()).filter(Boolean);
    if (columns.length !== 3 || !columns[0].startsWith("`sui.")) {
      continue;
    }
    const field = columns[0].replaceAll("`", "");
    const operators = columns[2].split(",").map((operator) => operator.trim().replaceAll("`", ""));
    descriptors.set(field, { operators });
  }
  assert.notEqual(descriptors.size, 0, "documented policy field table parsed");
  return descriptors;
}

const CANONICAL_TX_BYTES_BASE64 = "AQID";
const VALID_PAYLOAD_DIGEST = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const VALID_PAYLOAD_REF = "payload_0123456789abcdef01234567";
const VALID_UPLOAD_ID = "upload_0123456789abcdef01234567";
const VALID_DEVICE_STATUS = {
  deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
  state: "idle",
  firmwareName: "Agent-Q Firmware",
  hardware: "hardware-id",
  firmwareVersion: "0.0.0",
};

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

test("builds retained-result recovery requests with the original signing request id", () => {
  const sessionId = "session_abcdef";
  const requestId = "req_original_sign";
  assert.deepEqual(makeGetResultRequest(sessionId, requestId), {
    id: requestId,
    version: 1,
    type: "get_result",
    sessionId,
  });
  assert.deepEqual(makeAckResultRequest(sessionId, requestId), {
    id: requestId,
    version: 1,
    type: "ack_result",
    sessionId,
  });
});

test("recovery request normalizer exact-validates get_result and ack_result", () => {
  assert.deepEqual(normalizeRecoveryRequest({
    id: "req_sign",
    version: 1,
    type: "get_result",
    sessionId: "session_abcdef",
  }), {
    id: "req_sign",
    version: 1,
    type: "get_result",
    sessionId: "session_abcdef",
  });

  assert.throws(
    () => normalizeRecoveryRequest({
      id: "req_sign",
      version: 1,
      type: "ack_result",
      sessionId: "session_abcdef",
      extra: true,
    }),
    { code: "protocol_error" },
  );
});

test("parseProtocolResponse accepts and exact-validates ack_result as full protocol", () => {
  const response = assertAckResultResponse(parseProtocolResponse(JSON.stringify({
    id: "req_sign",
    version: 1,
    type: "ack_result",
    status: "acked",
  }), "req_sign"));
  assert.deepEqual(response, {
    id: "req_sign",
    version: 1,
    type: "ack_result",
    status: "acked",
  });

  assert.throws(
    () => parseProtocolResponse(JSON.stringify({
      id: "req_sign",
      version: 1,
      type: "ack_result",
      status: "acked",
      extra: true,
    }), "req_sign"),
    { code: "protocol_error" },
  );

  assert.throws(
    () => assertAckResultResponse({
      id: "req_sign",
      version: 2,
      type: "ack_result",
      status: "acked",
    }),
    { code: "protocol_error" },
  );

  assert.throws(
    () => assertAckResultResponse({
      id: "req_sign",
      version: 1,
      type: "ack_result",
      status: "not_acked",
    }),
    { code: "protocol_error" },
  );
});

test("builds and exact-normalizes payload upload requests", () => {
  const sessionId = "session_abcdef0123456789";

  const begin = makePayloadUploadBeginRequest(
    sessionId,
    "sui",
    "sign_transaction",
    { payloadKind: "transaction", sizeBytes: "131072", payloadDigest: VALID_PAYLOAD_DIGEST },
    "req_upload_begin",
  );
  assert.deepEqual(begin, {
    id: "req_upload_begin",
    version: 1,
    type: "payload_upload_begin",
    sessionId,
    chain: "sui",
    method: "sign_transaction",
    payloadKind: "transaction",
    sizeBytes: "131072",
    payloadDigest: VALID_PAYLOAD_DIGEST,
  });
  assert.deepEqual(normalizePayloadUploadRequest(begin), begin);

  const chunk = makePayloadUploadChunkRequest(
    sessionId,
    VALID_UPLOAD_ID,
    "3",
    CANONICAL_TX_BYTES_BASE64,
    "req_upload_chunk",
  );
  assert.deepEqual(chunk, {
    id: "req_upload_chunk",
    version: 1,
    type: "payload_upload_chunk",
    sessionId,
    uploadId: VALID_UPLOAD_ID,
    offsetBytes: "3",
    chunk: CANONICAL_TX_BYTES_BASE64,
  });
  assert.deepEqual(normalizePayloadUploadRequest(chunk), chunk);

  const finish = makePayloadUploadFinishRequest(sessionId, VALID_UPLOAD_ID, "req_upload_finish");
  assert.deepEqual(finish, {
    id: "req_upload_finish",
    version: 1,
    type: "payload_upload_finish",
    sessionId,
    uploadId: VALID_UPLOAD_ID,
  });
  assert.deepEqual(normalizePayloadUploadRequest(finish), finish);

  const abortUpload = makePayloadUploadAbortRequest(sessionId, { uploadId: VALID_UPLOAD_ID }, "req_upload_abort");
  assert.deepEqual(normalizePayloadUploadRequest(abortUpload), abortUpload);
  const abortPayload = makePayloadUploadAbortRequest(sessionId, { payloadRef: VALID_PAYLOAD_REF }, "req_payload_abort");
  assert.deepEqual(normalizePayloadUploadRequest(abortPayload), abortPayload);

  assert.throws(
    () => normalizePayloadUploadRequest({ ...begin, extra: true }),
    { code: "protocol_error" },
  );
  assert.throws(
    () => makePayloadUploadAbortRequest(sessionId, { uploadId: VALID_UPLOAD_ID, payloadRef: VALID_PAYLOAD_REF }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => makePayloadUploadBeginRequest(sessionId, "evm", "sign_transaction", {
      payloadKind: "transaction",
      sizeBytes: "1",
      payloadDigest: VALID_PAYLOAD_DIGEST,
    }),
    { code: "unsupported_chain" },
  );
  assert.throws(
    () => makePayloadUploadBeginRequest(sessionId, "evm", "sign_transaction", {
      payloadKind: "message",
      sizeBytes: "not-decimal",
      payloadDigest: "not-digest",
    }),
    { code: "unsupported_chain" },
  );
  assert.throws(
    () => makePayloadUploadBeginRequest(sessionId, "sui", "sign_personal_message", {
      payloadKind: "transaction",
      sizeBytes: "1",
      payloadDigest: VALID_PAYLOAD_DIGEST,
    }),
    { code: "unsupported_method" },
  );
  assert.throws(
    () => makePayloadUploadBeginRequest(sessionId, "sui", "future_method", {
      payloadKind: "message",
      sizeBytes: "not-decimal",
      payloadDigest: "not-digest",
    }),
    { code: "unsupported_method" },
  );
  assert.throws(
    () => makePayloadUploadBeginRequest(sessionId, "SUI", "sign_transaction", {
      payloadKind: "transaction",
      sizeBytes: "1",
      payloadDigest: VALID_PAYLOAD_DIGEST,
    }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => makePayloadUploadBeginRequest(sessionId, "sui", "sign_transaction", {
      payloadKind: "message",
      sizeBytes: "1",
      payloadDigest: VALID_PAYLOAD_DIGEST,
    }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => makePayloadUploadBeginRequest(sessionId, "sui", "sign_transaction", {
      payloadKind: "transaction",
      sizeBytes: "18446744073709551616",
      payloadDigest: VALID_PAYLOAD_DIGEST,
    }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => makePayloadUploadChunkRequest(
      sessionId,
      VALID_UPLOAD_ID,
      "18446744073709551616",
      CANONICAL_TX_BYTES_BASE64,
    ),
    { code: "invalid_params" },
  );
});

test("payload upload chunk frame budget fits the advertised transport chunk size", () => {
  const maxRequestId = "r".repeat(79);
  const maxSessionId = `session_${"a".repeat(128)}`;
  const maxUploadId = `upload_${"b".repeat(72)}`;
  const maxUint64Offset = "18446744073709551615";
  const advertisedChunk = Buffer.alloc(2700, 7).toString("base64");
  const request = makePayloadUploadChunkRequest(
    maxSessionId,
    maxUploadId,
    maxUint64Offset,
    advertisedChunk,
    maxRequestId,
  );

  assert.equal(Buffer.from(advertisedChunk, "base64").length, 2700);
  assert.ok(Buffer.byteLength(JSON.stringify(request), "utf8") <= MAX_RAW_PROTOCOL_JSON_BYTES);
  assert.ok(Buffer.byteLength(serializeRequest(request), "utf8") <= MAX_RAW_PROTOCOL_JSON_BYTES + 1);
  assert.deepEqual(normalizePayloadUploadRequest(request), request);
});

test("builds staged sign_transaction requests without txBytes", () => {
  const request = makeStagedSignTransactionRequest(
    "session_abcdef0123456789",
    "sui",
    "sign_transaction",
    {
      network: "mainnet",
      payloadRef: VALID_PAYLOAD_REF,
      payloadKind: "transaction",
      sizeBytes: "131072",
      payloadDigest: VALID_PAYLOAD_DIGEST,
    },
    "req_staged_sign",
  );
  assert.deepEqual(request, {
    id: "req_staged_sign",
    version: 1,
    type: "sign_transaction",
    sessionId: "session_abcdef0123456789",
    chain: "sui",
    method: "sign_transaction",
    params: {
      network: "mainnet",
      payloadRef: VALID_PAYLOAD_REF,
      payloadKind: "transaction",
      sizeBytes: "131072",
      payloadDigest: VALID_PAYLOAD_DIGEST,
    },
  });
  assert.equal("txBytes" in request.params, false);
  assert.throws(
    () => makeStagedSignTransactionRequest(
      "session_abcdef0123456789",
      "sui",
      "sign_transaction",
      {
        network: "mainnet",
        payloadRef: VALID_PAYLOAD_REF,
        payloadKind: "transaction",
        sizeBytes: "131072",
        payloadDigest: VALID_PAYLOAD_DIGEST,
        txBytes: CANONICAL_TX_BYTES_BASE64,
      },
    ),
    { code: "protocol_error" },
  );
  assert.throws(
    () => makeStagedSignTransactionRequest(
      "session_abcdef0123456789",
      "sui",
      "sign_transaction",
      { network: "mainnet", payloadRef: VALID_PAYLOAD_REF },
    ),
    { code: "invalid_params" },
  );
  assert.throws(
    () => makeStagedSignTransactionRequest(
      "session_abcdef0123456789",
      "sui",
      "sign_transaction",
      {
        network: "mainnet",
        payloadRef: VALID_PAYLOAD_REF,
        payloadKind: "transaction",
        sizeBytes: "18446744073709551616",
        payloadDigest: VALID_PAYLOAD_DIGEST,
      },
    ),
    { code: "invalid_params" },
  );
});

test("parseProtocolResponse accepts and exact-validates payload upload responses", () => {
  const begin = parseProtocolResponse(JSON.stringify({
    id: "req_upload_begin",
    version: 1,
    type: "payload_upload_begin_result",
    uploadId: VALID_UPLOAD_ID,
    receivedBytes: "0",
    chunkMaxBytes: "2048",
  }), "req_upload_begin");
  assert.equal(begin.type, "payload_upload_begin_result");
  assert.equal(begin.uploadId, VALID_UPLOAD_ID);
  assert.throws(
    () => parseProtocolResponse(JSON.stringify({
      id: "req_upload_begin",
      version: 1,
      type: "payload_upload_begin_result",
      uploadId: VALID_UPLOAD_ID,
      receivedBytes: "0",
      chunkMaxBytes: "2047",
    }), "req_upload_begin"),
    { code: "protocol_error" },
  );

  const chunk = parseProtocolResponse(JSON.stringify({
    id: "req_upload_chunk",
    version: 1,
    type: "payload_upload_chunk_result",
    receivedBytes: "3",
  }), "req_upload_chunk");
  assert.equal(chunk.type, "payload_upload_chunk_result");
  assert.equal(chunk.receivedBytes, "3");

  const finish = parseProtocolResponse(JSON.stringify({
    id: "req_upload_finish",
    version: 1,
    type: "payload_upload_finish_result",
    payloadRef: VALID_PAYLOAD_REF,
    chain: "sui",
    method: "sign_transaction",
    payloadKind: "transaction",
    sizeBytes: "131072",
    payloadDigest: VALID_PAYLOAD_DIGEST,
  }), "req_upload_finish");
  assert.equal(finish.type, "payload_upload_finish_result");
  assert.equal(finish.payloadRef, VALID_PAYLOAD_REF);

  const abort = parseProtocolResponse(JSON.stringify({
    id: "req_payload_abort",
    version: 1,
    type: "payload_upload_abort_result",
    status: "aborted",
  }), "req_payload_abort");
  assert.equal(abort.type, "payload_upload_abort_result");

  assert.throws(
    () => parseProtocolResponse(JSON.stringify({
      id: "req_upload_finish",
      version: 1,
      type: "payload_upload_finish_result",
      payloadRef: VALID_PAYLOAD_REF,
      chain: "sui",
      method: "sign_transaction",
      payloadKind: "transaction",
      sizeBytes: "131072",
      payloadDigest: VALID_PAYLOAD_DIGEST,
      txBytes: CANONICAL_TX_BYTES_BASE64,
    }), "req_upload_finish"),
    { code: "protocol_error" },
  );
  for (const routePatch of [
    { chain: "evm", method: "sign_transaction" },
    { chain: "sui", method: "sign_personal_message" },
  ]) {
    assert.throws(
      () => parseProtocolResponse(JSON.stringify({
        id: "req_upload_finish",
        version: 1,
        type: "payload_upload_finish_result",
        payloadRef: VALID_PAYLOAD_REF,
        chain: routePatch.chain,
        method: routePatch.method,
        payloadKind: "transaction",
        sizeBytes: "131072",
        payloadDigest: VALID_PAYLOAD_DIGEST,
      }), "req_upload_finish"),
      { code: "protocol_error" },
    );
  }
});

test("identifySignRoute matches the shared protocol route vectors", () => {
  for (const vector of SIGN_ROUTE_VECTORS) {
    if (vector.expected === "ok") {
      const route = identifySignRoute(vector.operation, vector.chain, vector.method);
      assert.equal(route.operation, vector.operation);
      assert.equal(route.chain, vector.chain);
      assert.equal(route.method, vector.method);
      continue;
    }
    assert.throws(
      () => identifySignRoute(vector.operation, vector.chain, vector.method),
      { code: vector.expected },
      `${vector.operation}/${vector.chain}/${vector.method}`,
    );
  }
});

test("creates and parses identify_device messages", () => {
  const request = makeIdentifyDeviceRequest("1234", "req_identify");
  assert.deepEqual(request, {
    id: "req_identify",
    version: 1,
    type: "identify_device",
    params: {
      code: "1234",
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
  for (const code of [
    "unsupported_type",
    "busy",
    "invalid_state",
    "invalid_method",
    "invalid_params",
    "request_id_conflict",
    "unsupported_chain",
    "unsupported_method",
    "unsupported_payload_size",
    "malformed_transaction",
    "policy_error",
    "rng_error",
    "account_error",
    "history_error",
  ]) {
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

test("parseProtocolResponse rejects unsupported fields in canonical response envelopes", () => {
  const rejectedResponses = [
    {
      id: "req_error",
      version: 1,
      type: "error",
      sessionId: "session_should_not_pass",
      error: {
        code: "invalid_session",
        message: "Invalid session.",
      },
    },
    {
      id: "req_error",
      version: 1,
      type: "error",
      error: {
        code: "invalid_session",
        message: "Invalid session.",
        sessionId: "session_should_not_pass",
      },
    },
    {
      id: "req_status",
      version: 1,
      type: "status",
      device: VALID_DEVICE_STATUS,
      provisioning: { state: "provisioned" },
      sessionId: "session_should_not_pass",
    },
    {
      id: "req_status",
      version: 1,
      type: "status",
      device: { ...VALID_DEVICE_STATUS, sessionId: "session_should_not_pass" },
      provisioning: { state: "provisioned" },
    },
    {
      id: "req_status",
      version: 1,
      type: "status",
      device: VALID_DEVICE_STATUS,
      provisioning: { state: "provisioned", sessionId: "session_should_not_pass" },
    },
    {
      id: "req_identify",
      version: 1,
      type: "identify_device_result",
      status: "displayed",
      code: "1234",
      device: VALID_DEVICE_STATUS,
      sessionId: "session_should_not_pass",
    },
    {
      id: "req_identify",
      version: 1,
      type: "identify_device_result",
      status: "displayed",
      code: "1234",
      device: { ...VALID_DEVICE_STATUS, sessionId: "session_should_not_pass" },
    },
    {
      id: "req_connect",
      version: 1,
      type: "connect_result",
      status: "approved",
      sessionId: "session_abcdef0123456789",
      sessionTtlMs: 30000,
      device: VALID_DEVICE_STATUS,
      privateKey: "must-not-pass",
    },
    {
      id: "req_connect",
      version: 1,
      type: "connect_result",
      status: "approved",
      sessionId: "session_abcdef0123456789",
      sessionTtlMs: 30000,
      device: { ...VALID_DEVICE_STATUS, privateKey: "must-not-pass" },
    },
    {
      id: "req_connect",
      version: 1,
      type: "connect_result",
      status: "rejected",
      error: {
        code: "rejected",
        message: "Rejected.",
        sessionId: "session_should_not_pass",
      },
    },
    {
      id: "req_disconnect",
      version: 1,
      type: "disconnect_result",
      status: "disconnected",
      sessionId: "session_should_not_pass",
    },
  ];

  for (const response of rejectedResponses) {
    assert.throws(
      () => parseProtocolResponse(JSON.stringify(response), response.id),
      { code: "protocol_error" },
      `${response.type} with unsupported fields must fail closed`,
    );
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
      provisioning: {
        state: "unprovisioned",
      },
    }),
    "req_1",
  );

  assert.equal(response.type, "status");
  assert.equal(response.device.state, "idle");
  assert.equal(response.provisioning.state, "unprovisioned");

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

test("parses busy status while setup material is displayed", () => {
  const response = assertStatusResponse(
    parseProtocolResponse(
      JSON.stringify({
        id: "req_busy",
        version: 1,
        type: "status",
        device: {
          deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
          state: "busy",
          firmwareName: "Agent-Q Firmware",
          hardware: "hardware-id",
          firmwareVersion: "0.0.0",
        },
        provisioning: {
          state: "unprovisioned",
        },
      }),
      "req_busy",
    ),
  );

  assert.equal(response.device.state, "busy");
  assert.equal(response.provisioning.state, "unprovisioned");
});

test("parses consistency-error provisioning status", () => {
  const response = assertStatusResponse(
    parseProtocolResponse(
      JSON.stringify({
        id: "req_error",
        version: 1,
        type: "status",
        device: {
          deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
          state: "error",
          firmwareName: "Agent-Q Firmware",
          hardware: "hardware-id",
          firmwareVersion: "0.0.0",
        },
        provisioning: {
          state: "error",
        },
      }),
      "req_error",
    ),
  );

  assert.equal(response.device.state, "error");
  assert.equal(response.provisioning.state, "error");
});

test("status response requires provisioning and rejects invalid provisioning state", () => {
  for (const provisioning of [undefined, { state: "signing_ready" }]) {
    assert.throws(
      () =>
        parseProtocolResponse(
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
            ...(provisioning === undefined ? {} : { provisioning }),
          }),
          "req_1",
        ),
      { code: "protocol_error" },
    );
  }
});

test("makeConnectRequest validates clientName", () => {
  const request = makeConnectRequest("Agent-Q", "req_connect_1");
  assert.deepEqual(request, {
    id: "req_connect_1",
    version: 1,
    type: "connect",
    params: {
      clientName: "Agent-Q",
    },
  });

  assert.throws(() => makeConnectRequest(""), /clientName/);
  assert.throws(() => makeConnectRequest("a".repeat(65)), /clientName/);
  assert.throws(() => makeConnectRequest("Hello ÿ"), /clientName/);
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

test("makeGetAccountsRequest validates sessionId", () => {
  const request = makeGetAccountsRequest("session_abcdef0123456789", "req_get_accounts_1");
  assert.deepEqual(request, {
    id: "req_get_accounts_1",
    version: 1,
    type: "get_accounts",
    sessionId: "session_abcdef0123456789",
  });

  assert.throws(() => makeGetAccountsRequest("not_a_session"), /Invalid sessionId/);
  assert.throws(() => makeGetAccountsRequest("session_"), /Invalid sessionId/);
});

test("makePolicyGetRequest validates sessionId", () => {
  const request = makePolicyGetRequest("session_abcdef0123456789", "req_policy_get_1");
  assert.deepEqual(request, {
    id: "req_policy_get_1",
    version: 1,
    type: "policy_get",
    sessionId: "session_abcdef0123456789",
  });

  assert.throws(() => makePolicyGetRequest("not_a_session"), /Invalid sessionId/);
  assert.throws(() => makePolicyGetRequest("session_"), /Invalid sessionId/);
});

test("makeGetApprovalHistoryRequest validates session and pagination params", () => {
  const request = makeGetApprovalHistoryRequest(
    "session_abcdef0123456789",
    { limit: 2, beforeSeq: "42" },
    "req_get_approval_history_1",
  );
  assert.deepEqual(request, {
    id: "req_get_approval_history_1",
    version: 1,
    type: "get_approval_history",
    sessionId: "session_abcdef0123456789",
    params: {
      limit: 2,
      beforeSeq: "42",
    },
  });

  assert.throws(() => makeGetApprovalHistoryRequest("not_a_session"), /sessionId/);
  assert.throws(() => makeGetApprovalHistoryRequest("session_abcdef0123456789", { limit: 0 }), /limit/);
  assert.throws(() => makeGetApprovalHistoryRequest("session_abcdef0123456789", { limit: 5 }), /limit/);
  assert.throws(
    () => makeGetApprovalHistoryRequest("session_abcdef0123456789", { beforeSeq: "not-number" }),
    /beforeSeq/,
  );
  assert.throws(
    () => makeGetApprovalHistoryRequest("session_abcdef0123456789", { beforeSeq: "18446744073709551616" }),
    /beforeSeq/,
  );
});

test("makeSignTransactionRequest builds bounded signing params without caller-selected authorization", () => {
  const params = { network: "devnet", txBytes: CANONICAL_TX_BYTES_BASE64 };
  const request = makeSignTransactionRequest(
    "session_abcdef0123456789",
    "sui",
    "sign_transaction",
    params,
    "req_sign_transaction_1",
  );
  assert.deepEqual(request, {
    id: "req_sign_transaction_1",
    version: 1,
    type: "sign_transaction",
    sessionId: "session_abcdef0123456789",
    chain: "sui",
    method: "sign_transaction",
    params,
  });

  assert.throws(() => makeSignTransactionRequest("not_a_session", "sui", "sign_transaction", params), /sessionId/);
  assert.throws(
    () => makeSignTransactionRequest("not_a_session", "evm", "sign_transaction", params),
    { code: "unsupported_chain" },
  );
  assert.throws(
    () => makeSignTransactionRequest("session_abcdef0123456789", "sui", "sign_personal_message", params),
    { code: "unsupported_method" },
  );
  assert.throws(
    () => makeSignTransactionRequest("session_abcdef0123456789", "sui", "sign_transaction", { ...params, timeoutMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => makeSignTransactionRequest("session_abcdef0123456789", "sui", "sign_transaction", { ...params, approvalTimeoutMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => makeSignTransactionRequest("session_abcdef0123456789", "sui", "sign_transaction", { ...params, durationMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => makeSignTransactionRequest("session_abcdef0123456789", "sui", "sign_transaction", { ...params, privateKey: "must-not-forward" }),
    /secret material/,
  );
  const aboveCurrentAdapterCapacity = Buffer.alloc(385, 1).toString("base64");
  assert.equal(
    makeSignTransactionRequest(
      "session_abcdef0123456789",
      "sui",
      "sign_transaction",
      { network: "devnet", txBytes: aboveCurrentAdapterCapacity },
    ).params.txBytes,
    aboveCurrentAdapterCapacity,
  );
  assert.throws(
    () => makeSignTransactionRequest(
      "session_abcdef0123456789",
      "sui",
      "sign_transaction",
      { network: "devnet", txBytes: Buffer.alloc(MAX_SUI_SIGN_TRANSACTION_TX_BYTES + 1).toString("base64") },
    ),
    /maximum decoded byte length/,
  );
});

test("makeSignPersonalMessageRequest builds bounded personal-message params without caller-selected authorization", () => {
  const params = { network: "devnet", message: Buffer.from("hello Agent-Q").toString("base64") };
  const request = makeSignPersonalMessageRequest(
    "session_abcdef0123456789",
    "sui",
    "sign_personal_message",
    params,
    "req_sign_message_1",
  );
  assert.deepEqual(request, {
    id: "req_sign_message_1",
    version: 1,
    type: "sign_personal_message",
    sessionId: "session_abcdef0123456789",
    chain: "sui",
    method: "sign_personal_message",
    params,
  });

  assert.throws(() => makeSignPersonalMessageRequest("not_a_session", "sui", "sign_personal_message", params), /sessionId/);
  assert.throws(
    () => makeSignPersonalMessageRequest("session_abcdef0123456789", "sui", "sign_transaction", params),
    { code: "unsupported_method" },
  );
  assert.throws(
    () => makeSignPersonalMessageRequest("session_abcdef0123456789", "sui", "sign_personal_message", { ...params, timeoutMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => makeSignPersonalMessageRequest("session_abcdef0123456789", "sui", "sign_personal_message", { ...params, authorization: "user" }),
    /unsupported fields/,
  );
  assert.throws(
    () => makeSignPersonalMessageRequest("session_abcdef0123456789", "sui", "sign_personal_message", { ...params, seed: "must-not-forward" }),
    /secret material/,
  );
  const aboveCurrentAdapterCapacity = Buffer.alloc(257, 1).toString("base64");
  assert.equal(
    makeSignPersonalMessageRequest(
      "session_abcdef0123456789",
      "sui",
      "sign_personal_message",
      { network: "devnet", message: aboveCurrentAdapterCapacity },
    ).params.message,
    aboveCurrentAdapterCapacity,
  );
});

test("makePolicyProposeRequest builds admin proposal requests without chain authority", () => {
  const policy = {
    schema: "agentq.policy",
    defaultAction: "reject",
    blockchains: [
      {
        blockchain: "sui",
        networks: [
          {
            network: "testnet",
            policies: [
              {
                id: "reject_devnet",
                action: "reject",
                conditions: [{ field: "sui.command_kinds", op: "not_contains", values: ["publish"] }],
              },
            ],
          },
        ],
      },
    ],
  };
  const request = makePolicyProposeRequest(
    "session_abcdef0123456789",
    policy,
    "req_policy_propose_1",
  );
  assert.deepEqual(request, {
    id: "req_policy_propose_1",
    version: 1,
    type: "policy_propose",
    sessionId: "session_abcdef0123456789",
    params: { policy },
  });
  assert.equal("chain" in request, false);
  assert.ok(Buffer.byteLength(serializeRequest(request), "utf8") <= 4097);

  const longRejectValue = "x".repeat(256);
  const largePolicy = {
    schema: "agentq.policy",
    defaultAction: "reject",
    blockchains: [
      {
        blockchain: "sui",
        networks: [
          {
            network: "testnet",
            policies: Array.from({ length: 16 }, (_, index) => ({
              id: `reject_big_${index}`,
              action: "reject",
              conditions: [{ field: "sui.command_kinds", op: "not_contains", values: [longRejectValue] }],
            })),
          },
        ],
      },
    ],
  };
  const largeRequest = makePolicyProposeRequest(
    "session_abcdef0123456789",
    largePolicy,
    "req_policy_propose_big",
  );
  const largeRequestBytes = Buffer.byteLength(serializeRequest(largeRequest), "utf8");
  assert.ok(largeRequestBytes > MAX_RAW_PROTOCOL_JSON_BYTES);
  assert.ok(largeRequestBytes <= MAX_POLICY_UPDATE_REQUEST_JSON_BYTES + 1);

  assert.throws(
    () => makePolicyProposeRequest("not_a_session", policy),
    /sessionId/,
  );
  assert.throws(
    () => makePolicyProposeRequest("session_abcdef0123456789", []),
    /policy_propose/,
  );
  assert.throws(
    () => makePolicyProposeRequest("session_abcdef0123456789", { seed: "must-not-forward" }),
    /secret material/,
  );
  assert.throws(
    () => makePolicyProposeRequest("session_abcdef0123456789", { data: "x".repeat(20000) }),
    /too large/,
  );
});

test("makeGetCapabilitiesRequest validates sessionId", () => {
  const request = makeGetCapabilitiesRequest("session_abcdef0123456789", "req_get_capabilities_1");
  assert.deepEqual(request, {
    id: "req_get_capabilities_1",
    version: 1,
    type: "get_capabilities",
    sessionId: "session_abcdef0123456789",
  });

  assert.throws(() => makeGetCapabilitiesRequest("not_a_session"), /Invalid sessionId/);
  assert.throws(() => makeGetCapabilitiesRequest("session_"), /Invalid sessionId/);
});

const capabilitiesLine = (chainOverrides = {}, accountOverrides = {}, responseOverrides = {}) =>
  JSON.stringify({
    id: "req_capabilities",
    version: 1,
    type: "capabilities",
    chains: [
      {
        id: "sui",
        accounts: [
          {
            keyScheme: "ed25519",
            derivationPath: "m/44'/784'/0'/0'/0'",
            ...accountOverrides,
          },
        ],
        methods: [],
        ...chainOverrides,
      },
    ],
    ...responseOverrides,
  });

test("parseProtocolResponse accepts a valid capabilities response with signing metadata", () => {
  for (const signing of [
    {
      authorization: "policy",
      methods: [{ chain: "sui", method: "sign_transaction" }],
    },
    {
      authorization: "user",
      methods: [
        { chain: "sui", method: "sign_transaction" },
        { chain: "sui", method: "sign_personal_message" },
      ],
    },
  ]) {
    const response = assertCapabilitiesResponse(
      parseProtocolResponse(
        capabilitiesLine({}, {}, { signing }),
        "req_capabilities",
      ),
    );
    assert.equal(response.type, "capabilities");
    assert.equal(response.chains.length, 1);
    assert.equal(response.chains[0].id, "sui");
    assert.equal(response.chains[0].accounts.length, 1);
    assert.equal(response.chains[0].accounts[0].keyScheme, "ed25519");
    assert.equal(response.chains[0].accounts[0].derivationPath, "m/44'/784'/0'/0'/0'");
    assert.deepEqual(response.chains[0].methods, []);
    assert.deepEqual(response.signing, signing);
  }
});

test("parseProtocolResponse preserves sign_transaction payload capability metadata", () => {
  const payload = {
    kind: "transaction",
    inlineMaxBytes: "384",
    chunkMaxBytes: "2048",
    payloadMaxBytes: "131072",
  };
  const signing = {
    authorization: "user",
    methods: [
      { chain: "sui", method: "sign_transaction", payload },
      { chain: "sui", method: "sign_personal_message" },
    ],
  };
  const response = assertCapabilitiesResponse(
    parseProtocolResponse(capabilitiesLine({}, {}, { signing }), "req_capabilities"),
  );
  assert.deepEqual(response.signing, signing);
  assert.throws(
    () => parseProtocolResponse(
      capabilitiesLine({}, {}, {
        signing: {
          authorization: "user",
          methods: [
            {
              chain: "sui",
              method: "sign_transaction",
              payload: { ...payload, chunkMaxBytes: "2047" },
            },
          ],
        },
      }),
      "req_capabilities",
    ),
    { code: "protocol_error" },
  );

  assert.throws(
    () => parseProtocolResponse(
      capabilitiesLine({}, {}, {
        signing: {
          authorization: "user",
          methods: [
            { chain: "sui", method: "sign_transaction" },
            { chain: "sui", method: "sign_personal_message", payload },
          ],
        },
      }),
      "req_capabilities",
    ),
    { code: "protocol_error" },
  );
});

test("parseProtocolResponse rejects unsupported capabilities", () => {
  assert.throws(
    () => parseProtocolResponse(capabilitiesLine({ id: "ethereum" }), "req_capabilities"),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(capabilitiesLine({ methods: ["sign_transaction"] }), "req_capabilities"),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(capabilitiesLine({ methods: ["sign_transaction", "sign_personal_message"] }), "req_capabilities"),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(capabilitiesLine({}, { keyScheme: "secp256k1" }), "req_capabilities"),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(capabilitiesLine({}, { derivationPath: "m/44'/0'/0'/0'/0'" }), "req_capabilities"),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        capabilitiesLine({}, {}, { sessionId: "session_abcdef0123456789" }),
        "req_capabilities",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(capabilitiesLine({}, {}, { signing: { authorization: "host", methods: [] } }), "req_capabilities"),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        capabilitiesLine({}, {}, { signing: { authorization: "user", methods: [{ chain: "sui", method: "sign_personal_message" }] } }),
        "req_capabilities",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        capabilitiesLine({}, {}, { signing: { authorization: "user", methods: [{ chain: "sui", method: "sign_transaction", txBytes: "AQID" }] } }),
        "req_capabilities",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        capabilitiesLine({}, {}, { signing: { user: [{ chain: "sui", method: "sign_transaction" }], policy: [{ chain: "sui", method: "sign_transaction" }] } }),
        "req_capabilities",
      ),
    { code: "protocol_error" },
  );
});

test("parseProtocolResponse rejects capabilities carrying secret material", () => {
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.throws(
      () =>
        parseProtocolResponse(
          capabilitiesLine({}, { [fieldName]: "secret-like value" }),
          "req_capabilities",
        ),
      { code: "protocol_error" },
      `secret-like capability field ${fieldName} must be rejected`,
    );
  }
});

const accountsLine = (accountOverrides = {}) =>
  JSON.stringify({
    id: "req_accounts",
    version: 1,
    type: "accounts",
    accounts: [
      {
        chain: "sui",
        address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
        publicKey: "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk=",
        keyScheme: "ed25519",
        derivationPath: "m/44'/784'/0'/0'/0'",
        ...accountOverrides,
      },
    ],
  });

test("parseProtocolResponse accepts a valid Sui accounts response", () => {
  const response = assertAccountsResponse(parseProtocolResponse(accountsLine(), "req_accounts"));
  assert.equal(response.type, "accounts");
  assert.equal(response.accounts.length, 1);
  assert.equal(response.accounts[0].chain, "sui");
  assert.equal(
    response.accounts[0].address,
    "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
  );
  assert.equal(response.accounts[0].keyScheme, "ed25519");
  assert.equal(response.accounts[0].derivationPath, "m/44'/784'/0'/0'/0'");
  assert.equal(
    isSuiAddressForPublicKey(response.accounts[0].address, response.accounts[0].publicKey),
    true,
  );
});

test("parseProtocolResponse rejects an accounts response carrying secret material", () => {
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.throws(
      () => parseProtocolResponse(accountsLine({ [fieldName]: "secret-like value" }), "req_accounts"),
      { code: "protocol_error" },
      `secret-like account field ${fieldName} must be rejected`,
    );
  }
});

test("parseProtocolResponse rejects malformed or unsupported accounts", () => {
  assert.throws(
    () => parseProtocolResponse(accountsLine({ address: "0xnothex" }), "req_accounts"),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(accountsLine({ chain: "ethereum" }), "req_accounts"),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(accountsLine({ keyScheme: "secp256k1" }), "req_accounts"),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(accountsLine({ derivationPath: "m/44'/0'/0'/0'/0'" }), "req_accounts"),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        accountsLine({ publicKey: "vG6hEnkYNIpdmWa/WaLivd1FWBkxG+HfhXkyWgs9uP4=" }),
        "req_accounts",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        accountsLine({ address: "0x1ada6e6f3f3e4055096f606c746690f1108fcc2ca479055cc434a3e1d3f758aa" }),
        "req_accounts",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        accountsLine({ publicKey: "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGl=" }),
        "req_accounts",
      ),
    { code: "protocol_error" },
  );
});

test("parseProtocolResponse rejects an accounts response exceeding the supported count", () => {
  const account = {
    chain: "sui",
    address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
    publicKey: "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk=",
    keyScheme: "ed25519",
    derivationPath: "m/44'/784'/0'/0'/0'",
  };
  const tooMany = JSON.stringify({
    id: "req_accounts",
    version: 1,
    type: "accounts",
    accounts: [account, account],
  });
  assert.throws(() => parseProtocolResponse(tooMany, "req_accounts"), { code: "protocol_error" });

  const empty = JSON.stringify({
    id: "req_accounts",
    version: 1,
    type: "accounts",
    accounts: [],
  });
  assert.throws(() => parseProtocolResponse(empty, "req_accounts"), { code: "protocol_error" });
});

const POLICY_HASH = "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3";
const SUI_TYPE_TAG = "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";

const rejectGasPolicy = () => ({
  id: "reject_expensive_gas",
  action: "reject",
  conditions: [
    { field: "sui.gas_budget_raw", op: "lte", value: "50000000" },
    { field: "sui.command_kinds", op: "not_contains", value: "publish" },
  ],
});

const signGasCoinSourceAmountPolicy = () => ({
  id: "sign_gas_source_amount",
  action: "sign",
  conditions: [
    { field: "sui.token_sources.source", op: "eq", value: "gas_coin" },
    { field: "sui.token_sources.amount_raw", op: "lte", value: "1000000000" },
    { field: "sui.token_unknown_amount_present", op: "eq", value: "false" },
  ],
});

const signSuiTotalPolicy = () => ({
  id: "sign_sui_total_limit",
  action: "sign",
  conditions: [
    {
      field: "sui.token_totals_by_type.amount_raw",
      where: { type: SUI_TYPE_TAG },
      op: "lte",
      value: "1000000000",
    },
  ],
});

function policyBlockchains(policies = []) {
  return [
    {
      blockchain: "sui",
      networks: [
        {
          network: "testnet",
          policies,
        },
      ],
    },
  ];
}

function countPolicyDocument(blockchains) {
  let networkCount = 0;
  let policyCount = 0;
  let conditionCount = 0;
  for (const blockchain of blockchains) {
    networkCount += blockchain.networks.length;
    for (const network of blockchain.networks) {
      policyCount += network.policies.length;
      for (const policy of network.policies) {
        conditionCount += policy.conditions.length;
      }
    }
  }
  return {
    blockchainCount: blockchains.length,
    networkCount,
    policyCount,
    conditionCount,
  };
}

function policyDocument(overrides = {}) {
  const blockchains = overrides.blockchains ?? policyBlockchains();
  return {
    schema: "agentq.policy",
    policyId: POLICY_HASH,
    defaultAction: "reject",
    ...countPolicyDocument(blockchains),
    ...overrides,
    blockchains,
  };
}

test("current policy field descriptors stay aligned across Firmware, Core, and docs", () => {
  const firmware = parseFirmwarePolicyFieldDescriptors();
  const core = parseCorePolicyFieldDescriptors();
  const docs = parseDocumentedPolicyFieldOperators();
  const fields = [...firmware.keys()].sort();

  assert.deepEqual([...core.keys()].sort(), fields, "Core policy fields match Firmware");
  assert.deepEqual([...docs.keys()].sort(), fields, "documented policy fields match Firmware");

  for (const field of fields) {
    assert.deepEqual(
      core.get(field),
      firmware.get(field),
      `${field} Core descriptor matches Firmware`,
    );
    assert.deepEqual(
      docs.get(field).operators,
      firmware.get(field).operators,
      `${field} documented operators match Firmware`,
    );
  }
});

const policyLine = (policyOverrides = {}, topLevelOverrides = {}) =>
  JSON.stringify({
    id: "req_policy",
    version: 1,
    type: "policy",
    policy: policyDocument(policyOverrides),
    ...topLevelOverrides,
  });

test("parseProtocolResponse accepts a valid current active policy document", () => {
  const response = assertPolicyResponse(parseProtocolResponse(policyLine(), "req_policy"));
  assert.equal(response.type, "policy");
  assert.equal(response.policy.schema, "agentq.policy");
  assert.equal(response.policy.defaultAction, "reject");
  assert.equal(response.policy.blockchainCount, 1);
  assert.equal(response.policy.networkCount, 1);
  assert.equal(response.policy.policyCount, 0);
  assert.equal(response.policy.conditionCount, 0);
  assert.deepEqual(response.policy.blockchains, policyBlockchains());
  assert.match(response.policy.policyId, /^sha256:[0-9a-f]{64}$/);
});

test("parseProtocolResponse accepts current scoped policy conditions", () => {
  const blockchains = policyBlockchains([rejectGasPolicy(), signGasCoinSourceAmountPolicy(), signSuiTotalPolicy()]);
  const response = assertPolicyResponse(parseProtocolResponse(policyLine({ blockchains }), "req_policy"));
  assert.equal(response.type, "policy");
  assert.equal(response.policy.blockchainCount, 1);
  assert.equal(response.policy.networkCount, 1);
  assert.equal(response.policy.policyCount, 3);
  assert.equal(response.policy.conditionCount, 6);
  assert.equal(response.policy.blockchains[0].blockchain, "sui");
  assert.equal(response.policy.blockchains[0].networks[0].network, "testnet");
  assert.deepEqual(response.policy.blockchains[0].networks[0].policies, [
    rejectGasPolicy(),
    signGasCoinSourceAmountPolicy(),
    signSuiTotalPolicy(),
  ]);
});

test("parseProtocolResponse rejects malformed current policy documents", () => {
  assert.throws(() => parseProtocolResponse(policyLine({ schema: "other.policy" }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ policyId: "not-a-hash" }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ defaultAction: "approve" }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ blockchainCount: 2 }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ networkCount: 2 }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ policyCount: 1 }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ conditionCount: 1 }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ unexpected: [] }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ blockchains: [{ blockchain: "sui", networks: [] }, { blockchain: "sui", networks: [] }] }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({
    blockchains: [
      {
        blockchain: "sui",
        networks: [
          { network: "testnet", policies: [] },
          { network: "testnet", policies: [] },
        ],
      },
    ],
  }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({
    blockchains: policyBlockchains([
      { ...rejectGasPolicy(), id: "dup" },
      { ...signGasCoinSourceAmountPolicy(), id: "dup" },
    ]),
  }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({
    blockchains: policyBlockchains([{ ...rejectGasPolicy(), action: "approve" }]),
  }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({
    blockchains: policyBlockchains([{ ...rejectGasPolicy(), privateKey: "x" }]),
  }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({
    blockchains: policyBlockchains([
      {
        id: "bad_field",
        action: "reject",
        conditions: [{ field: "network", op: "eq", value: "testnet" }],
      },
    ]),
  }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({
    blockchains: policyBlockchains([
      {
        id: "bad_u64",
        action: "reject",
        conditions: [{ field: "sui.gas_budget_raw", op: "lte", value: "000500000000" }],
      },
    ]),
  }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({
    blockchains: policyBlockchains([
      {
        id: "bad_operator",
        action: "reject",
        conditions: [{ field: "sui.gas_budget_raw", op: "in", values: ["500000000"] }],
      },
    ]),
  }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({
    blockchains: policyBlockchains([
      {
        id: "missing_selector",
        action: "sign",
        conditions: [{ field: "sui.token_totals_by_type.amount_raw", op: "lte", value: "1000000000" }],
      },
    ]),
  }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({
    blockchains: policyBlockchains([
      {
        id: "forbidden_selector",
        action: "reject",
        conditions: [{ field: "sui.gas_budget_raw", where: { type: SUI_TYPE_TAG }, op: "lte", value: "1000000" }],
      },
    ]),
  }), "req_policy"), {
    code: "protocol_error",
  });
});

test("parseProtocolResponse rejects policy documents carrying secret material", () => {
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.throws(
      () => parseProtocolResponse(policyLine({ [fieldName]: "secret-like value" }), "req_policy"),
      { code: "protocol_error" },
      `secret-like policy field ${fieldName} must be rejected`,
    );
  }
});

const APPROVAL_DIGEST = "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3";

const approvalHistoryRecord = (overrides = {}) => ({
  seq: "2",
  uptimeMs: "12345",
  timeSource: "uptime",
  eventKind: "signing",
  authorization: "policy",
  recordKind: "terminal",
  terminalResult: "policy_rejected",
  chain: "sui",
  method: "sign_transaction",
  reasonCode: "default_reject",
  payloadDigest: APPROVAL_DIGEST,
  policyHash: APPROVAL_DIGEST,
  ruleRef: "default",
  ...overrides,
});

const approvalHistoryLine = (recordOverrides = {}, topLevelOverrides = {}) =>
  JSON.stringify({
    id: "req_approval_history",
    version: 1,
    type: "approval_history",
    records: [approvalHistoryRecord(recordOverrides)],
    hasMore: false,
    ...topLevelOverrides,
  });

const approvalHistoryPolicyUpdateRecord = (overrides = {}) => ({
  seq: "3",
  uptimeMs: "12346",
  timeSource: "uptime",
  eventKind: "policy_update",
  reasonCode: "device_confirmed",
  result: "applied",
  policyHash: APPROVAL_DIGEST,
  policyCount: 1,
  highestAction: "reject",
  ...overrides,
});

const approvalHistoryPolicyUpdateLine = (recordOverrides = {}, topLevelOverrides = {}) =>
  JSON.stringify({
    id: "req_approval_history",
    version: 1,
    type: "approval_history",
    records: [approvalHistoryPolicyUpdateRecord(recordOverrides)],
    hasMore: false,
    ...topLevelOverrides,
  });

const approvalHistorySigningUserConfirmationRecord = (overrides = {}) => ({
  seq: "4",
  uptimeMs: "12347",
  timeSource: "uptime",
  eventKind: "signing",
  authorization: "user",
  reasonCode: "device_confirmed",
  recordKind: "confirmation",
  confirmationKind: "local_pin",
  chain: "sui",
  method: "sign_transaction",
  payloadDigest: APPROVAL_DIGEST,
  ...overrides,
});

const approvalHistorySigningUserTerminalRecord = (overrides = {}) => ({
  seq: "5",
  uptimeMs: "12348",
  timeSource: "uptime",
  eventKind: "signing",
  authorization: "user",
  reasonCode: "device_confirmed",
  recordKind: "terminal",
  terminalResult: "signed",
  chain: "sui",
  method: "sign_transaction",
  payloadDigest: APPROVAL_DIGEST,
  ...overrides,
});

const approvalHistorySigningUserLine = (recordOverrides = {}, topLevelOverrides = {}, terminal = false) =>
  JSON.stringify({
    id: "req_approval_history",
    version: 1,
    type: "approval_history",
    records: [
      terminal
        ? approvalHistorySigningUserTerminalRecord(recordOverrides)
        : approvalHistorySigningUserConfirmationRecord(recordOverrides),
    ],
    hasMore: false,
    ...topLevelOverrides,
  });

test("parseProtocolResponse accepts bounded approval history pages", () => {
  const response = assertApprovalHistoryResponse(
    parseProtocolResponse(approvalHistoryLine(), "req_approval_history"),
  );
  assert.equal(response.type, "approval_history");
  assert.equal(response.records.length, 1);
  assert.equal(response.hasMore, false);
  assert.equal(response.records[0].eventKind, "signing");
  assert.equal(response.records[0].authorization, "policy");
  assert.equal(response.records[0].terminalResult, "policy_rejected");
  assert.equal(response.records[0].payloadDigest, APPROVAL_DIGEST);

});

test("parseProtocolResponse accepts policy update approval history records", () => {
  const response = assertApprovalHistoryResponse(
    parseProtocolResponse(approvalHistoryPolicyUpdateLine(), "req_approval_history"),
  );
  assert.equal(response.type, "approval_history");
  assert.equal(response.records.length, 1);
  assert.equal(response.records[0].eventKind, "policy_update");
  assert.equal(response.records[0].result, "applied");
  assert.equal(response.records[0].policyHash, APPROVAL_DIGEST);
  assert.equal(response.records[0].policyCount, 1);
  assert.equal(response.records[0].highestAction, "reject");
});

test("parseProtocolResponse accepts signing approval history records", () => {
  const confirmation = assertApprovalHistoryResponse(
    parseProtocolResponse(approvalHistorySigningUserLine(), "req_approval_history"),
  );
  assert.equal(confirmation.records[0].eventKind, "signing");
  assert.equal(confirmation.records[0].recordKind, "confirmation");
  assert.equal(confirmation.records[0].authorization, "user");
  assert.equal(confirmation.records[0].confirmationKind, "local_pin");
  assert.equal(confirmation.records[0].payloadDigest, APPROVAL_DIGEST);

  const physicalConfirmation = assertApprovalHistoryResponse(
    parseProtocolResponse(
      approvalHistorySigningUserLine({ confirmationKind: "physical_confirm" }),
      "req_approval_history",
    ),
  );
  assert.equal(physicalConfirmation.records[0].eventKind, "signing");
  assert.equal(physicalConfirmation.records[0].recordKind, "confirmation");
  assert.equal(physicalConfirmation.records[0].authorization, "user");
  assert.equal(physicalConfirmation.records[0].confirmationKind, "physical_confirm");
  assert.equal(physicalConfirmation.records[0].payloadDigest, APPROVAL_DIGEST);

  const blindSigningConfirmation = assertApprovalHistoryResponse(
    parseProtocolResponse(
      approvalHistorySigningUserLine({ reasonCode: "blind_signing_confirmed" }),
      "req_approval_history",
    ),
  );
  assert.equal(blindSigningConfirmation.records[0].eventKind, "signing");
  assert.equal(blindSigningConfirmation.records[0].recordKind, "confirmation");
  assert.equal(blindSigningConfirmation.records[0].authorization, "user");
  assert.equal(blindSigningConfirmation.records[0].confirmationKind, "local_pin");
  assert.equal(blindSigningConfirmation.records[0].reasonCode, "blind_signing_confirmed");
  assert.equal(blindSigningConfirmation.records[0].payloadDigest, APPROVAL_DIGEST);

  const terminal = assertApprovalHistoryResponse(
    parseProtocolResponse(
      approvalHistorySigningUserLine({}, {}, true),
      "req_approval_history",
    ),
  );
  assert.equal(terminal.records[0].eventKind, "signing");
  assert.equal(terminal.records[0].recordKind, "terminal");
  assert.equal(terminal.records[0].authorization, "user");
  assert.equal(terminal.records[0].terminalResult, "signed");
  assert.equal(terminal.records[0].payloadDigest, APPROVAL_DIGEST);
});

test("parseProtocolResponse rejects non-recordable policy_propose_result statuses", () => {
  for (const result of ["history_error", "consistency_error", "invalid_policy"]) {
    assert.throws(
      () => parseProtocolResponse(approvalHistoryPolicyUpdateLine({ result }), "req_approval_history"),
      { code: "protocol_error" },
      `${result} is not a durable policy update history result`,
    );
  }
});

test("parseProtocolResponse rejects approval history carrying secret material", () => {
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.throws(
      () => parseProtocolResponse(approvalHistoryLine({ [fieldName]: "secret-like value" }), "req_approval_history"),
      { code: "protocol_error" },
      `secret-like approval history field ${fieldName} must be rejected`,
    );
    assert.throws(
      () => parseProtocolResponse(approvalHistoryLine({}, { [fieldName]: "secret-like value" }), "req_approval_history"),
      { code: "protocol_error" },
      `secret-like approval history top-level field ${fieldName} must be rejected`,
    );
  }
});

test("parseProtocolResponse rejects malformed approval history records", () => {
  for (const recordOverride of [
    { seq: "01" },
    { seq: "18446744073709551616" },
    { uptimeMs: "not-number" },
    { timeSource: "wall_clock" },
    { eventKind: "session_event" },
    { confirmationKind: "connect_pin" },
    { chain: "Sui" },
    { method: "sign transaction" },
    { reasonCode: "DefaultReject" },
    { payloadDigest: "not-a-digest" },
    { policyHash: "not-a-digest" },
    { ruleRef: "has space" },
    { result: "applied" },
    { policyCount: 1 },
    { highestAction: "reject" },
    { sessionId: "session_abcdef0123456789" },
  ]) {
    assert.throws(
      () => parseProtocolResponse(approvalHistoryLine(recordOverride), "req_approval_history"),
      { code: "protocol_error" },
      `approval history override should be rejected: ${JSON.stringify(recordOverride)}`,
    );
  }
});

test("parseProtocolResponse rejects malformed policy update approval history records", () => {
  for (const recordOverride of [
    { result: "success" },
    { reasonCode: "DeviceConfirmed" },
    { policyHash: "not-a-digest" },
    { policyCount: -1 },
    { policyCount: 65 },
    { policyCount: 1.5 },
    { highestAction: "approve" },
    { confirmationKind: "policy" },
    { chain: "sui" },
    { method: "sign_transaction" },
    { payloadDigest: APPROVAL_DIGEST },
    { ruleRef: "default" },
    { sessionId: "session_abcdef0123456789" },
  ]) {
    assert.throws(
      () => parseProtocolResponse(approvalHistoryPolicyUpdateLine(recordOverride), "req_approval_history"),
      { code: "protocol_error" },
      `policy update approval history override should be rejected: ${JSON.stringify(recordOverride)}`,
    );
  }
});

test("parseProtocolResponse rejects malformed signing approval history records", () => {
  for (const recordOverride of [
    { recordKind: "approved" },
    { recordKind: "confirmation", confirmationKind: "policy" },
    { recordKind: "confirmation", terminalResult: "signed" },
    { recordKind: "terminal", confirmationKind: "local_pin" },
    { recordKind: "terminal", terminalResult: "history_error" },
    { recordKind: "terminal", terminalResult: null },
    { payloadDigest: "not-a-digest" },
    { policyHash: APPROVAL_DIGEST },
    { result: "signed" },
    { ruleRef: "default" },
    { sessionId: "session_abcdef0123456789" },
  ]) {
    assert.throws(
      () => parseProtocolResponse(approvalHistorySigningUserLine(recordOverride), "req_approval_history"),
      { code: "protocol_error" },
      `signing approval history override should be rejected: ${JSON.stringify(recordOverride)}`,
    );
  }
});

test("parseProtocolResponse rejects unsupported approval history response shape", () => {
  const record = approvalHistoryRecord();
  const tooMany = JSON.stringify({
    id: "req_approval_history",
    version: 1,
    type: "approval_history",
    records: [record, record, record, record, record],
    hasMore: false,
  });
  assert.throws(() => parseProtocolResponse(tooMany, "req_approval_history"), { code: "protocol_error" });

  assert.throws(
    () => parseProtocolResponse(approvalHistoryLine({}, { hasMore: "false" }), "req_approval_history"),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(approvalHistoryLine({}, { sessionId: "session_abcdef0123456789" }), "req_approval_history"),
    { code: "protocol_error" },
  );
});

const policyProposeResultPolicy = (overrides = {}) => ({
  policyHash: APPROVAL_DIGEST,
  blockchainCount: 1,
  networkCount: 1,
  policyCount: 1,
  conditionCount: 2,
  highestAction: "reject",
  ...overrides,
});

const policyProposeResultLine = (overrides = {}, policyOverrides = undefined) =>
  JSON.stringify({
    id: "req_policy_propose",
    version: 1,
    type: "policy_propose_result",
    status: "applied",
    reasonCode: "device_confirmed",
    policy: policyOverrides === null ? undefined : policyProposeResultPolicy(policyOverrides),
    ...overrides,
  });

test("parseProtocolResponse accepts policy_propose_result terminal outcomes", () => {
  for (const status of ["applied", "rejected", "timed_out", "ui_error", "storage_error", "consistency_error"]) {
    const response = assertPolicyProposeResultResponse(
      parseProtocolResponse(policyProposeResultLine({ status }), "req_policy_propose"),
    );
    assert.equal(response.type, "policy_propose_result");
    assert.equal(response.status, status);
    assert.equal(response.reasonCode, "device_confirmed");
    assert.equal(response.policy.policyHash, APPROVAL_DIGEST);
    assert.equal(response.policy.blockchainCount, 1);
    assert.equal(response.policy.networkCount, 1);
    assert.equal(response.policy.policyCount, 1);
    assert.equal(response.policy.conditionCount, 2);
    assert.equal(response.policy.highestAction, "reject");
  }

  const invalid = assertPolicyProposeResultResponse(
    parseProtocolResponse(
      policyProposeResultLine({ status: "invalid_policy", reasonCode: "invalid_policy" }, null),
      "req_policy_propose",
    ),
  );
  assert.equal(invalid.status, "invalid_policy");
  assert.equal(invalid.policy, undefined);
});

test("parseProtocolResponse rejects malformed policy_propose_result responses", () => {
  for (const override of [
    { status: "busy" },
    { status: "history_error" },
    { status: "invalid_policy" },
    { reasonCode: "DeviceConfirmed" },
    { policy: undefined },
    { sessionId: "session_abcdef0123456789" },
  ]) {
    assert.throws(
      () => parseProtocolResponse(policyProposeResultLine(override), "req_policy_propose"),
      { code: "protocol_error" },
      `policy_propose_result override should be rejected: ${JSON.stringify(override)}`,
    );
  }

  for (const policyOverride of [
    { policyHash: "not-a-digest" },
    { blockchainCount: -1 },
    { blockchainCount: 17 },
    { blockchainCount: 1.5 },
    { networkCount: -1 },
    { networkCount: 17 },
    { networkCount: 1.5 },
    { policyCount: -1 },
    { policyCount: 65 },
    { policyCount: 1.5 },
    { conditionCount: -1 },
    { conditionCount: 257 },
    { conditionCount: 1.5 },
    { highestAction: "approve" },
    { sessionId: "session_abcdef0123456789" },
  ]) {
    assert.throws(
      () => parseProtocolResponse(policyProposeResultLine({}, policyOverride), "req_policy_propose"),
      { code: "protocol_error" },
      `policy_propose_result policy override should be rejected: ${JSON.stringify(policyOverride)}`,
    );
  }
});

const signResultLine = (overrides = {}, errorOverrides = {}) =>
  JSON.stringify({
    id: "req_sign",
    version: 1,
    type: "sign_result",
    authorization: "user",
    status: "user_rejected",
    error: {
      code: "user_rejected",
      message: "The signing request was rejected on the device.",
      ...errorOverrides,
    },
    ...overrides,
  });

test("parseProtocolResponse accepts signed sign_result responses for user and policy authorization", () => {
  for (const authorization of ["user", "policy"]) {
    const signature = Buffer.alloc(97, authorization === "user" ? 1 : 2).toString("base64");
    const signed = assertSignResultResponse(
      parseProtocolResponse(
        signResultLine({
          authorization,
          status: "signed",
          chain: "sui",
          method: "sign_transaction",
          signature,
          error: undefined,
        }),
        "req_sign",
      ),
    );
    assert.equal(signed.type, "sign_result");
    assert.equal(signed.status, "signed");
    assert.equal(signed.authorization, authorization);
    assert.equal(signed.signature, signature);
  }

  const messageBytes = Buffer.from("hello Agent-Q").toString("base64");
  const personalMessageSignature = Buffer.alloc(97, 3).toString("base64");
  const personalMessageSigned = assertSignResultResponse(
    parseProtocolResponse(
      signResultLine({
        authorization: "user",
        status: "signed",
        chain: "sui",
        method: "sign_personal_message",
        signature: personalMessageSignature,
        messageBytes,
        error: undefined,
      }),
      "req_sign",
    ),
  );
  assert.equal(personalMessageSigned.status, "signed");
  assert.equal(personalMessageSigned.authorization, "user");
  assert.equal(personalMessageSigned.method, "sign_personal_message");
  assert.equal(personalMessageSigned.signature, personalMessageSignature);
  assert.equal(personalMessageSigned.messageBytes, messageBytes);

  const largerThanCurrentAdapterCapacity = Buffer.alloc(300, 7).toString("base64");
  const largerPersonalMessageSigned = assertSignResultResponse(
    parseProtocolResponse(
      signResultLine({
        authorization: "user",
        status: "signed",
        chain: "sui",
        method: "sign_personal_message",
        signature: personalMessageSignature,
        messageBytes: largerThanCurrentAdapterCapacity,
        error: undefined,
      }),
      "req_sign",
    ),
  );
  assert.equal(largerPersonalMessageSigned.method, "sign_personal_message");
  assert.equal(largerPersonalMessageSigned.messageBytes, largerThanCurrentAdapterCapacity);

  const largerThanRawRequestBound = Buffer.alloc(3500, 8).toString("base64");
  assert.ok(largerThanRawRequestBound.length > MAX_RAW_PROTOCOL_JSON_BYTES);
  assert.ok(largerThanRawRequestBound.length < MAX_SIGN_RESULT_PAYLOAD_BASE64_CHARS);
  const responseLineBoundPersonalMessageSigned = assertSignResultResponse(
    parseProtocolResponse(
      signResultLine({
        authorization: "user",
        status: "signed",
        chain: "sui",
        method: "sign_personal_message",
        signature: personalMessageSignature,
        messageBytes: largerThanRawRequestBound,
        error: undefined,
      }),
      "req_sign",
    ),
  );
  assert.equal(responseLineBoundPersonalMessageSigned.method, "sign_personal_message");
  assert.equal(responseLineBoundPersonalMessageSigned.messageBytes, largerThanRawRequestBound);
});

test("parseProtocolResponse accepts bounded sign_result terminal outcomes", () => {
  const cases = [
    {
      status: "user_rejected",
      authorization: "user",
      code: "user_rejected",
      message: "The signing request was rejected on the device.",
    },
    {
      status: "user_timed_out",
      authorization: "user",
      code: "user_timed_out",
      message: "The signing request timed out on the device.",
    },
    {
      status: "policy_rejected",
      authorization: "policy",
      code: "policy_rejected",
      message: "The signing request was rejected by device policy.",
      policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
      ruleRef: "default",
    },
    {
      status: "signing_failed",
      authorization: "policy",
      code: "signing_failed",
      message: "The device could not produce a signature.",
    },
  ];
  for (const terminal of cases) {
    const response = assertSignResultResponse(
      parseProtocolResponse(
        signResultLine({
          authorization: terminal.authorization,
          status: terminal.status,
          policyHash: terminal.policyHash,
          ruleRef: terminal.ruleRef,
        }, {
          code: terminal.code,
          message: terminal.message,
        }),
        "req_sign",
      ),
    );
    assert.equal(response.status, terminal.status);
    assert.equal(response.authorization, terminal.authorization);
    if (response.status === "policy_rejected") {
      assert.equal(response.policyHash, terminal.policyHash);
      assert.equal(response.ruleRef, terminal.ruleRef);
    }
    if (response.status !== "signed") {
      assert.equal(response.error.code, terminal.code);
    }
  }
});

test("parseProtocolResponse exposes signing history write failures as top-level errors", () => {
  const response = parseProtocolResponse(
    JSON.stringify({
      id: "req_sign",
      version: 1,
      type: "error",
      error: {
        code: "history_error",
        message: "Could not record signing terminal result.",
      },
    }),
    "req_sign",
  );
  assert.equal(response.type, "error");
  assert.equal(response.error.code, "history_error");
  assert.throws(() => assertSignResultResponse(response), { code: "history_error" });
});

test("parseProtocolResponse rejects sign_result leaks and inconsistent terminal errors", () => {
  assert.throws(
    () =>
      parseProtocolResponse(
        signResultLine({
          status: "signed",
          chain: "sui",
          method: "sign_transaction",
          signature: Buffer.alloc(96, 1).toString("base64"),
          error: undefined,
        }),
        "req_sign",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        signResultLine({
          status: "signed",
          chain: "sui",
          method: "sign_transaction",
          signature: Buffer.alloc(97, 1).toString("base64"),
          messageBytes: Buffer.from("hello").toString("base64"),
          error: undefined,
        }),
        "req_sign",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        signResultLine({
          authorization: "policy",
          status: "signed",
          chain: "sui",
          method: "sign_personal_message",
          signature: Buffer.alloc(97, 1).toString("base64"),
          messageBytes: Buffer.from("hello").toString("base64"),
          error: undefined,
        }),
        "req_sign",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        signResultLine({
          status: "signed",
          chain: "sui",
          method: "sign_personal_message",
          signature: Buffer.alloc(97, 1).toString("base64"),
          error: undefined,
        }),
        "req_sign",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        signResultLine({
          status: "signed",
          chain: "sui",
          method: "sign_transaction",
          signature: Buffer.alloc(97, 1).toString("base64"),
          txBytes: CANONICAL_TX_BYTES_BASE64,
          error: undefined,
        }),
        "req_sign",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        signResultLine({}, {
          code: "user_timed_out",
          message: "The signing request timed out on the device.",
        }),
        "req_sign",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        signResultLine({
          sessionId: "session_abcdef0123456789",
        }),
        "req_sign",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        signResultLine({
          authorization: "user",
          status: "policy_rejected",
          policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
          ruleRef: "default",
        }, {
          code: "policy_rejected",
          message: "The signing request was rejected by device policy.",
        }),
        "req_sign",
      ),
    { code: "protocol_error" },
  );
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.throws(
      () => parseProtocolResponse(signResultLine({ [fieldName]: "secret-like value" }), "req_sign"),
      { code: "protocol_error" },
      `secret-like sign_result field ${fieldName} must be rejected`,
    );
  }
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
  // device, so the wire boundary rejects it as malformed.
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

test("isSessionId and isClientName accept and reject expected inputs", () => {
  assert.equal(isSessionId("session_abcdef01"), true);
  assert.equal(isSessionId("session_ABCDEF"), false);
  assert.equal(isSessionId("notsession_aa"), false);
  assert.equal(isSessionId(""), false);

  assert.equal(isClientName("Agent-Q"), true);
  assert.equal(isClientName(""), false);
  assert.equal(isClientName("a".repeat(65)), false);
  assert.equal(isClientName("control\tchar"), false);
});

const safeDeviceId = "a508d833-5c83-4680-88bb-18aee976881e";

function statusLine(device) {
  return JSON.stringify({
    id: "req_1",
    version: 1,
    type: "status",
    device,
    provisioning: {
      state: "unprovisioned",
    },
  });
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
