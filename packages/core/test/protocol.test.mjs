import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  assertAccountsResult,
  assertApprovalHistoryResponse,
  assertCapabilitiesResult,
  assertCredentialPreparationResponse,
  assertCredentialProposalOutcomeResponse,
  assertPolicyResponse,
  assertPolicyProposalOutcomeResponse,
  assertSigningOutcome,
  assertConnectResult,
  assertDisconnectResult,
  assertIdentifyDeviceResponse,
  assertStatusResponse,
  createRequestId,
  FORBIDDEN_SECRET_FIELD_NAMES,
  isClientName,
  isSafeDeviceId,
  isSafeRequestId,
  isSessionId,
  isSuiAddressForSchemePrefixedPublicKey,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
  SUI_SIGNATURE_SCHEME_FLAG_ED25519,
  SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
  identifySignRoute,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_SESSION_TTL_MS,
  MAX_SIGNING_OUTCOME_PAYLOAD_BASE64_CHARS,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES,
  SIGNING_OUTCOME_ERROR_MESSAGES,
  sanitizeDisplayText,
  validateApprovalHistoryInput,
  validateCredentialPrepareRequestInput,
  validateCredentialProposeRequestInput,
  validatePolicyProposeRequestInput,
  validateSignPersonalMessageRequestInput,
  validateSignRequestInput,
} from "../dist/protocol.js";
import {
  makeDeviceFailureResponse,
  makeDeviceRequest,
  makeDeviceSuccessResponse,
  serializeDeviceRequest,
} from "../dist/device-contract.js";
import {
  makePayloadTransferAbortRequest,
  makePayloadTransferBeginRequest,
  makePayloadTransferChunkRequest,
  makePayloadTransferFinishRequest,
  normalizePayloadTransferRequest,
  parsePayloadTransferResponse,
  sanitizePayloadTransferAbortResult,
  sanitizePayloadTransferBeginResult,
  sanitizePayloadTransferChunkResult,
  sanitizePayloadTransferFinishResult,
} from "../dist/protocol-payload-delivery.js";

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

function serializeJsonLine(value) {
  return `${JSON.stringify(value)}\n`;
}

function suiEd25519Signature(fill = 1) {
  const bytes = Buffer.alloc(97, fill);
  bytes[0] = SUI_SIGNATURE_SCHEME_FLAG_ED25519;
  return bytes.toString("base64");
}

function suiZkLoginSignature(byteLength = 145) {
  const bytes = Buffer.alloc(byteLength, 6);
  bytes[0] = SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN;
  return bytes.toString("base64");
}

function parseFirmwarePolicyFieldDescriptors() {
  const source = readFileSync(
    new URL(
      "../../../firmware/src/common/policy/document.cpp",
      import.meta.url,
    ),
    "utf8",
  );
  const descriptors = new Map();
  const rowPattern =
    /\{"([^"]+)", CurrentPolicyValueKind::([a-z0-9_]+), CurrentPolicyWhereTypeRequirement::[a-z0-9_]+, CurrentPolicyEvaluationKind::[a-z0-9_]+, (true|false), (true|false), (true|false), (true|false), (true|false), (true|false), (true|false), (true|false)\}/g;
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
const VALID_TRANSFER_ID = "transfer_0123456789abcdef01234567";
const VALID_SCHEME_PREFIXED_PUBLIC_KEY =
  "ACJkf+7vNjBgvUIFoWcaFfEKEjZ2WRixtfY42C8zz8Rp";
const VALID_ZKLOGIN_PUBLIC_KEY =
  "BRtodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ==";
const VALID_ZKLOGIN_ADDRESS =
  "0xd41c7cbc0cbccb9e7ab701373f3b5f082cc0024098f2ab561ff342107b91491f";
const VALID_DEVICE_STATUS = {
  deviceId: "a508d833-5c83-4680-88bb-18aee976881e",
  state: "idle",
  firmwareName: "Agent-Q Firmware",
  hardware: "hardware-id",
  firmwareVersion: "0.0.0",
};

function validZkLoginInputs(overrides = {}) {
  return {
    proofPoints: {
      a: [
        "17318089125952421736342263717932719437717844282410187957984751939942898251250",
        "11373966645469122582074082295985388258840681618268593976697325892280915681207",
        "1",
      ],
      b: [
        [
          "5939871147348834997361720122238980177152303274311047249905942384915768690895",
          "4533568271134785278731234570361482651996740791888285864966884032717049811708",
        ],
        [
          "10564387285071555469753990661410840118635925466597037018058770041347518461368",
          "12597323547277579144698496372242615368085801313343155735511330003884767957854",
        ],
        ["1", "0"],
      ],
      c: [
        "15791589472556826263231644728873337629015269984699404073623603352537678813171",
        "4547866499248881449676161158024748060485373250029423904113017422539037162527",
        "1",
      ],
    },
    issBase64Details: {
      value: "ImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIs",
      indexMod4: 0,
    },
    headerBase64: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ",
    addressSeed: "1",
    ...overrides,
  };
}

function validCredentialProposeParams(overrides = {}) {
  return {
    chain: "sui",
    credential: "zklogin",
    network: "testnet",
    address: VALID_ZKLOGIN_ADDRESS,
    publicKey: VALID_ZKLOGIN_PUBLIC_KEY,
    maxEpoch: "42",
    inputs: validZkLoginInputs(),
    ...overrides,
  };
}

test("creates safe request ids", () => {
  const id = createRequestId();
  assert.equal(isSafeRequestId(id), true);
  assert.match(id, /^req_[0-9a-f]+$/);
});

test("rejects unsafe request ids", () => {
  assert.equal(isSafeRequestId("req_ok-1.2"), true);
  assert.equal(isSafeRequestId(""), false);
  assert.equal(isSafeRequestId("req/unsafe"), false);
  assert.equal(isSafeRequestId("a".repeat(80)), false);
});

test("builds and exact-normalizes payload transfer requests", () => {
  const sessionId = "session_abcdef0123456789";

  const begin = makePayloadTransferBeginRequest(
    sessionId,
    { totalBytes: "131072", payloadDigest: VALID_PAYLOAD_DIGEST },
    "req_upload_begin",
  );
  assert.deepEqual(begin, {
    id: "req_upload_begin",
    version: 1,
    type: "payload_transfer",
    action: "begin",
    sessionId,
    totalBytes: "131072",
    payloadDigest: VALID_PAYLOAD_DIGEST,
  });
  assert.deepEqual(normalizePayloadTransferRequest(begin), begin);

  const chunk = makePayloadTransferChunkRequest(
    sessionId,
    VALID_TRANSFER_ID,
    "3",
    CANONICAL_TX_BYTES_BASE64,
    "req_upload_chunk",
  );
  assert.deepEqual(chunk, {
    id: "req_upload_chunk",
    version: 1,
    type: "payload_transfer",
    action: "chunk",
    sessionId,
    transferId: VALID_TRANSFER_ID,
    offsetBytes: "3",
    chunk: CANONICAL_TX_BYTES_BASE64,
  });
  assert.deepEqual(normalizePayloadTransferRequest(chunk), chunk);

  const finish = makePayloadTransferFinishRequest(sessionId, VALID_TRANSFER_ID, "req_upload_finish");
  assert.deepEqual(finish, {
    id: "req_upload_finish",
    version: 1,
    type: "payload_transfer",
    action: "finish",
    sessionId,
    transferId: VALID_TRANSFER_ID,
  });
  assert.deepEqual(normalizePayloadTransferRequest(finish), finish);

  const abortTransfer = makePayloadTransferAbortRequest(sessionId, VALID_TRANSFER_ID, "req_upload_abort");
  assert.deepEqual(normalizePayloadTransferRequest(abortTransfer), abortTransfer);
  assert.deepEqual(abortTransfer, {
    id: "req_upload_abort",
    version: 1,
    type: "payload_transfer",
    action: "abort",
    sessionId,
    transferId: VALID_TRANSFER_ID,
  });

  const abortFinalized = makePayloadTransferAbortRequest(sessionId, VALID_PAYLOAD_REF, "req_payload_abort");
  assert.deepEqual(normalizePayloadTransferRequest(abortFinalized), abortFinalized);
  assert.deepEqual(abortFinalized, {
    id: "req_payload_abort",
    version: 1,
    type: "payload_transfer",
    action: "abort",
    sessionId,
    payloadRef: VALID_PAYLOAD_REF,
  });

  assert.throws(
    () => normalizePayloadTransferRequest({ ...begin, extra: true }),
    { code: "invalid_request" },
  );
  assert.throws(
    () => normalizePayloadTransferRequest({ ...begin, version: "1" }),
    { code: "invalid_request" },
  );
  assert.throws(
    () => normalizePayloadTransferRequest({ ...begin, version: 2 }),
    { code: "unsupported_version" },
  );
  assert.throws(
    () => normalizePayloadTransferRequest({ ...begin, type: 7 }),
    { code: "invalid_request" },
  );
  assert.throws(
    () => normalizePayloadTransferRequest({ ...begin, type: "other" }),
    { code: "unsupported_method" },
  );
  assert.throws(
    () => normalizePayloadTransferRequest({ ...begin, action: "replace" }),
    { code: "unsupported_method" },
  );
  assert.throws(
    () => normalizePayloadTransferRequest({ ...abortTransfer, payloadRef: VALID_PAYLOAD_REF }),
    { code: "invalid_request" },
  );
  assert.throws(
    () =>
      normalizePayloadTransferRequest({
        id: "req_abort_missing_target",
        version: 1,
        type: "payload_transfer",
        action: "abort",
        sessionId,
      }),
    { code: "invalid_request" },
  );
  assert.throws(
    () => makePayloadTransferBeginRequest(sessionId, {
      totalBytes: "not-decimal",
      payloadDigest: VALID_PAYLOAD_DIGEST,
    }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => makePayloadTransferBeginRequest(sessionId, {
      totalBytes: "1",
      payloadDigest: "not-digest",
    }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => makePayloadTransferBeginRequest(sessionId, {
      totalBytes: "18446744073709551616",
      payloadDigest: VALID_PAYLOAD_DIGEST,
    }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => makePayloadTransferChunkRequest(
      sessionId,
      VALID_TRANSFER_ID,
      "18446744073709551616",
      CANONICAL_TX_BYTES_BASE64,
    ),
    { code: "invalid_params" },
  );
});

test("payload transfer chunk frame budget fits the transport chunk size", () => {
  const maxRequestId = "r".repeat(79);
  const maxSessionId = `session_${"a".repeat(17)}`;
  const maxTransferId = `transfer_${"b".repeat(72)}`;
  const maxUint64Offset = "18446744073709551615";
  const advertisedChunk = Buffer.alloc(2700, 7).toString("base64");
  const request = makePayloadTransferChunkRequest(
    maxSessionId,
    maxTransferId,
    maxUint64Offset,
    advertisedChunk,
    maxRequestId,
  );

  assert.equal(Buffer.from(advertisedChunk, "base64").length, 2700);
  assert.ok(Buffer.byteLength(JSON.stringify(request), "utf8") <= MAX_RAW_PROTOCOL_JSON_BYTES);
  assert.ok(Buffer.byteLength(serializeJsonLine(request), "utf8") <= MAX_RAW_PROTOCOL_JSON_BYTES + 1);
  assert.deepEqual(normalizePayloadTransferRequest(request), request);
});

test("sign_transaction direct-frame boundary is computed from the DeviceRequest line", () => {
  function requestLineForDecodedTxBytes(decodedBytes) {
    return serializeDeviceRequest(makeDeviceRequest({
      id: "req_sign_boundary",
      method: "sign_transaction",
      sessionId: "session_aaaaaaaaaaaaaaaa",
      payload: {
        chain: "sui",
        network: "devnet",
        txBytes: Buffer.alloc(decodedBytes, 1).toString("base64"),
      },
    }));
  }

  let low = 0;
  let high = MAX_RAW_PROTOCOL_JSON_BYTES;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (Buffer.byteLength(requestLineForDecodedTxBytes(mid), "utf8") <= MAX_RAW_PROTOCOL_JSON_BYTES) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }

  const maxDirectDecodedBytes = low;
  const maxDirectTxBytes = Buffer.alloc(maxDirectDecodedBytes, 1).toString("base64");
  const nextTxBytes = Buffer.alloc(maxDirectDecodedBytes + 1, 1).toString("base64");

  assert.ok(maxDirectDecodedBytes > 656);
  assert.ok(Buffer.byteLength(requestLineForDecodedTxBytes(maxDirectDecodedBytes), "utf8") <= MAX_RAW_PROTOCOL_JSON_BYTES);
  assert.ok(Buffer.byteLength(requestLineForDecodedTxBytes(maxDirectDecodedBytes + 1), "utf8") > MAX_RAW_PROTOCOL_JSON_BYTES);
  assert.equal(
    validateSignRequestInput("sui", "sign_transaction", { network: "devnet", txBytes: maxDirectTxBytes }).txBytes,
    maxDirectTxBytes,
  );
  assert.equal(
    validateSignRequestInput("sui", "sign_transaction", { network: "devnet", txBytes: nextTxBytes }).txBytes,
    nextTxBytes,
  );
});

test("parsePayloadTransferResponse accepts and exact-validates payload transfer responses", () => {
  const begin = parsePayloadTransferResponse({
    id: "req_upload_begin",
    version: 1,
    success: true,
    result: {
      transferId: VALID_TRANSFER_ID,
      receivedBytes: "0",
      chunkMaxBytes: "2048",
    },
  }, "req_upload_begin", sanitizePayloadTransferBeginResult);
  assert.equal(begin.success, true);
  assert.equal(begin.result.transferId, VALID_TRANSFER_ID);
  assert.throws(
    () => parsePayloadTransferResponse({
      id: "req_upload_begin",
      version: 1,
      success: true,
      result: {
        transferId: VALID_TRANSFER_ID,
        receivedBytes: "0",
        chunkMaxBytes: "2047",
      },
    }, "req_upload_begin", sanitizePayloadTransferBeginResult),
    { code: "invalid_response" },
  );

  const chunk = parsePayloadTransferResponse({
    id: "req_upload_chunk",
    version: 1,
    success: true,
    result: {
      receivedBytes: "3",
    },
  }, "req_upload_chunk", sanitizePayloadTransferChunkResult);
  assert.equal(chunk.success, true);
  assert.equal(chunk.result.receivedBytes, "3");

  const finish = parsePayloadTransferResponse({
    id: "req_upload_finish",
    version: 1,
    success: true,
    result: {
      payloadRef: VALID_PAYLOAD_REF,
    },
  }, "req_upload_finish", sanitizePayloadTransferFinishResult);
  assert.equal(finish.success, true);
  assert.equal(finish.result.payloadRef, VALID_PAYLOAD_REF);

  const abort = parsePayloadTransferResponse({
    id: "req_payload_abort",
    version: 1,
    success: true,
    result: {},
  }, "req_payload_abort", sanitizePayloadTransferAbortResult);
  assert.equal(abort.success, true);
  assert.deepEqual(abort.result, {});

  assert.throws(
    () => parsePayloadTransferResponse({
      id: "req_upload_finish",
      version: 1,
      success: true,
      result: {
        payloadRef: VALID_PAYLOAD_REF,
        sizeBytes: "131072",
      },
    }, "req_upload_finish", sanitizePayloadTransferFinishResult),
    { code: "invalid_response" },
  );
  const failure = parsePayloadTransferResponse({
    id: "req_payload_abort",
    version: 1,
    success: false,
    error: {
      code: "invalid_session",
      message: "Session expired.",
      retryable: false,
    },
  }, "req_payload_abort", sanitizePayloadTransferAbortResult);
  assert.equal(failure.success, false);
  assert.equal(failure.error.code, "invalid_session");
});

test("Core method assertions accept DeviceResponse success envelopes", () => {
  const capabilitiesResult = {
    chains: [
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
    credentials: [
      {
        chain: "sui",
        credential: "zklogin",
        operations: ["credential_prepare", "credential_propose"],
      },
    ],
  };
  const account = {
    chain: "sui",
    address: VALID_ZKLOGIN_ADDRESS,
    publicKey: VALID_ZKLOGIN_PUBLIC_KEY,
    keyScheme: "zklogin",
    sponsoredTransactions: { acceptGasSponsor: false },
  };
  const nativePreparation = {
    address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
    publicKey: VALID_SCHEME_PREFIXED_PUBLIC_KEY,
    keyScheme: "ed25519",
  };
  const cases = [
    {
      method: "get_status",
      assertResponse: assertStatusResponse,
      result: { device: VALID_DEVICE_STATUS, provisioning: { state: "provisioned" } },
    },
    {
      method: "identify_device",
      assertResponse: assertIdentifyDeviceResponse,
      result: { code: "1234", device: VALID_DEVICE_STATUS },
    },
    {
      method: "connect",
      assertResponse: assertConnectResult,
      result: { sessionId: "session_abcdef0123456789", sessionTtlMs: MAX_SESSION_TTL_MS, device: VALID_DEVICE_STATUS },
    },
    {
      method: "disconnect",
      assertResponse: assertDisconnectResult,
      result: {},
    },
    {
      method: "get_capabilities",
      assertResponse: assertCapabilitiesResult,
      result: capabilitiesResult,
    },
    {
      method: "get_accounts",
      assertResponse: assertAccountsResult,
      result: { accounts: [account] },
    },
    {
      method: "policy_get",
      assertResponse: assertPolicyResponse,
      result: { policy: policyDocument() },
    },
    {
      method: "get_approval_history",
      assertResponse: assertApprovalHistoryResponse,
      result: { records: [], hasMore: false },
    },
    {
      method: "policy_propose",
      assertResponse: assertPolicyProposalOutcomeResponse,
      result: { status: "applied", reasonCode: "device_confirmed", policy: currentPolicyProposeSummary() },
    },
    {
      method: "credential_prepare",
      assertResponse: assertCredentialPreparationResponse,
      result: { chain: "sui", credential: "zklogin", preparation: nativePreparation },
    },
    {
      method: "credential_propose",
      assertResponse: assertCredentialProposalOutcomeResponse,
      result: { status: "activated", reasonCode: "device_confirmed", sessionEnded: true },
    },
    {
      method: "sign_transaction",
      assertResponse: assertSigningOutcome,
      result: {
        authorization: "user",
        chain: "sui",
        method: "sign_transaction",
        signature: suiEd25519Signature(1),
      },
    },
    {
      method: "sign_personal_message",
      assertResponse: assertSigningOutcome,
      result: {
        authorization: "user",
        chain: "sui",
        method: "sign_personal_message",
        signature: suiEd25519Signature(2),
        messageBytes: CANONICAL_TX_BYTES_BASE64,
      },
    },
  ];

  for (const entry of cases) {
    const response = makeDeviceSuccessResponse({
      id: `req_${entry.method}`,
      method: entry.method,
      result: entry.result,
    });
    const parsed = entry.assertResponse(response);
    assert.equal(Object.hasOwn(parsed, "type"), false, entry.method);
  }
});

test("Core method assertions throw DeviceResponse failure codes directly", () => {
  const failure = makeDeviceFailureResponse({
    id: "req_status_failure",
    method: "get_status",
    code: "invalid_state",
  });
  assert.throws(() => assertStatusResponse(failure), {
    code: "invalid_state",
  });
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

test("approval history input validation stays bounded without exposing request builders", () => {
  assert.deepEqual(validateApprovalHistoryInput({ limit: 2, beforeSeq: "42" }), {
    limit: 2,
    beforeSeq: "42",
  });
  assert.throws(() => validateApprovalHistoryInput({ limit: 0 }), /limit/);
  assert.throws(() => validateApprovalHistoryInput({ limit: 5 }), /limit/);
  assert.throws(() => validateApprovalHistoryInput({ beforeSeq: "not-number" }), /beforeSeq/);
  assert.throws(() => validateApprovalHistoryInput({ beforeSeq: "18446744073709551616" }), /beforeSeq/);
});

test("sign transaction input validation rejects caller-selected authorization without exposing request builders", () => {
  const params = { network: "devnet", txBytes: CANONICAL_TX_BYTES_BASE64 };
  assert.deepEqual(validateSignRequestInput("sui", "sign_transaction", params), params);
  assert.throws(
    () => validateSignRequestInput("evm", "sign_transaction", params),
    { code: "unsupported_chain" },
  );
  assert.throws(
    () => validateSignRequestInput("sui", "sign_personal_message", params),
    { code: "unsupported_method" },
  );
  assert.throws(
    () => validateSignRequestInput("sui", "sign_transaction", { ...params, timeoutMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => validateSignRequestInput("sui", "sign_transaction", { ...params, approvalTimeoutMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => validateSignRequestInput("sui", "sign_transaction", { ...params, durationMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => validateSignRequestInput("sui", "sign_transaction", { ...params, privateKey: "must-not-forward" }),
    /secret material/,
  );
  const observedAppWebTxBytes = Buffer.alloc(656, 1).toString("base64");
  assert.equal(
    validateSignRequestInput(
      "sui",
      "sign_transaction",
      { network: "devnet", txBytes: observedAppWebTxBytes },
    ).txBytes,
    observedAppWebTxBytes,
  );
  const aboveRemovedInlineCapacity = Buffer.alloc(385, 1).toString("base64");
  assert.equal(
    validateSignRequestInput(
      "sui",
      "sign_transaction",
      { network: "devnet", txBytes: aboveRemovedInlineCapacity },
    ).txBytes,
    aboveRemovedInlineCapacity,
  );
  assert.throws(
    () => validateSignRequestInput(
      "sui",
      "sign_transaction",
      { network: "devnet", txBytes: Buffer.alloc(MAX_SUI_SIGN_TRANSACTION_TX_BYTES + 1).toString("base64") },
    ),
    { code: "payload_too_large" },
  );
});

test("sign personal-message input validation rejects caller-selected authorization without exposing request builders", () => {
  const params = { network: "devnet", message: Buffer.from("hello Agent-Q").toString("base64") };
  assert.deepEqual(validateSignPersonalMessageRequestInput("sui", "sign_personal_message", params), params);
  assert.throws(
    () => validateSignPersonalMessageRequestInput("sui", "sign_transaction", params),
    { code: "unsupported_method" },
  );
  assert.throws(
    () => validateSignPersonalMessageRequestInput("sui", "sign_personal_message", { ...params, timeoutMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => validateSignPersonalMessageRequestInput("sui", "sign_personal_message", { ...params, authorization: "user" }),
    /unsupported fields/,
  );
  assert.throws(
    () => validateSignPersonalMessageRequestInput("sui", "sign_personal_message", { ...params, seed: "must-not-forward" }),
    /secret material/,
  );
  const observedAppWebMessage = Buffer.alloc(518, 1).toString("base64");
  assert.equal(
    validateSignPersonalMessageRequestInput(
      "sui",
      "sign_personal_message",
      { network: "devnet", message: observedAppWebMessage },
    ).message,
    observedAppWebMessage,
  );
  const aboveRemovedPersonalMessageCapacity = Buffer.alloc(257, 1).toString("base64");
  assert.equal(
    validateSignPersonalMessageRequestInput(
      "sui",
      "sign_personal_message",
      { network: "devnet", message: aboveRemovedPersonalMessageCapacity },
    ).message,
    aboveRemovedPersonalMessageCapacity,
  );
  assert.throws(
    () => validateSignPersonalMessageRequestInput(
      "sui",
      "sign_personal_message",
      { network: "devnet", message: Buffer.alloc(MAX_SUI_SIGN_PERSONAL_MESSAGE_BYTES + 1).toString("base64") },
    ),
    { code: "payload_too_large" },
  );
});

test("policy proposal input validation rejects secrets without exposing request builders", () => {
  const policy = {
    schema: "signing.policy",
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
  assert.doesNotThrow(() => validatePolicyProposeRequestInput("session_abcdef0123456789", policy));
  assert.throws(
    () => validatePolicyProposeRequestInput("not_a_session", policy),
    /sessionId/,
  );
  assert.throws(
    () => validatePolicyProposeRequestInput("session_abcdef0123456789", []),
    /policy_propose/,
  );
  assert.throws(
    () => validatePolicyProposeRequestInput("session_abcdef0123456789", { seed: "must-not-forward" }),
    /secret material/,
  );
});

test("credential input validation uses common operations and bounded zkLogin DTOs", () => {
  assert.doesNotThrow(() =>
    validateCredentialPrepareRequestInput("session_abcdef0123456789", { chain: "sui", credential: "zklogin" }),
  );
  const params = validCredentialProposeParams();
  assert.doesNotThrow(() => validateCredentialProposeRequestInput("session_abcdef0123456789", params));
  assert.equal(
    isSuiAddressForSchemePrefixedPublicKey(params.address, params.publicKey, 0x05, 34, 288),
    true,
  );

  assert.throws(
    () => validateCredentialPrepareRequestInput("not_a_session", { chain: "sui", credential: "zklogin" }),
    { code: "invalid_session" },
  );
  assert.throws(
    () => validateCredentialPrepareRequestInput("session_abcdef0123456789", { chain: "sui", credential: "passkey" }),
    { code: "invalid_params" },
  );
  assert.throws(
    () => validateCredentialProposeRequestInput(
      "session_abcdef0123456789",
      validCredentialProposeParams({ publicKey: VALID_SCHEME_PREFIXED_PUBLIC_KEY }),
    ),
    { code: "invalid_params" },
  );
  assert.throws(
    () => validateCredentialProposeRequestInput(
      "session_abcdef0123456789",
      validCredentialProposeParams({ inputs: validZkLoginInputs({ addressSeed: "01" }) }),
    ),
    { code: "invalid_params" },
  );
  assert.throws(
    () => validateCredentialProposeRequestInput(
      "session_abcdef0123456789",
      validCredentialProposeParams({ inputs: validZkLoginInputs({ issBase64Details: { value: "abc=", indexMod4: 0 } }) }),
    ),
    { code: "invalid_params" },
  );
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
    schema: "signing.policy",
    policyId: POLICY_HASH,
    defaultAction: "reject",
    ...countPolicyDocument(blockchains),
    ...overrides,
    blockchains,
  };
}

function currentPolicyProposeSummary(overrides = {}) {
  return {
    policyHash: POLICY_HASH,
    blockchainCount: 1,
    networkCount: 1,
    policyCount: 0,
    conditionCount: 0,
    highestAction: "reject",
    ...overrides,
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

const policyProposeResultPolicy = (overrides = {}) => ({
  policyHash: APPROVAL_DIGEST,
  blockchainCount: 1,
  networkCount: 1,
  policyCount: 1,
  conditionCount: 2,
  highestAction: "reject",
  ...overrides,
});

test("isSessionId and isClientName accept and reject expected inputs", () => {
  assert.equal(isSessionId("session_abcdef01"), true);
  assert.equal(isSessionId("session_00010203040506070"), true);
  assert.equal(isSessionId("session_000102030405060700"), false);
  assert.equal(isSessionId("session_" + "a".repeat(128)), false);
  assert.equal(isSessionId("session_ABCDEF"), false);
  assert.equal(isSessionId("notsession_aa"), false);
  assert.equal(isSessionId(""), false);

  assert.equal(isClientName("Agent-Q"), true);
  assert.equal(isClientName(""), false);
  assert.equal(isClientName("a".repeat(65)), false);
  assert.equal(isClientName("control\tchar"), false);
});

const safeDeviceId = "a508d833-5c83-4680-88bb-18aee976881e";

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
