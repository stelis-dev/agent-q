import assert from "node:assert/strict";
import test from "node:test";
import {
  assertAccountsResponse,
  assertApprovalHistoryResponse,
  assertCapabilitiesResponse,
  assertMethodResultResponse,
  assertPolicyResponse,
  assertPolicyUpdateResultResponse,
  assertSignatureResultResponse,
  assertConnectResponse,
  assertDisconnectResponse,
  assertStatusResponse,
  createRequestId,
  FORBIDDEN_SECRET_FIELD_NAMES,
  isGatewayName,
  isSafeDeviceId,
  isSafeRequestId,
  isSessionId,
  isSuiAddressForPublicKey,
  makeCallMethodRequest,
  makeConnectRequest,
  makeDisconnectRequest,
  makeGetCapabilitiesRequest,
  makeGetAccountsRequest,
  makeGetApprovalHistoryRequest,
  makeGetPolicyRequest,
  makeIdentifyDeviceRequest,
  makeGetStatusRequest,
  makeProposePolicyUpdateRequest,
  makeRequestSignatureRequest,
  MAX_SESSION_TTL_MS,
  parseProtocolResponse,
  sanitizeDisplayText,
  serializeRequest,
} from "../dist/protocol.js";

const CANONICAL_TX_BYTES_BASE64 = "AQID";

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
    "unsupported_method",
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

test("makeConnectRequest validates gatewayName", () => {
  const request = makeConnectRequest("Agent-Q Gateway", "req_connect_1");
  assert.deepEqual(request, {
    id: "req_connect_1",
    version: 1,
    type: "connect",
    params: {
      gatewayName: "Agent-Q Gateway",
    },
  });

  assert.throws(() => makeConnectRequest(""), /gatewayName/);
  assert.throws(() => makeConnectRequest("a".repeat(65)), /gatewayName/);
  assert.throws(() => makeConnectRequest("Hello ÿ"), /gatewayName/);
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

test("makeGetPolicyRequest validates sessionId", () => {
  const request = makeGetPolicyRequest("session_abcdef0123456789", "req_get_policy_1");
  assert.deepEqual(request, {
    id: "req_get_policy_1",
    version: 1,
    type: "get_policy",
    sessionId: "session_abcdef0123456789",
  });

  assert.throws(() => makeGetPolicyRequest("not_a_session"), /Invalid sessionId/);
  assert.throws(() => makeGetPolicyRequest("session_"), /Invalid sessionId/);
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

test("makeCallMethodRequest validates session, method identifiers, and params", () => {
  const request = makeCallMethodRequest(
    "session_abcdef0123456789",
    "sui",
    "unknown_method",
    {},
    "req_call_method_1",
  );
  assert.deepEqual(request, {
    id: "req_call_method_1",
    version: 1,
    type: "call_method",
    sessionId: "session_abcdef0123456789",
    chain: "sui",
    method: "unknown_method",
    params: {},
  });

  assert.throws(() => makeCallMethodRequest("not_a_session", "sui", "sign_transaction"), /sessionId/);
  assert.throws(() => makeCallMethodRequest("session_abcdef0123456789", "Sui", "sign_transaction"), /chain/);
  assert.throws(() => makeCallMethodRequest("session_abcdef0123456789", "sui", "sign transaction"), /method/);
  assert.throws(
    () => makeCallMethodRequest("session_abcdef0123456789", "sui", "sign_transaction", []),
    /params/,
  );
  assert.throws(
    () =>
      makeCallMethodRequest("session_abcdef0123456789", "sui", "unknown_method", {
        memo: "가".repeat(250),
      }),
    /too large/,
  );
});

test("makeCallMethodRequest validates Sui sign_transaction params", () => {
  const params = { network: "devnet", txBytes: CANONICAL_TX_BYTES_BASE64 };
  const request = makeCallMethodRequest(
    "session_abcdef0123456789",
    "sui",
    "sign_transaction",
    params,
    "req_call_method_1",
  );
  assert.deepEqual(request.params, params);

  assert.throws(
    () => makeCallMethodRequest("session_abcdef0123456789", "sui", "sign_transaction", {}),
    /network/,
  );
  assert.throws(
    () =>
      makeCallMethodRequest("session_abcdef0123456789", "sui", "sign_transaction", {
        network: "invalidnet",
        txBytes: CANONICAL_TX_BYTES_BASE64,
      }),
    /network/,
  );
  assert.throws(
    () =>
      makeCallMethodRequest("session_abcdef0123456789", "sui", "sign_transaction", {
        network: "devnet",
        txBytes: "not-base64",
      }),
    /base64/,
  );
  assert.throws(
    () =>
      makeCallMethodRequest("session_abcdef0123456789", "sui", "sign_transaction", {
        network: "devnet",
        txBytes: CANONICAL_TX_BYTES_BASE64,
        memo: "extra",
      }),
    /unsupported fields/,
  );
  assert.throws(
    () =>
      makeCallMethodRequest("session_abcdef0123456789", "sui", "sign_transaction", {
        seed: "must-not-forward",
      }),
    /secret material/,
  );
});

test("makeRequestSignatureRequest builds bounded device-confirmed signing requests", () => {
  const params = {
    chain: "sui",
    method: "sign_transaction",
    network: "devnet",
    txBytes: CANONICAL_TX_BYTES_BASE64,
  };
  const request = makeRequestSignatureRequest(
    "session_abcdef0123456789",
    params,
    "req_signature_1",
  );
  assert.deepEqual(request, {
    id: "req_signature_1",
    version: 1,
    type: "request_signature",
    sessionId: "session_abcdef0123456789",
    params,
  });

  assert.throws(() => makeRequestSignatureRequest("not_a_session", params), /sessionId/);
  assert.throws(
    () => makeRequestSignatureRequest("session_abcdef0123456789", { ...params, method: "sign_personal_message" }),
    /unsupported/,
  );
  assert.throws(
    () => makeRequestSignatureRequest("session_abcdef0123456789", { ...params, timeoutMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => makeRequestSignatureRequest("session_abcdef0123456789", { ...params, approvalTimeoutMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => makeRequestSignatureRequest("session_abcdef0123456789", { ...params, durationMs: 30000 }),
    /unsupported fields/,
  );
  assert.throws(
    () => makeRequestSignatureRequest("session_abcdef0123456789", { ...params, privateKey: "must-not-forward" }),
    /secret material/,
  );
});

test("makeProposePolicyUpdateRequest builds admin proposal requests without chain authority", () => {
  const policy = {
    schema: "agentq.policy.v0",
    defaultAction: "reject",
    rules: [
      {
        id: "reject_devnet",
        chain: "sui",
        method: "sign_transaction",
        action: "reject",
        criteria: [{ field: "common.network", op: "eq", value: "devnet" }],
      },
    ],
  };
  const request = makeProposePolicyUpdateRequest(
    "session_abcdef0123456789",
    policy,
    "req_policy_update_1",
  );
  assert.deepEqual(request, {
    id: "req_policy_update_1",
    version: 1,
    type: "call_method",
    sessionId: "session_abcdef0123456789",
    methodNamespace: "admin",
    method: "propose_policy_update",
    params: { policy },
  });
  assert.equal("chain" in request, false);
  assert.ok(Buffer.byteLength(serializeRequest(request), "utf8") <= 4097);

  assert.throws(
    () => makeProposePolicyUpdateRequest("not_a_session", policy),
    /sessionId/,
  );
  assert.throws(
    () => makeProposePolicyUpdateRequest("session_abcdef0123456789", []),
    /proposal/,
  );
  assert.throws(
    () => makeProposePolicyUpdateRequest("session_abcdef0123456789", { seed: "must-not-forward" }),
    /secret material/,
  );
  assert.throws(
    () => makeProposePolicyUpdateRequest("session_abcdef0123456789", { data: "x".repeat(5000) }),
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

test("parseProtocolResponse accepts a valid capabilities response with provider signing metadata", () => {
  const response = assertCapabilitiesResponse(
    parseProtocolResponse(
      capabilitiesLine({}, {}, { signatureRequests: [{ chain: "sui", method: "sign_transaction" }] }),
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
  assert.deepEqual(response.signatureRequests, [{ chain: "sui", method: "sign_transaction" }]);
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
    () => parseProtocolResponse(capabilitiesLine({}, {}, { signatureRequests: [] }), "req_capabilities"),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        capabilitiesLine({}, {}, { signatureRequests: [{ chain: "sui", method: "sign_personal_message" }] }),
        "req_capabilities",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        capabilitiesLine({}, {}, { signatureRequests: [{ chain: "sui", method: "sign_transaction", txBytes: "AQID" }] }),
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

const policyLine = (policyOverrides = {}, topLevelOverrides = {}) =>
  JSON.stringify({
    id: "req_policy",
    version: 1,
    type: "policy",
    policy: {
      schema: "agentq.policy.v0",
      policyId: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
      defaultAction: "reject",
      ruleCount: 0,
      ...policyOverrides,
    },
    ...topLevelOverrides,
  });

test("parseProtocolResponse accepts a valid active policy summary", () => {
  const response = assertPolicyResponse(parseProtocolResponse(policyLine(), "req_policy"));
  assert.equal(response.type, "policy");
  assert.equal(response.policy.schema, "agentq.policy.v0");
  assert.equal(response.policy.defaultAction, "reject");
  assert.equal(response.policy.ruleCount, 0);
  assert.match(response.policy.policyId, /^sha256:[0-9a-f]{64}$/);
});

test("parseProtocolResponse accepts a bounded custom policy summary", () => {
  const response = assertPolicyResponse(parseProtocolResponse(policyLine({ ruleCount: 1 }), "req_policy"));
  assert.equal(response.type, "policy");
  assert.equal(response.policy.ruleCount, 1);
});

test("parseProtocolResponse rejects malformed policy summaries", () => {
  assert.throws(() => parseProtocolResponse(policyLine({ schema: "agentq.policy.v1" }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ policyId: "not-a-hash" }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ defaultAction: "approve" }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ ruleCount: 17 }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ ruleCount: -1 }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ ruleCount: 1.5 }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({ rules: [] }), "req_policy"), {
    code: "protocol_error",
  });
  assert.throws(() => parseProtocolResponse(policyLine({}, { sessionId: "session_abcdef0123456789" }), "req_policy"), {
    code: "protocol_error",
  });
});

test("parseProtocolResponse rejects policy summaries carrying secret material", () => {
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
  eventKind: "method_decision",
  decisionKind: "policy_rejected",
  confirmationKind: "policy",
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
  ruleCount: 1,
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

const approvalHistorySignatureRequestConfirmationRecord = (overrides = {}) => ({
  seq: "4",
  uptimeMs: "12347",
  timeSource: "uptime",
  eventKind: "signature_request",
  reasonCode: "device_confirmed",
  recordKind: "confirmation",
  confirmationKind: "local_pin",
  chain: "sui",
  method: "sign_transaction",
  payloadDigest: APPROVAL_DIGEST,
  ...overrides,
});

const approvalHistorySignatureRequestTerminalRecord = (overrides = {}) => ({
  seq: "5",
  uptimeMs: "12348",
  timeSource: "uptime",
  eventKind: "signature_request",
  reasonCode: "device_confirmed",
  recordKind: "terminal",
  terminalResult: "signed",
  chain: "sui",
  method: "sign_transaction",
  payloadDigest: APPROVAL_DIGEST,
  ...overrides,
});

const approvalHistorySignatureRequestLine = (recordOverrides = {}, topLevelOverrides = {}, terminal = false) =>
  JSON.stringify({
    id: "req_approval_history",
    version: 1,
    type: "approval_history",
    records: [
      terminal
        ? approvalHistorySignatureRequestTerminalRecord(recordOverrides)
        : approvalHistorySignatureRequestConfirmationRecord(recordOverrides),
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
  assert.equal(response.records[0].eventKind, "method_decision");
  assert.equal(response.records[0].decisionKind, "policy_rejected");
  assert.equal(response.records[0].confirmationKind, "policy");
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
  assert.equal(response.records[0].ruleCount, 1);
  assert.equal(response.records[0].highestAction, "reject");
});

test("parseProtocolResponse accepts signature request approval history records", () => {
  const confirmation = assertApprovalHistoryResponse(
    parseProtocolResponse(approvalHistorySignatureRequestLine(), "req_approval_history"),
  );
  assert.equal(confirmation.records[0].eventKind, "signature_request");
  assert.equal(confirmation.records[0].recordKind, "confirmation");
  assert.equal(confirmation.records[0].confirmationKind, "local_pin");
  assert.equal(confirmation.records[0].payloadDigest, APPROVAL_DIGEST);

  const terminal = assertApprovalHistoryResponse(
    parseProtocolResponse(
      approvalHistorySignatureRequestLine({}, {}, true),
      "req_approval_history",
    ),
  );
  assert.equal(terminal.records[0].eventKind, "signature_request");
  assert.equal(terminal.records[0].recordKind, "terminal");
  assert.equal(terminal.records[0].terminalResult, "signed");
  assert.equal(terminal.records[0].payloadDigest, APPROVAL_DIGEST);
});

test("parseProtocolResponse rejects non-recordable policy update results", () => {
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
    { decisionKind: "approved" },
    { decisionKind: "connect_approved" },
    { confirmationKind: "connect_pin" },
    { chain: "Sui" },
    { method: "sign transaction" },
    { reasonCode: "DefaultReject" },
    { payloadDigest: "not-a-digest" },
    { policyHash: "not-a-digest" },
    { ruleRef: "has space" },
    { result: "applied" },
    { ruleCount: 1 },
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
    { ruleCount: -1 },
    { ruleCount: 17 },
    { ruleCount: 1.5 },
    { highestAction: "approve" },
    { decisionKind: "policy_rejected" },
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

test("parseProtocolResponse rejects malformed signature request approval history records", () => {
  for (const recordOverride of [
    { recordKind: "approved" },
    { recordKind: "confirmation", confirmationKind: "policy" },
    { recordKind: "confirmation", terminalResult: "signed" },
    { recordKind: "terminal", confirmationKind: "local_pin" },
    { recordKind: "terminal", terminalResult: "history_error" },
    { recordKind: "terminal", terminalResult: null },
    { payloadDigest: "not-a-digest" },
    { policyHash: APPROVAL_DIGEST },
    { decisionKind: "policy_rejected" },
    { result: "signed" },
    { ruleRef: "default" },
    { sessionId: "session_abcdef0123456789" },
  ]) {
    assert.throws(
      () => parseProtocolResponse(approvalHistorySignatureRequestLine(recordOverride), "req_approval_history"),
      { code: "protocol_error" },
      `signature request approval history override should be rejected: ${JSON.stringify(recordOverride)}`,
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

const policyUpdateResultPolicy = (overrides = {}) => ({
  policyHash: APPROVAL_DIGEST,
  ruleCount: 1,
  highestAction: "reject",
  ...overrides,
});

const policyUpdateResultLine = (overrides = {}, policyOverrides = undefined) =>
  JSON.stringify({
    id: "req_policy_update",
    version: 1,
    type: "policy_update_result",
    status: "applied",
    reasonCode: "device_confirmed",
    policy: policyOverrides === null ? undefined : policyUpdateResultPolicy(policyOverrides),
    ...overrides,
  });

test("parseProtocolResponse accepts policy_update_result terminal outcomes", () => {
  for (const status of ["applied", "rejected", "timed_out", "ui_error", "storage_error", "consistency_error"]) {
    const response = assertPolicyUpdateResultResponse(
      parseProtocolResponse(policyUpdateResultLine({ status }), "req_policy_update"),
    );
    assert.equal(response.type, "policy_update_result");
    assert.equal(response.status, status);
    assert.equal(response.reasonCode, "device_confirmed");
    assert.equal(response.policy.policyHash, APPROVAL_DIGEST);
    assert.equal(response.policy.ruleCount, 1);
    assert.equal(response.policy.highestAction, "reject");
  }

  const invalid = assertPolicyUpdateResultResponse(
    parseProtocolResponse(
      policyUpdateResultLine({ status: "invalid_policy", reasonCode: "invalid_policy" }, null),
      "req_policy_update",
    ),
  );
  assert.equal(invalid.status, "invalid_policy");
  assert.equal(invalid.policy, undefined);
});

test("parseProtocolResponse rejects malformed policy_update_result responses", () => {
  for (const override of [
    { status: "busy" },
    { status: "history_error" },
    { status: "invalid_policy" },
    { reasonCode: "DeviceConfirmed" },
    { policy: undefined },
    { sessionId: "session_abcdef0123456789" },
  ]) {
    assert.throws(
      () => parseProtocolResponse(policyUpdateResultLine(override), "req_policy_update"),
      { code: "protocol_error" },
      `policy_update_result override should be rejected: ${JSON.stringify(override)}`,
    );
  }

  for (const policyOverride of [
    { policyHash: "not-a-digest" },
    { ruleCount: -1 },
    { ruleCount: 17 },
    { ruleCount: 1.5 },
    { highestAction: "approve" },
    { sessionId: "session_abcdef0123456789" },
  ]) {
    assert.throws(
      () => parseProtocolResponse(policyUpdateResultLine({}, policyOverride), "req_policy_update"),
      { code: "protocol_error" },
      `policy_update_result policy override should be rejected: ${JSON.stringify(policyOverride)}`,
    );
  }
});

const methodResultLine = (overrides = {}, errorOverrides = {}) =>
  JSON.stringify({
    id: "req_call_method",
    version: 1,
    type: "method_result",
    status: "rejected",
    error: {
      code: "unsupported_method",
      message: "Method is not supported.",
      ...errorOverrides,
    },
    ...overrides,
  });

test("parseProtocolResponse accepts rejected method_result responses", () => {
  const response = assertMethodResultResponse(
    parseProtocolResponse(methodResultLine(), "req_call_method"),
  );
  assert.equal(response.type, "method_result");
  assert.equal(response.status, "rejected");
  assert.equal(response.error.code, "unsupported_method");
});

test("parseProtocolResponse accepts rejected Sui sign_transaction policy decisions", () => {
  const cases = [
    ["policy_rejected", "The request was rejected by device policy."],
    ["malformed_transaction", "Transaction bytes are malformed."],
    ["unsupported_transaction", "Transaction shape is not supported."],
    ["policy_error", "Active policy is unavailable."],
  ];
  for (const [code, message] of cases) {
    const response = assertMethodResultResponse(
      parseProtocolResponse(methodResultLine({}, { code, message }), "req_call_method"),
    );
    assert.equal(response.status, "rejected");
    assert.equal(response.error.code, code);
    assert.equal(response.error.message, message);
  }
});

test("parseProtocolResponse exposes call_method history write failures as top-level errors", () => {
  const response = parseProtocolResponse(
    JSON.stringify({
      id: "req_call_method",
      version: 1,
      type: "error",
      error: {
        code: "history_error",
        message: "Could not record method decision.",
      },
    }),
    "req_call_method",
  );
  assert.equal(response.type, "error");
  assert.equal(response.error.code, "history_error");
  assert.throws(() => assertMethodResultResponse(response), { code: "history_error" });
});

test("parseProtocolResponse rejects unsupported method_result shapes", () => {
  assert.throws(
    () => parseProtocolResponse(methodResultLine({ status: "approved", result: { signature: "x" } }), "req_call_method"),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        methodResultLine({
          status: "approved",
          chain: "sui",
          method: "sign_transaction",
          signature: "not-public",
          error: undefined,
        }),
        "req_call_method",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        methodResultLine({
          status: "approved",
          chain: "sui",
          method: "sign_personal_message",
          signature: "not-public",
          error: undefined,
        }),
        "req_call_method",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        methodResultLine({
          status: "approved",
          chain: "sui",
          method: "sign_transaction",
          signature: "not-public",
          txBytes: CANONICAL_TX_BYTES_BASE64,
          error: undefined,
        }),
        "req_call_method",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(methodResultLine({ sessionId: "session_abcdef0123456789" }), "req_call_method"),
    { code: "protocol_error" },
  );
  assert.throws(
    () => parseProtocolResponse(methodResultLine({}, { code: "policy_rejected", message: "wrong" }), "req_call_method"),
    { code: "protocol_error" },
  );
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.throws(
      () => parseProtocolResponse(methodResultLine({ [fieldName]: "secret-like value" }), "req_call_method"),
      { code: "protocol_error" },
      `secret-like method_result field ${fieldName} must be rejected`,
    );
  }
});

test("parseProtocolResponse accepts bounded signature_result product outcomes", () => {
  const signed = assertSignatureResultResponse(
    parseProtocolResponse(
      JSON.stringify({
        id: "req_signature",
        version: 1,
        type: "signature_result",
        status: "signed",
        reasonCode: "device_confirmed",
        chain: "sui",
        method: "sign_transaction",
        signature: Buffer.alloc(97, 1).toString("base64"),
      }),
      "req_signature",
    ),
  );
  assert.equal(signed.status, "signed");
  assert.equal(signed.reasonCode, "device_confirmed");
  assert.equal(signed.signature, Buffer.alloc(97, 1).toString("base64"));

  for (const terminal of [
    {
      status: "rejected",
      reasonCode: "device_rejected",
      message: "The signing request was rejected on the device.",
    },
    {
      status: "timed_out",
      reasonCode: "device_timed_out",
      message: "The signing request timed out on the device.",
    },
    {
      status: "failed",
      reasonCode: "signing_failed",
      message: "The device could not produce a signature.",
    },
  ]) {
    const response = assertSignatureResultResponse(
      parseProtocolResponse(
        JSON.stringify({
          id: "req_signature",
          version: 1,
          type: "signature_result",
          status: terminal.status,
          reasonCode: terminal.reasonCode,
          error: {
            code: terminal.reasonCode,
            message: terminal.message,
          },
        }),
        "req_signature",
      ),
    );
    assert.equal(response.status, terminal.status);
    assert.equal(response.reasonCode, terminal.reasonCode);
    if (response.status !== "signed") {
      assert.equal(response.error.code, terminal.reasonCode);
    }
  }
});

test("parseProtocolResponse rejects signature_result leaks and inconsistent terminal errors", () => {
  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_signature",
          version: 1,
          type: "signature_result",
          status: "signed",
          reasonCode: "device_confirmed",
          chain: "sui",
          method: "sign_transaction",
          signature: Buffer.alloc(96, 1).toString("base64"),
        }),
        "req_signature",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_signature",
          version: 1,
          type: "signature_result",
          status: "signed",
          reasonCode: "device_confirmed",
          chain: "sui",
          method: "sign_transaction",
          signature: Buffer.alloc(97, 1).toString("base64"),
          txBytes: CANONICAL_TX_BYTES_BASE64,
        }),
        "req_signature",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_signature",
          version: 1,
          type: "signature_result",
          status: "rejected",
          reasonCode: "device_rejected",
          error: {
            code: "device_timed_out",
            message: "The signing request timed out on the device.",
          },
        }),
        "req_signature",
      ),
    { code: "protocol_error" },
  );
  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_signature",
          version: 1,
          type: "signature_result",
          status: "rejected",
          reasonCode: "device_rejected",
          sessionId: "session_abcdef0123456789",
          error: {
            code: "device_rejected",
            message: "The signing request was rejected on the device.",
          },
        }),
        "req_signature",
      ),
    { code: "protocol_error" },
  );
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
