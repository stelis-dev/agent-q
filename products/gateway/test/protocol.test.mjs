import assert from "node:assert/strict";
import test from "node:test";
import {
  assertAccountsResponse,
  assertCapabilitiesResponse,
  assertMethodResultResponse,
  assertConnectResponse,
  assertDisconnectResponse,
  assertFactoryResetResponse,
  assertProvisioningResponse,
  assertRecoveryPhraseResponse,
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
  makeCancelProvisioningRequest,
  makeConfirmRecoveryPhraseBackupRequest,
  makeDisconnectRequest,
  makeFactoryResetRequest,
  makeGetCapabilitiesRequest,
  makeGetAccountsRequest,
  makeIdentifyDeviceRequest,
  makeGetStatusRequest,
  makeStartProvisioningRequest,
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
  for (const code of [
    "unsupported_type",
    "busy",
    "storage_error",
    "invalid_state",
    "invalid_setup_step",
    "unsupported_method",
    "rng_error",
    "ui_error",
    "generation_error",
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

test("parseProtocolResponse accepts a valid capabilities response with no signing methods", () => {
  const response = assertCapabilitiesResponse(
    parseProtocolResponse(capabilitiesLine(), "req_capabilities"),
  );
  assert.equal(response.type, "capabilities");
  assert.equal(response.chains.length, 1);
  assert.equal(response.chains[0].id, "sui");
  assert.equal(response.chains[0].accounts.length, 1);
  assert.equal(response.chains[0].accounts[0].keyScheme, "ed25519");
  assert.equal(response.chains[0].accounts[0].derivationPath, "m/44'/784'/0'/0'/0'");
  assert.deepEqual(response.chains[0].methods, []);
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

test("parseProtocolResponse accepts the current rejected method_result skeleton", () => {
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
    ["policy_action_not_implemented", "Policy action is not implemented."],
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

test("parseProtocolResponse rejects unsupported method_result shapes", () => {
  assert.throws(
    () => parseProtocolResponse(methodResultLine({ status: "approved", result: { signature: "x" } }), "req_call_method"),
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

test("creates provisioning requests without secret fields", () => {
  const start = makeStartProvisioningRequest(30000, "req_start_setup");
  assert.deepEqual(start, {
    id: "req_start_setup",
    version: 1,
    type: "start_provisioning",
    params: {
      approvalTimeoutMs: 30000,
    },
  });

  const cancel = makeCancelProvisioningRequest(30000, "req_cancel_setup");
  assert.deepEqual(cancel, {
    id: "req_cancel_setup",
    version: 1,
    type: "cancel_provisioning",
    params: {
      approvalTimeoutMs: 30000,
    },
  });

  const confirmRecoveryPhraseBackup = makeConfirmRecoveryPhraseBackupRequest(30000, "req_confirm_phrase");
  assert.deepEqual(confirmRecoveryPhraseBackup, {
    id: "req_confirm_phrase",
    version: 1,
    type: "confirm_recovery_phrase_backup",
    params: {
      approvalTimeoutMs: 30000,
    },
  });

  const factoryReset = makeFactoryResetRequest(30000, "req_factory_reset");
  assert.deepEqual(factoryReset, {
    id: "req_factory_reset",
    version: 1,
    type: "factory_reset",
    params: {
      approvalTimeoutMs: 30000,
    },
  });

  const serialized =
    serializeRequest(start) +
    serializeRequest(cancel) +
    serializeRequest(confirmRecoveryPhraseBackup) +
    serializeRequest(factoryReset);
  assert.doesNotMatch(serialized, /mnemonic|seed|private|secret|import/i);

  assert.throws(() => makeStartProvisioningRequest(0), /approvalTimeoutMs/);
  assert.throws(() => makeCancelProvisioningRequest(60001), /approvalTimeoutMs/);
  assert.throws(() => makeConfirmRecoveryPhraseBackupRequest(60001), /approvalTimeoutMs/);
  assert.throws(() => makeFactoryResetRequest(60001), /approvalTimeoutMs/);
  assert.throws(() => makeStartProvisioningRequest(30000, "req/unsafe"), /Invalid request id/);
});

test("parses provisioning transition responses and rejects malformed state", () => {
  const canceled = assertProvisioningResponse(
    parseProtocolResponse(
      JSON.stringify({
        id: "req_cancel_setup",
        version: 1,
        type: "provisioning_result",
        status: "canceled",
        provisioning: {
          state: "unprovisioned",
        },
      }),
      "req_cancel_setup",
    ),
  );
  assert.equal(canceled.status, "canceled");
  assert.equal(canceled.provisioning.state, "unprovisioned");

  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_start_setup",
          version: 1,
          type: "provisioning_result",
          status: "started",
          provisioning: {
            state: "signing_ready",
          },
        }),
        "req_start_setup",
      ),
    { code: "protocol_error" },
  );

  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_start_setup",
          version: 1,
          type: "provisioning_result",
          status: "canceled",
          provisioning: {
            state: "provisioning",
          },
        }),
        "req_start_setup",
      ),
    { code: "protocol_error" },
  );

  const rejected = parseProtocolResponse(
    JSON.stringify({
      id: "req_start_setup",
      version: 1,
      type: "error",
      error: {
        code: "rejected",
        message: "Provisioning start rejected.",
      },
    }),
    "req_start_setup",
  );
  assert.throws(() => assertProvisioningResponse(rejected), { code: "rejected" });
});

test("parses factory reset responses and requires unprovisioned state", () => {
  const reset = assertFactoryResetResponse(
    parseProtocolResponse(
      JSON.stringify({
        id: "req_factory_reset",
        version: 1,
        type: "factory_reset_result",
        status: "reset",
        provisioning: {
          state: "unprovisioned",
        },
      }),
      "req_factory_reset",
    ),
  );

  assert.equal(reset.status, "reset");
  assert.equal(reset.provisioning.state, "unprovisioned");

  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_factory_reset",
          version: 1,
          type: "factory_reset_result",
          status: "reset",
          provisioning: {
            state: "provisioned",
          },
        }),
        "req_factory_reset",
      ),
    { code: "protocol_error" },
  );

  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_factory_reset",
          version: 1,
          type: "factory_reset_result",
          status: "reset",
          provisioning: {
            state: "unprovisioned",
          },
          words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        }),
        "req_factory_reset",
      ),
    { code: "protocol_error" },
  );
});

test("parses recovery phrase responses and rejects host-carried secrets", () => {
  for (const [status, provisioningState] of [
    ["displayed", "unprovisioned"],
    ["confirmed", "provisioned"],
  ]) {
    const response = assertRecoveryPhraseResponse(
      parseProtocolResponse(
        JSON.stringify({
          id: `req_phrase_${status}`,
          version: 1,
          type: "recovery_phrase_result",
          status,
          provisioning: {
            state: provisioningState,
          },
        }),
        `req_phrase_${status}`,
      ),
    );

    assert.equal(response.status, status);
    assert.equal(response.provisioning.state, provisioningState);
  }

  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_phrase",
          version: 1,
          type: "recovery_phrase_result",
          status: "displayed",
          provisioning: {
            state: "provisioned",
          },
        }),
        "req_phrase",
      ),
    { code: "protocol_error" },
  );

  assert.throws(
    () =>
      parseProtocolResponse(
        JSON.stringify({
          id: "req_phrase",
          version: 1,
          type: "recovery_phrase_result",
          status: "confirmed",
          provisioning: {
            state: "unprovisioned",
          },
        }),
        "req_phrase",
      ),
    { code: "protocol_error" },
  );

  for (const extra of [
    { mnemonic: "never accept this" },
    { recoveryPhrase: "never accept this" },
    { words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
    { payload: { seed: "never accept this" } },
    {
      provisioning: {
        state: "provisioned",
        words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      },
    },
  ]) {
    assert.throws(
      () =>
        parseProtocolResponse(
          JSON.stringify({
            id: "req_phrase",
            version: 1,
            type: "recovery_phrase_result",
            status: "confirmed",
            provisioning: {
              state: "provisioned",
            },
            ...extra,
          }),
          "req_phrase",
        ),
      { code: "protocol_error" },
    );
  }

  const invalidState = parseProtocolResponse(
    JSON.stringify({
      id: "req_phrase",
      version: 1,
      type: "error",
      error: {
        code: "invalid_state",
        message: "Recovery phrase backup confirmation is valid only during mnemonic setup.",
      },
    }),
    "req_phrase",
  );
  assert.throws(() => assertRecoveryPhraseResponse(invalidState), { code: "invalid_state" });
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
