import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gatewaySuccessOutputSchemas } from "../dist/adapter-internal.js";
import { createDefaultDeviceClientCore } from "../dist/client.js";
import { createDefaultGatewayCore, GatewayCore } from "../dist/admin.js";
import { SIGN_RESULT_ERROR_MESSAGES, SUI_DERIVATION_PATH } from "../dist/protocol.js";

const SUI_ADDRESS = "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133";
const SUI_PUBLIC_KEY = "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk=";
const DEVICE_ID = "device-1";
const SUI_SIGNATURE = Buffer.alloc(97, 1).toString("base64");
const PERSONAL_MESSAGE_BYTES = Buffer.from("Agent-Q personal message").toString("base64");

function validLiveAccount() {
  return {
    chain: "sui",
    address: SUI_ADDRESS,
    publicKey: SUI_PUBLIC_KEY,
    keyScheme: "ed25519",
    derivationPath: SUI_DERIVATION_PATH,
  };
}

function validDevice() {
  return {
    deviceId: DEVICE_ID,
    state: "idle",
    firmwareName: "Agent-Q Firmware",
    hardware: "stackchan-cores3",
    firmwareVersion: "0.0.0",
  };
}

function validProvisioning() {
  return { state: "provisioned" };
}

function validLiveStatus() {
  return {
    source: "live",
    connected: true,
    portPath: "/dev/cu.usbmodem1",
    protocolResponse: {
      id: "req_status",
      version: 1,
      type: "status",
      device: validDevice(),
      provisioning: validProvisioning(),
    },
  };
}

function validPolicyDocument() {
  return {
    schema: "agentq.policy.v0",
    policyId: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
    defaultAction: "reject",
    ruleCount: 0,
    rules: [],
  };
}

function invalidUnboundedSignPolicyDocument() {
  return {
    schema: "agentq.policy.v0",
    policyId: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
    defaultAction: "reject",
    ruleCount: 1,
    rules: [
      {
        id: "allow_unbounded_transfer",
        chain: "sui",
        method: "sign_transaction",
        action: "sign",
        criteria: [
          { field: "sui.command_shape", op: "eq", value: "restricted_transfer" },
          { field: "sui.amount_raw", op: "lte", value: "500000000" },
        ],
      },
    ],
  };
}

function invalidUnsupportedRejectPolicyDocument() {
  return {
    schema: "agentq.policy.v0",
    policyId: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
    defaultAction: "reject",
    ruleCount: 1,
    rules: [
      {
        id: "reject_unknown_method",
        chain: "unknown",
        method: "unknown_method",
        action: "reject",
        criteria: [],
      },
    ],
  };
}

function validGatewaySuccessOutputSamples() {
  return {
    scanDevices: { source: "live", devices: [], failures: [], activeDeviceId: null },
    identifyDevices: { source: "live", devices: [], activeDeviceId: null },
    selectDevice: {
      source: "selected",
      activeDeviceId: DEVICE_ID,
      purpose: null,
      device: validDevice(),
    },
    getDeviceStatus: validLiveStatus(),
    listDevices: {
      source: "list",
      devices: [
        {
          deviceId: DEVICE_ID,
          transport: "usb",
          lastPortHint: "/dev/cu.usbmodem1",
          lastSeenAt: "2026-05-28T00:00:00.000Z",
          label: null,
          lastStatus: {
            device: validDevice(),
            provisioning: validProvisioning(),
          },
          assignedPurposes: [],
          isDefaultActive: true,
          runtimeSession: {
            sessionTtlMs: 4294967295,
            connectedAt: "2026-05-28T00:00:00.000Z",
          },
        },
      ],
      activeDeviceId: DEVICE_ID,
      activeDeviceIdsByPurpose: {},
    },
    setDeviceMetadata: { source: "metadata", deviceId: DEVICE_ID, label: null },
    connectDevice: {
      source: "connected",
      deviceId: DEVICE_ID,
      sessionTtlMs: 4294967295,
      connectedAt: "2026-05-28T00:00:00.000Z",
      device: validDevice(),
    },
    disconnectDevice: { source: "disconnected", deviceId: DEVICE_ID, reason: "firmware_confirmed" },
    getCapabilities: {
      source: "live",
      deviceId: DEVICE_ID,
      capabilities: [
        {
          id: "sui",
          accounts: [
            {
              keyScheme: "ed25519",
              derivationPath: SUI_DERIVATION_PATH,
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
    },
    getAccounts: { source: "live", deviceId: DEVICE_ID, accounts: [validLiveAccount()] },
    policyGet: { source: "live", deviceId: DEVICE_ID, policy: validPolicyDocument() },
    getApprovalHistory: { source: "live", deviceId: DEVICE_ID, records: [], hasMore: false },
    signTransaction: validSignTransactionSignedOutput(),
    signPersonalMessage: validSignPersonalMessageSignedOutput(),
    policyPropose: {
      source: "live",
      deviceId: DEVICE_ID,
      status: "applied",
      reasonCode: "device_confirmed",
      policy: {
        policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
        ruleCount: 0,
        highestAction: "reject",
      },
    },
  };
}

function validSignTransactionSignedOutput() {
  return {
    source: "live",
    deviceId: DEVICE_ID,
    status: "signed",
    authorization: "user",
    chain: "sui",
    method: "sign_transaction",
    signature: SUI_SIGNATURE,
  };
}

function validSignPersonalMessageSignedOutput() {
  return {
    source: "live",
    deviceId: DEVICE_ID,
    status: "signed",
    authorization: "user",
    chain: "sui",
    method: "sign_personal_message",
    signature: SUI_SIGNATURE,
    messageBytes: PERSONAL_MESSAGE_BYTES,
  };
}

test("gateway success output schemas reject unknown top-level fields", () => {
  const samples = validGatewaySuccessOutputSamples();
  for (const [name, sample] of Object.entries(samples)) {
    const schema = gatewaySuccessOutputSchemas[name];
    assert.equal(schema.safeParse(sample).success, true, `${name} sample must be valid`);
    assert.throws(
      () => schema.parse({ ...sample, sessionId: "session_should_not_leak" }),
      `${name} must reject unknown top-level fields`,
    );
  }
});

test("gateway success output schemas reject unknown nested fields", () => {
  const samples = validGatewaySuccessOutputSamples();
  assert.throws(() => gatewaySuccessOutputSchemas.connectDevice.parse({
    ...samples.connectDevice,
    device: { ...samples.connectDevice.device, sessionId: "session_should_not_leak" },
  }));
  assert.throws(() => gatewaySuccessOutputSchemas.getDeviceStatus.parse({
    ...samples.getDeviceStatus,
    protocolResponse: {
      ...samples.getDeviceStatus.protocolResponse,
      sessionId: "session_should_not_leak",
    },
  }));
  assert.throws(() => gatewaySuccessOutputSchemas.listDevices.parse({
    ...samples.listDevices,
    devices: [
      {
        ...samples.listDevices.devices[0],
        sessionId: "session_should_not_leak",
      },
    ],
  }));
  assert.throws(() => gatewaySuccessOutputSchemas.policyGet.parse({
    ...samples.policyGet,
    policy: { ...samples.policyGet.policy, sessionId: "session_should_not_leak" },
  }));
  assert.throws(() => gatewaySuccessOutputSchemas.policyPropose.parse({
    ...samples.policyPropose,
    policy: { ...samples.policyPropose.policy, sessionId: "session_should_not_leak" },
  }));
});

test("gateway success output schemas reject semantically invalid policy documents", () => {
  const samples = validGatewaySuccessOutputSamples();
  assert.throws(() => gatewaySuccessOutputSchemas.policyGet.parse({
    ...samples.policyGet,
    policy: invalidUnboundedSignPolicyDocument(),
  }));
  assert.throws(() => gatewaySuccessOutputSchemas.policyGet.parse({
    ...samples.policyGet,
    policy: invalidUnsupportedRejectPolicyDocument(),
  }));
});

test("client entrypoint constructs an admin-disabled device core facade", () => {
  const core = createDefaultDeviceClientCore();
  assert.equal(typeof core.scanDevices, "function");
  assert.equal(typeof core.signTransaction, "function");
  assert.equal(core.signByUser, undefined);
  assert.equal(core.signByPolicy, undefined);
  assert.equal(core.policyPropose, undefined);
});

test("admin entrypoint constructs the admin-capable Gateway core", () => {
  const core = createDefaultGatewayCore();
  assert.equal(core instanceof GatewayCore, true);
});

test("client entrypoint does not import MCP or Admin adapters", async () => {
  const clientPath = fileURLToPath(new URL("../dist/client.js", import.meta.url));
  const source = await readFile(clientPath, "utf8");
  assert.doesNotMatch(source, /["']\.\/mcp\.js["']/);
  assert.doesNotMatch(source, /["']\.\/admin\.js["']/);
});

test("package metadata exposes the current client entrypoints", async () => {
  const packagePath = fileURLToPath(new URL("../package.json", import.meta.url));
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  assert.equal(packageJson.name, "@stelis/agent-q-client");
  assert.equal(packageJson.main, "./dist/client.js");
  assert.equal(packageJson.types, "./dist/client.d.ts");
  assert.deepEqual(Object.keys(packageJson.exports).sort(), [
    ".",
    "./adapter-internal",
    "./admin",
    "./client",
    "./package.json",
    "./protocol",
    "./provider-protocol",
  ]);
  assert.deepEqual(packageJson.exports["."], {
    types: "./dist/client.d.ts",
    import: "./dist/client.js",
  });
  assert.deepEqual(packageJson.exports["./client"], {
    types: "./dist/client.d.ts",
    import: "./dist/client.js",
  });
  assert.deepEqual(packageJson.exports["./admin"], {
    types: "./dist/admin.d.ts",
    import: "./dist/admin.js",
  });
  assert.equal(packageJson.exports["./usb"], undefined);
  assert.equal(packageJson.bin, undefined);
  assert.equal(packageJson.exports["./mcp"], undefined);
  assert.equal(packageJson.exports["./provider"], undefined);
});

test("package self-reference resolves only client entrypoints", async () => {
  const root = await import("@stelis/agent-q-client");
  const admin = await import("@stelis/agent-q-client/admin");
  const adapterInternal = await import("@stelis/agent-q-client/adapter-internal");
  const client = await import("@stelis/agent-q-client/client");
  const protocol = await import("@stelis/agent-q-client/protocol");
  const providerProtocol = await import("@stelis/agent-q-client/provider-protocol");
  assert.equal(typeof root.createDefaultDeviceClientCore, "function");
  assert.equal(root.createDefaultGatewayCore, undefined);
  assert.equal(typeof admin.createDefaultGatewayCore, "function");
  assert.equal(typeof adapterInternal.gatewaySuccessOutputSchemas, "object");
  assert.equal(typeof client.createDefaultDeviceClientCore, "function");
  assert.equal(typeof protocol.makeGetStatusRequest, "function");
  assert.equal(typeof protocol.makeSignTransactionRequest, "function");
  assert.equal(providerProtocol.makeGetStatusRequest, undefined);
  assert.equal(providerProtocol.makePolicyGetRequest, undefined);
  assert.equal(providerProtocol.makePolicyProposeRequest, undefined);
  assert.equal(providerProtocol.makeGetApprovalHistoryRequest, undefined);
  assert.equal(providerProtocol.AGENT_Q_POLICY_SCHEMA, undefined);
  assert.equal(providerProtocol.MAX_POLICY_RULE_COUNT, undefined);
  assert.equal(providerProtocol.MAX_APPROVAL_HISTORY_RECORDS, undefined);
  assert.equal(providerProtocol.POLICY_PROPOSE_RESULT_STATUSES, undefined);
  assert.equal(providerProtocol.serializeRequest, undefined);
  assert.equal(typeof providerProtocol.serializeProviderProtocolRequest, "function");
  assert.equal(providerProtocol.INTERNAL_CONNECT_DEADLINE_MS, 185000);
  assert.equal(providerProtocol.INTERNAL_SIGN_TRANSACTION_DEADLINE_MS, 185000);
  assert.equal(providerProtocol.INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS, 185000);
  assert.equal(typeof providerProtocol.makeConnectRequest, "function");
  assert.equal(typeof providerProtocol.makeGetCapabilitiesRequest, "function");
  assert.equal(typeof providerProtocol.makeGetAccountsRequest, "function");
  assert.equal(typeof providerProtocol.makeSignTransactionRequest, "function");
  assert.equal(typeof providerProtocol.makeSignPersonalMessageRequest, "function");
  assert.equal(typeof admin.SerialPortUsbDriver, "function");
  for (const subpath of ["config", "core", "errors", "gateway-output-schema", "public-error", "safe-text", "usb"]) {
    await assert.rejects(() => import(`@stelis/agent-q-client/${subpath}`), {
      code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
    });
  }
  await assert.rejects(() => import("@stelis/agent-q-client/mcp"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
  await assert.rejects(() => import("@stelis/agent-q-client/provider"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
});

test("provider-protocol declaration stays type-bounded to provider requests", async () => {
  const typesPath = fileURLToPath(new URL("../dist/provider-protocol.d.ts", import.meta.url));
  const types = await readFile(typesPath, "utf8");
  assert.match(types, /serializeProviderProtocolRequest\(request: ProviderProtocolRequest\): string/);
  assert.doesNotMatch(types, /serializeRequest/);
  assert.doesNotMatch(types, /\bProtocolRequest\b/);
  assert.doesNotMatch(types, /PolicyGetRequest/);
  assert.doesNotMatch(types, /PolicyProposeRequest/);
  assert.doesNotMatch(types, /GetApprovalHistoryRequest/);
  assert.doesNotMatch(types, /AGENT_Q_POLICY_SCHEMA/);
  assert.doesNotMatch(types, /MAX_POLICY_RULE_COUNT/);
  assert.doesNotMatch(types, /MAX_APPROVAL_HISTORY_RECORDS/);
  assert.doesNotMatch(types, /POLICY_PROPOSE_RESULT_STATUSES/);
});

test("provider-protocol serializer rejects non-provider requests at runtime", async () => {
  const providerProtocol = await import("@stelis/agent-q-client/provider-protocol");
  const blockedRequests = [
    {
      id: "req_policy_get",
      version: 1,
      type: "policy_get",
      sessionId: "session_abcdef0123456789",
    },
    {
      id: "req_policy_propose",
      version: 1,
      type: "policy_propose",
      sessionId: "session_abcdef0123456789",
      params: { policy: {} },
    },
    {
      id: "req_history",
      version: 1,
      type: "get_approval_history",
      sessionId: "session_abcdef0123456789",
      params: { limit: 1 },
    },
  ];
  for (const request of blockedRequests) {
    assert.throws(
      () => providerProtocol.serializeProviderProtocolRequest(request),
      { code: "invalid_method" },
      `${request.type} must not serialize through provider-protocol`,
    );
  }
});

test("provider-protocol serializer exact-validates provider requests at runtime", async () => {
  const providerProtocol = await import("@stelis/agent-q-client/provider-protocol");
  const requestId = "req_1234567890abcdef12345678";
  const sessionId = "session_abcdef0123456789";

  const validRequest = providerProtocol.makeSignTransactionRequest(
    sessionId,
    "sui",
    "sign_transaction",
    { network: "testnet", txBytes: "AQID" },
    requestId,
  );
  assert.equal(
    providerProtocol.serializeProviderProtocolRequest(validRequest),
    `${JSON.stringify(validRequest)}\n`,
  );

  const forgedRequests = [
    {
      id: requestId,
      version: 1,
      type: "connect",
      params: { gatewayName: "Agent-Q Browser" },
      policy_get: true,
    },
    {
      id: requestId,
      version: 1,
      type: "connect",
      params: { gatewayName: "Agent-Q Browser", sessionId: "session_should_not_pass" },
    },
    {
      id: requestId,
      version: 1,
      type: "get_accounts",
      sessionId,
      timeoutMs: 30000,
    },
    {
      id: requestId,
      version: 1,
      type: "sign_transaction",
      sessionId,
      chain: "sui",
      method: "sign_transaction",
      params: { network: "testnet", txBytes: "AQID" },
      timeoutMs: 30000,
    },
    {
      id: requestId,
      version: 1,
      type: "sign_transaction",
      sessionId,
      chain: "sui",
      method: "sign_transaction",
      params: { network: "testnet", txBytes: "AQID", authorization: "policy" },
    },
    {
      id: requestId,
      version: 1,
      type: "sign_transaction",
      sessionId,
      chain: "evm",
      method: "sign_transaction",
      params: { network: "testnet", txBytes: "AQID" },
    },
    {
      id: requestId,
      version: 1,
      type: "sign_personal_message",
      sessionId,
      chain: "sui",
      method: "sign_personal_message",
      params: { network: "testnet", message: "AQID", txBytes: "AQID" },
    },
  ];
  for (const request of forgedRequests) {
    assert.throws(
      () => providerProtocol.serializeProviderProtocolRequest(request),
      /unsupported|Invalid|invalid|must/,
      `${request.type} forged provider request must not serialize`,
    );
  }
});

test("adapter output schema keeps signing method result shapes exact", () => {
  const transactionSchema = gatewaySuccessOutputSchemas.signTransaction;
  const personalMessageSchema = gatewaySuccessOutputSchemas.signPersonalMessage;
  assert.equal(transactionSchema.parse(validSignTransactionSignedOutput()).method, "sign_transaction");
  assert.equal(personalMessageSchema.parse(validSignPersonalMessageSignedOutput()).method, "sign_personal_message");
  const largeMessageBytes = Buffer.alloc(300, 7).toString("base64");
  assert.equal(
    personalMessageSchema.parse({
      ...validSignPersonalMessageSignedOutput(),
      messageBytes: largeMessageBytes,
    }).messageBytes,
    largeMessageBytes,
  );

  assert.throws(() => transactionSchema.parse({
    ...validSignTransactionSignedOutput(),
    messageBytes: PERSONAL_MESSAGE_BYTES,
  }));
  assert.throws(() => transactionSchema.parse({
    ...validSignTransactionSignedOutput(),
    txBytes: "AQID",
  }));
  assert.throws(() => transactionSchema.parse({
    ...validSignTransactionSignedOutput(),
    authorization: "policy",
    messageBytes: PERSONAL_MESSAGE_BYTES,
  }));
  assert.throws(() => personalMessageSchema.parse({
    ...validSignPersonalMessageSignedOutput(),
    txBytes: "AQID",
  }));
});

test("adapter output schema keeps terminal signing results exact", () => {
  const userTerminal = {
    source: "live",
    deviceId: DEVICE_ID,
    status: "user_rejected",
    authorization: "user",
    error: {
      code: "user_rejected",
      message: SIGN_RESULT_ERROR_MESSAGES.user_rejected,
    },
  };
  const policyTerminal = {
    source: "live",
    deviceId: DEVICE_ID,
    status: "policy_rejected",
    authorization: "policy",
    policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
    ruleRef: "default",
    error: {
      code: "policy_rejected",
      message: SIGN_RESULT_ERROR_MESSAGES.policy_rejected,
    },
  };
  const schema = gatewaySuccessOutputSchemas.signTransaction;
  assert.equal(schema.parse(userTerminal).status, "user_rejected");
  assert.equal(schema.parse(policyTerminal).status, "policy_rejected");
  assert.throws(() => schema.parse({ ...userTerminal, signature: SUI_SIGNATURE }));
  assert.throws(() => schema.parse({ ...userTerminal, messageBytes: PERSONAL_MESSAGE_BYTES }));
  assert.throws(() => schema.parse({ ...policyTerminal, signature: SUI_SIGNATURE }));
  assert.throws(() => schema.parse({
    ...userTerminal,
    error: {
      ...userTerminal.error,
      sessionId: "session_should_not_leak",
    },
  }));
});

test("adapter output schema keeps Sui account projection exact", () => {
  const schema = gatewaySuccessOutputSchemas.getAccounts;
  const output = {
    source: "live",
    deviceId: DEVICE_ID,
    accounts: [validLiveAccount()],
  };
  assert.equal(schema.parse(output).accounts[0].address, SUI_ADDRESS);
  assert.throws(() => schema.parse({ ...output, sessionId: "session_should_not_leak" }));
  assert.throws(() => schema.parse({
    ...output,
    accounts: [
      {
        ...validLiveAccount(),
        label: "unexpected",
      },
    ],
  }));
});
