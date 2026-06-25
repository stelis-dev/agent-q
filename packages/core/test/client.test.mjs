import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { hostSuccessOutputSchemas } from "../dist/adapter-internal.js";
import { createDefaultAgentQDeviceClient } from "../dist/device.js";
import { createDefaultAgentQCore, AgentQCore } from "../dist/core.js";
import {
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_SIGN_RESULT_PAYLOAD_BASE64_CHARS,
  SIGN_RESULT_ERROR_MESSAGES,
  SUI_DERIVATION_PATH,
} from "../dist/protocol.js";

const SUI_ADDRESS = "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133";
const SUI_PUBLIC_KEY = "ACJkf+7vNjBgvUIFoWcaFfEKEjZ2WRixtfY42C8zz8Rp";
const DEVICE_ID = "device-1";
const SUI_SIGNATURE_BYTES = Buffer.alloc(97, 1);
SUI_SIGNATURE_BYTES[0] = 0;
const SUI_SIGNATURE = SUI_SIGNATURE_BYTES.toString("base64");
const ZKLOGIN_SIGNATURE_BYTES = Buffer.alloc(145, 6);
ZKLOGIN_SIGNATURE_BYTES[0] = 5;
const ZKLOGIN_SIGNATURE = ZKLOGIN_SIGNATURE_BYTES.toString("base64");
const PERSONAL_MESSAGE_BYTES = Buffer.from("Agent-Q personal message").toString("base64");

function validLiveAccount() {
  return {
    chain: "sui",
    address: SUI_ADDRESS,
    publicKey: SUI_PUBLIC_KEY,
    keyScheme: "ed25519",
    derivationPath: SUI_DERIVATION_PATH,
    sponsoredTransactions: {
      acceptGasSponsor: false,
    },
  };
}

function validCredentialCapability() {
  return {
    chain: "sui",
    credential: "zklogin",
    operations: ["credential_prepare", "credential_propose"],
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
    schema: "agentq.policy",
    policyId: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
    defaultAction: "reject",
    blockchainCount: 1,
    networkCount: 1,
    policyCount: 0,
    conditionCount: 0,
    blockchains: [
      {
        blockchain: "sui",
        networks: [
          {
            network: "testnet",
            policies: [],
          },
        ],
      },
    ],
  };
}

function invalidMalformedSignPolicyDocument() {
  return {
    schema: "agentq.policy",
    policyId: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
    defaultAction: "reject",
    blockchainCount: 1,
    networkCount: 1,
    policyCount: 1,
    conditionCount: 2,
    blockchains: [
      {
        blockchain: "sui",
        networks: [
          {
            network: "testnet",
            policies: [
              {
                id: "sign_bad_field",
                action: "sign",
                conditions: [
                  { field: "sui.unsupported_field", op: "eq", value: "move_call" },
                  { field: "sui.gas_budget_raw", op: "lte", value: "500000000" },
                ],
              },
            ],
          },
        ],
      },
    ],
  };
}

function invalidUnsupportedScopePolicyDocument() {
  return {
    schema: "agentq.policy",
    policyId: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
    defaultAction: "reject",
    blockchainCount: 1,
    networkCount: 1,
    policyCount: 1,
    conditionCount: 0,
    blockchains: [
      {
        blockchain: "unknown",
        networks: [
          {
            network: "testnet",
            policies: [
              {
                id: "reject_unknown_scope",
                action: "reject",
                conditions: [],
              },
            ],
          },
        ],
      },
    ],
  };
}

function validAgentQSuccessOutputSamples() {
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
      credentials: [validCredentialCapability()],
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
        blockchainCount: 1,
        networkCount: 1,
        policyCount: 0,
        conditionCount: 0,
        highestAction: "reject",
      },
    },
    credentialPrepare: {
      source: "live",
      deviceId: DEVICE_ID,
      chain: "sui",
      credential: "zklogin",
      preparation: {
        address: SUI_ADDRESS,
        publicKey: SUI_PUBLIC_KEY,
        keyScheme: "ed25519",
      },
    },
    credentialPropose: {
      source: "live",
      deviceId: DEVICE_ID,
      status: "activated",
      reasonCode: "activated",
      sessionEnded: true,
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

test("agent-q success output schemas reject unknown top-level fields", () => {
  const samples = validAgentQSuccessOutputSamples();
  for (const [name, sample] of Object.entries(samples)) {
    const schema = hostSuccessOutputSchemas[name];
    assert.equal(schema.safeParse(sample).success, true, `${name} sample must be valid`);
    assert.throws(
      () => schema.parse({ ...sample, sessionId: "session_should_not_leak" }),
      `${name} must reject unknown top-level fields`,
    );
  }
});

test("agent-q success output schemas reject unknown nested fields", () => {
  const samples = validAgentQSuccessOutputSamples();
  assert.throws(() => hostSuccessOutputSchemas.connectDevice.parse({
    ...samples.connectDevice,
    device: { ...samples.connectDevice.device, sessionId: "session_should_not_leak" },
  }));
  assert.throws(() => hostSuccessOutputSchemas.getDeviceStatus.parse({
    ...samples.getDeviceStatus,
    protocolResponse: {
      ...samples.getDeviceStatus.protocolResponse,
      sessionId: "session_should_not_leak",
    },
  }));
  assert.throws(() => hostSuccessOutputSchemas.listDevices.parse({
    ...samples.listDevices,
    devices: [
      {
        ...samples.listDevices.devices[0],
        sessionId: "session_should_not_leak",
      },
    ],
  }));
  assert.throws(() => hostSuccessOutputSchemas.policyGet.parse({
    ...samples.policyGet,
    policy: { ...samples.policyGet.policy, sessionId: "session_should_not_leak" },
  }));
  assert.throws(() => hostSuccessOutputSchemas.policyPropose.parse({
    ...samples.policyPropose,
    policy: { ...samples.policyPropose.policy, sessionId: "session_should_not_leak" },
  }));
  assert.throws(() => hostSuccessOutputSchemas.getCapabilities.parse({
    ...samples.getCapabilities,
    credentials: [
      {
        ...validCredentialCapability(),
        sessionId: "session_should_not_leak",
      },
    ],
  }));
  assert.throws(() => hostSuccessOutputSchemas.credentialPrepare.parse({
    ...samples.credentialPrepare,
    preparation: { ...samples.credentialPrepare.preparation, jwt: "must_not_leak" },
  }));
});

test("agent-q success output schemas reject semantically invalid policy documents", () => {
  const samples = validAgentQSuccessOutputSamples();
  assert.throws(() => hostSuccessOutputSchemas.policyGet.parse({
    ...samples.policyGet,
    policy: invalidMalformedSignPolicyDocument(),
  }));
  assert.throws(() => hostSuccessOutputSchemas.policyGet.parse({
    ...samples.policyGet,
    policy: invalidUnsupportedScopePolicyDocument(),
  }));
});

test("device entrypoint constructs a limited device API facade", () => {
  const core = createDefaultAgentQDeviceClient();
  assert.equal(typeof core.scanDevices, "function");
  assert.equal(typeof core.signTransaction, "function");
  assert.equal(typeof core.credentialPrepare, "function");
  assert.equal(typeof core.credentialPropose, "function");
  assert.equal(core.signByUser, undefined);
  assert.equal(core.signByPolicy, undefined);
  assert.equal(core.policyPropose, undefined);
});

test("root entrypoint constructs the full Agent-Q core", () => {
  const core = createDefaultAgentQCore();
  assert.equal(core instanceof AgentQCore, true);
});

test("device entrypoint does not import server adapters", async () => {
  const clientPath = fileURLToPath(new URL("../dist/device.js", import.meta.url));
  const source = await readFile(clientPath, "utf8");
  assert.doesNotMatch(source, /["']\.\/mcp\.js["']/);
  assert.doesNotMatch(source, /["']\.\/admin\.js["']/);
});

test("package metadata exposes the current core entrypoints", async () => {
  const packagePath = fileURLToPath(new URL("../package.json", import.meta.url));
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  assert.equal(packageJson.name, "@stelis/agent-q-core");
  assert.equal(packageJson.main, "./dist/core.js");
  assert.equal(packageJson.types, "./dist/core.d.ts");
  assert.deepEqual(Object.keys(packageJson.exports).sort(), [
    ".",
    "./adapter-internal",
    "./device",
    "./package.json",
    "./protocol",
    "./provider-protocol",
  ]);
  assert.deepEqual(packageJson.exports["."], {
    types: "./dist/core.d.ts",
    import: "./dist/core.js",
  });
  assert.deepEqual(packageJson.exports["./device"], {
    types: "./dist/device.d.ts",
    import: "./dist/device.js",
  });
  assert.equal(packageJson.exports["./usb"], undefined);
  assert.equal(packageJson.exports["./payload-delivery-internal"], undefined);
  assert.equal(packageJson.bin, undefined);
  assert.equal(packageJson.exports["./mcp"], undefined);
  assert.equal(packageJson.exports["./provider"], undefined);
});

test("package self-reference resolves only core entrypoints", async () => {
  const root = await import("@stelis/agent-q-core");
  const adapterInternal = await import("@stelis/agent-q-core/adapter-internal");
  const device = await import("@stelis/agent-q-core/device");
  const protocol = await import("@stelis/agent-q-core/protocol");
  const providerProtocol = await import("@stelis/agent-q-core/provider-protocol");
  assert.equal(typeof root.createDefaultAgentQCore, "function");
  assert.equal(root.createDefaultAgentQDeviceClient, undefined);
  assert.equal(typeof adapterInternal.hostSuccessOutputSchemas, "object");
  assert.equal(typeof adapterInternal.requestDevice, "function");
  assert.equal(typeof device.createDefaultAgentQDeviceClient, "function");
  assert.equal(protocol.makeGetStatusRequest, undefined);
  assert.equal(protocol.makeSignTransactionRequest, undefined);
  assert.equal(protocol.makeSignPersonalMessageRequest, undefined);
  assert.equal(protocol.serializeRequest, undefined);
  assert.equal(protocol.makeGetResultRequest, undefined);
  assert.equal(protocol.makeAckResultRequest, undefined);
  assert.equal(protocol.assertAckResultResponse, undefined);
  assert.equal(protocol.makePayloadTransferBeginRequest, undefined);
  assert.equal(protocol.makePayloadTransferChunkRequest, undefined);
  assert.equal(protocol.makePayloadTransferFinishRequest, undefined);
  assert.equal(protocol.makePayloadTransferAbortRequest, undefined);
  assert.equal(protocol.serializePayloadTransferRequest, undefined);
  assert.equal(protocol.PayloadTransferRequest, undefined);
  await assert.rejects(() => import("@stelis/agent-q-core/protocol-recovery"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
  await assert.rejects(() => import("@stelis/agent-q-core/protocol-payload-delivery"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
  assert.equal(providerProtocol.makeGetResultRequest, undefined);
  assert.equal(providerProtocol.makeAckResultRequest, undefined);
  assert.equal(providerProtocol.assertAckResultResponse, undefined);
  assert.equal(providerProtocol.makePayloadTransferBeginRequest, undefined);
  assert.equal(providerProtocol.makePayloadTransferChunkRequest, undefined);
  assert.equal(providerProtocol.makePayloadTransferFinishRequest, undefined);
  assert.equal(providerProtocol.makePayloadTransferAbortRequest, undefined);
  assert.equal(providerProtocol.makeGetStatusRequest, undefined);
  assert.equal(providerProtocol.makePolicyGetRequest, undefined);
  assert.equal(providerProtocol.makePolicyProposeRequest, undefined);
  assert.equal(providerProtocol.makeCredentialPrepareRequest, undefined);
  assert.equal(providerProtocol.makeCredentialProposeRequest, undefined);
  assert.equal(providerProtocol.makeGetApprovalHistoryRequest, undefined);
  assert.equal(providerProtocol.AGENT_Q_POLICY_SCHEMA, undefined);
  assert.equal(providerProtocol.MAX_POLICY_TOTAL_POLICIES, undefined);
  assert.equal(providerProtocol.MAX_APPROVAL_HISTORY_RECORDS, undefined);
  assert.equal(providerProtocol.POLICY_PROPOSE_RESULT_STATUSES, undefined);
  assert.equal(providerProtocol.serializeRequest, undefined);
  assert.equal(providerProtocol.serializeProviderProtocolRequest, undefined);
  assert.equal(providerProtocol.INTERNAL_CONNECT_DEADLINE_MS, 185000);
  assert.equal(providerProtocol.INTERNAL_SIGN_TRANSACTION_DEADLINE_MS, 185000);
  assert.equal(providerProtocol.INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS, 185000);
  assert.equal(providerProtocol.makeConnectRequest, undefined);
  assert.equal(providerProtocol.makeGetCapabilitiesRequest, undefined);
  assert.equal(providerProtocol.makeGetAccountsRequest, undefined);
  assert.equal(providerProtocol.makeSignTransactionRequest, undefined);
  assert.equal(providerProtocol.makeSignPersonalMessageRequest, undefined);
  assert.equal(typeof root.SerialPortUsbDriver, "function");
  for (const subpath of ["config", "core", "errors", "agent-q-output-schema", "public-error", "safe-text", "usb"]) {
    await assert.rejects(() => import(`@stelis/agent-q-core/${subpath}`), {
      code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
    });
  }
  await assert.rejects(() => import("@stelis/agent-q-core/mcp"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
  await assert.rejects(() => import("@stelis/agent-q-core/provider"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
});

test("provider-protocol declaration stays type-bounded to provider requests", async () => {
  const typesPath = fileURLToPath(new URL("../dist/provider-protocol.d.ts", import.meta.url));
  const types = await readFile(typesPath, "utf8");
  assert.doesNotMatch(types, /serializeProviderProtocolRequest/);
  assert.doesNotMatch(types, /serializeRequest/);
  assert.doesNotMatch(types, /\bProtocolRequest\b/);
  assert.doesNotMatch(types, /\bProviderProtocolRequest\b/);
  assert.doesNotMatch(types, /makeConnectRequest/);
  assert.doesNotMatch(types, /makeDisconnectRequest/);
  assert.doesNotMatch(types, /makeGetCapabilitiesRequest/);
  assert.doesNotMatch(types, /makeGetAccountsRequest/);
  assert.doesNotMatch(types, /makeSignTransactionRequest/);
  assert.doesNotMatch(types, /makeSignPersonalMessageRequest/);
  assert.doesNotMatch(types, /PolicyGetRequest/);
  assert.doesNotMatch(types, /PolicyProposeRequest/);
  assert.doesNotMatch(types, /CredentialPrepareRequest/);
  assert.doesNotMatch(types, /CredentialProposeRequest/);
  assert.doesNotMatch(types, /GetApprovalHistoryRequest/);
  assert.doesNotMatch(types, /AGENT_Q_POLICY_SCHEMA/);
  assert.doesNotMatch(types, /MAX_POLICY_TOTAL_POLICIES/);
  assert.doesNotMatch(types, /MAX_APPROVAL_HISTORY_RECORDS/);
  assert.doesNotMatch(types, /POLICY_PROPOSE_RESULT_STATUSES/);
  assert.doesNotMatch(types, /makeGetResultRequest/);
  assert.doesNotMatch(types, /makeAckResultRequest/);
  assert.doesNotMatch(types, /assertAckResultResponse/);
  assert.doesNotMatch(types, /GetResultRequest/);
  assert.doesNotMatch(types, /AckResultRequest/);
  assert.doesNotMatch(types, /AckResultResponse/);
  assert.doesNotMatch(types, /protocol-recovery/);
  assert.doesNotMatch(types, /protocol-payload-delivery/);
  assert.doesNotMatch(types, /makePayloadTransferBeginRequest/);
  assert.doesNotMatch(types, /makePayloadTransferChunkRequest/);
  assert.doesNotMatch(types, /makePayloadTransferFinishRequest/);
  assert.doesNotMatch(types, /makePayloadTransferAbortRequest/);
  assert.doesNotMatch(types, /PayloadUploadRequest/);
  assert.doesNotMatch(types, /PayloadTransferRequest/);
  assert.doesNotMatch(types, /get_result/);
  assert.doesNotMatch(types, /ack_result/);
  assert.doesNotMatch(types, /payload_transfer/);
});

test("adapter-internal declaration exposes requestDevice without payload-transfer wire primitives", async () => {
  const typesPath = fileURLToPath(new URL("../dist/adapter-internal.d.ts", import.meta.url));
  const transportTypesPath = fileURLToPath(new URL("../dist/device-request-transport.d.ts", import.meta.url));
  const types = `${await readFile(typesPath, "utf8")}\n${await readFile(transportTypesPath, "utf8")}`;
  assert.match(types, /requestDevice/);
  assert.match(types, /requestLine:\s*string/);
  assert.doesNotMatch(types, /DeviceWireRequest/);
  assert.doesNotMatch(types, /serializeDeviceWireRequest/);
  assert.doesNotMatch(types, /makeDeviceWireRequest/);
  assert.doesNotMatch(types, /PayloadTransferRequest/);
  assert.doesNotMatch(types, /serializePayloadTransferRequest/);
  assert.doesNotMatch(types, /protocol-payload-delivery/);
  assert.doesNotMatch(types, /payload_transfer/);
});

test("client internals keep signing and recovery helper ownership separated", async () => {
  const protocolSource = await readFile(fileURLToPath(new URL("../src/protocol.ts", import.meta.url)), "utf8");
  const coreSource = await readFile(fileURLToPath(new URL("../src/core.ts", import.meta.url)), "utf8");
  const usbSource = await readFile(fileURLToPath(new URL("../src/usb.ts", import.meta.url)), "utf8");
  const providerProtocolSource = await readFile(fileURLToPath(new URL("../src/provider-protocol.ts", import.meta.url)), "utf8");

  assert.match(protocolSource, /export \{\s+identifySignRoute\s+\} from "\.\/provider-protocol\.js";/);
  assert.doesNotMatch(protocolSource, /from "\.\/protocol-recovery\.js";/);
  assert.doesNotMatch(protocolSource, /identifyProviderSignRoute/);
  assert.doesNotMatch(protocolSource, /makeProviderSignTransactionRequest/);
  assert.doesNotMatch(protocolSource, /makeProviderSignPersonalMessageRequest/);
  assert.doesNotMatch(providerProtocolSource, /function sanitizeAckResultResponse/);
  assert.doesNotMatch(providerProtocolSource, /"get_result request"\)/);
  assert.doesNotMatch(providerProtocolSource, /"ack_result request"\)/);
  assert.doesNotMatch(providerProtocolSource, /export \{\s+assertAckResultResponse/);
  assert.doesNotMatch(providerProtocolSource, /export \{\s+makeAckResultRequest/);
  assert.doesNotMatch(providerProtocolSource, /export \{\s+makeGetResultRequest/);
  assert.doesNotMatch(providerProtocolSource, /from "\.\/protocol-recovery\.js";/);
  assert.doesNotMatch(providerProtocolSource, /\bGetResultRequest\b/);
  assert.doesNotMatch(providerProtocolSource, /\bAckResultRequest\b/);
  assert.doesNotMatch(providerProtocolSource, /\bAckResultResponse\b/);

  assert.match(coreSource, /from "\.\/provider-protocol\.js";/);
  assert.doesNotMatch(coreSource, /validateSignTransactionParamsInput/);
  assert.doesNotMatch(coreSource, /validateSignPersonalMessageParamsInput/);

  assert.match(usbSource, /from "\.\/provider-protocol\.js";/);
});

test("serial transport keeps HUPCL disabled across short-lived USB requests", async () => {
  const usbSource = await readFile(fileURLToPath(new URL("../src/usb.ts", import.meta.url)), "utf8");
  assert.match(usbSource, /hupcl:\s*false/);
});

test("provider-protocol does not expose request wire serializers or builders", async () => {
  const providerProtocol = await import("@stelis/agent-q-core/provider-protocol");
  assert.equal(providerProtocol.serializeProviderProtocolRequest, undefined);
  assert.equal(providerProtocol.makeConnectRequest, undefined);
  assert.equal(providerProtocol.makeDisconnectRequest, undefined);
  assert.equal(providerProtocol.makeGetCapabilitiesRequest, undefined);
  assert.equal(providerProtocol.makeGetAccountsRequest, undefined);
  assert.equal(providerProtocol.makeSignTransactionRequest, undefined);
  assert.equal(providerProtocol.makeSignPersonalMessageRequest, undefined);
});

test("adapter output schema keeps signing method result shapes exact", () => {
  const transactionSchema = hostSuccessOutputSchemas.signTransaction;
  const personalMessageSchema = hostSuccessOutputSchemas.signPersonalMessage;
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
  const responseLineBoundMessageBytes = Buffer.alloc(3500, 8).toString("base64");
  assert.ok(responseLineBoundMessageBytes.length > MAX_RAW_PROTOCOL_JSON_BYTES);
  assert.ok(responseLineBoundMessageBytes.length < MAX_SIGN_RESULT_PAYLOAD_BASE64_CHARS);
  assert.equal(
    personalMessageSchema.parse({
      ...validSignPersonalMessageSignedOutput(),
      messageBytes: responseLineBoundMessageBytes,
    }).messageBytes,
    responseLineBoundMessageBytes,
  );
  assert.equal(
    personalMessageSchema.parse({
      ...validSignPersonalMessageSignedOutput(),
      signature: ZKLOGIN_SIGNATURE,
    }).signature,
    ZKLOGIN_SIGNATURE,
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
  const schema = hostSuccessOutputSchemas.signTransaction;
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
  const schema = hostSuccessOutputSchemas.getAccounts;
  const output = {
    source: "live",
    deviceId: DEVICE_ID,
    accounts: [validLiveAccount()],
  };
  assert.equal(schema.parse(output).accounts[0].address, SUI_ADDRESS);
  assert.deepEqual(schema.parse(output).accounts[0].sponsoredTransactions, {
    acceptGasSponsor: false,
  });
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
