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
  assert.equal(typeof root.createDefaultDeviceClientCore, "function");
  assert.equal(root.createDefaultGatewayCore, undefined);
  assert.equal(typeof admin.createDefaultGatewayCore, "function");
  assert.equal(typeof adapterInternal.gatewaySuccessOutputSchemas, "object");
  assert.equal(typeof client.createDefaultDeviceClientCore, "function");
  assert.equal(typeof protocol.makeGetStatusRequest, "function");
  assert.equal(typeof protocol.makeSignTransactionRequest, "function");
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

test("adapter output schema keeps signing method result shapes exact", () => {
  const transactionSchema = gatewaySuccessOutputSchemas.signTransaction;
  const personalMessageSchema = gatewaySuccessOutputSchemas.signPersonalMessage;
  assert.equal(transactionSchema.parse(validSignTransactionSignedOutput()).method, "sign_transaction");
  assert.equal(personalMessageSchema.parse(validSignPersonalMessageSignedOutput()).method, "sign_personal_message");

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
