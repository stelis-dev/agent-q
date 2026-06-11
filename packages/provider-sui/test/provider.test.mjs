import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { Transaction } from "@mysten/sui/transactions";
import {
  getWallets,
  StandardConnect,
  StandardDisconnect,
  StandardEvents,
  SuiSignPersonalMessage,
  SuiSignTransaction,
} from "@mysten/wallet-standard";
import { createAgentQSuiProvider, AgentQSuiProvider } from "../dist/provider-sui.js";
import {
  AGENT_Q_SUI_WALLET_ID,
  AGENT_Q_SUI_WALLET_NAME,
  AgentQSuiWallet,
  createAgentQSuiWallet,
  createAgentQSuiWalletInitializer,
  registerAgentQSuiWallet,
} from "../dist/wallet-standard.js";
import {
  AgentQSuiBrowserProvider,
  createAgentQSuiBrowserProvider,
  isAgentQSuiBrowserProviderAvailable,
} from "../dist/browser.js";
import { FORBIDDEN_SECRET_FIELD_NAMES, SIGN_RESULT_ERROR_MESSAGES, SUI_DERIVATION_PATH } from "@stelis/agent-q-core/protocol";
import { parseProviderProtocolResponse } from "@stelis/agent-q-core/provider-protocol";

const SUI_ADDRESS = "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133";
const SUI_PUBLIC_KEY = "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk=";
const SUI_SIGNATURE = Buffer.alloc(97, 1).toString("base64");
const PERSONAL_MESSAGE_BYTES = Buffer.from("Agent-Q personal message").toString("base64");

function assertNoSecretFields(value) {
  const text = JSON.stringify(value).toLowerCase();
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.equal(text.includes(fieldName.toLowerCase()), false, `${fieldName} must not appear in provider output`);
  }
  assert.equal(text.includes("sessionid"), false, "sessionId must not appear in provider output");
}

function createFakeCore() {
  return {
    async scanDevices() {
      return { source: "live", devices: [], failures: [], activeDeviceId: null };
    },
    async identifyDevices() {
      return { source: "live", devices: [], activeDeviceId: null };
    },
    async selectDevice(input) {
      return {
        source: "selected",
        activeDeviceId: input.deviceId,
        purpose: input.purpose ?? null,
        device: {
          deviceId: input.deviceId,
          state: "idle",
          firmwareName: "Agent-Q Firmware",
          hardware: "stackchan-cores3",
          firmwareVersion: "0.0.0",
        },
      };
    },
    async listDevices() {
      return { source: "list", devices: [], activeDeviceId: null, activeDeviceIdsByPurpose: {} };
    },
    async connectDevice() {
      return {
        source: "connected",
        deviceId: "device-1",
        sessionTtlMs: 60000,
        connectedAt: "2026-06-02T00:00:00.000Z",
        device: {
          deviceId: "device-1",
          state: "idle",
          firmwareName: "Agent-Q Firmware",
          hardware: "stackchan-cores3",
          firmwareVersion: "0.0.0",
        },
      };
    },
    async disconnectDevice() {
      return { source: "disconnected", deviceId: "device-1", reason: "firmware_confirmed" };
    },
    async getCapabilities() {
      return {
        source: "live",
        deviceId: "device-1",
        capabilities: [
          {
            id: "sui",
            accounts: [{ keyScheme: "ed25519", derivationPath: SUI_DERIVATION_PATH }],
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
      };
    },
    async getAccounts() {
      return {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            chain: "sui",
            address: SUI_ADDRESS,
            publicKey: SUI_PUBLIC_KEY,
            keyScheme: "ed25519",
            derivationPath: SUI_DERIVATION_PATH,
          },
        ],
      };
    },
    async signTransaction() {
      return {
        source: "live",
        deviceId: "device-1",
        status: "user_rejected",
        authorization: "user",
        error: {
          code: "user_rejected",
          message: "The signing request was rejected on the device.",
        },
      };
    },
    async signPersonalMessage() {
      return {
        source: "live",
        deviceId: "device-1",
        status: "user_rejected",
        authorization: "user",
        error: {
          code: "user_rejected",
          message: "The signing request was rejected on the device.",
        },
      };
    },
  };
}

function createSigningCore() {
  const calls = [];
  return {
    calls,
    core: {
      ...createFakeCore(),
      async signTransaction(input) {
        calls.push(input);
        return {
          source: "live",
          deviceId: "device-1",
          status: "signed",
          authorization: "user",
          chain: "sui",
          method: "sign_transaction",
          signature: SUI_SIGNATURE,
        };
      },
      async signPersonalMessage(input) {
        calls.push(input);
        return {
          source: "live",
          deviceId: "device-1",
          status: "signed",
          authorization: "user",
          chain: "sui",
          method: "sign_personal_message",
          signature: SUI_SIGNATURE,
          messageBytes: input.message,
        };
      },
    },
  };
}

async function createResolvedTransactionJson(sender = SUI_ADDRESS) {
  const transaction = new Transaction();
  transaction.setSender(sender);
  transaction.setGasBudget(1);
  transaction.setGasPrice(1);
  transaction.setGasPayment([
    {
      objectId: "0x0000000000000000000000000000000000000000000000000000000000000001",
      version: "1",
      digest: "11111111111111111111111111111111",
    },
  ]);
  return transaction.toJSON();
}

function fakeClient() {
  return {};
}

function validSignedTransactionResult() {
  return {
    source: "live",
    deviceId: "device-1",
    status: "signed",
    authorization: "user",
    chain: "sui",
    method: "sign_transaction",
    signature: SUI_SIGNATURE,
  };
}

function validSignedPersonalMessageResult(messageBytes = PERSONAL_MESSAGE_BYTES) {
  return {
    source: "live",
    deviceId: "device-1",
    status: "signed",
    authorization: "user",
    chain: "sui",
    method: "sign_personal_message",
    signature: SUI_SIGNATURE,
    messageBytes,
  };
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function validCapabilitiesResult({
  authorization = "user",
  methods = authorization === "user"
    ? [
      { chain: "sui", method: "sign_transaction" },
      { chain: "sui", method: "sign_personal_message" },
    ]
    : [
      { chain: "sui", method: "sign_transaction" },
    ],
} = {}) {
  return {
    source: "live",
    deviceId: "device-1",
    capabilities: [
      {
        id: "sui",
        accounts: [{ keyScheme: "ed25519", derivationPath: SUI_DERIVATION_PATH }],
        methods: [],
      },
    ],
    signing: {
      authorization,
      methods,
    },
  };
}

class FakeBrowserSerialPort {
  requests = [];
  readable = null;
  writable = null;
  #controller = null;
  #responseForRequest;

  constructor(responseForRequest) {
    this.#responseForRequest = responseForRequest;
  }

  async open() {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    this.readable = new ReadableStream({
      start: (controller) => {
        this.#controller = controller;
      },
      cancel: () => {
        this.#controller = null;
      },
    });
    this.writable = new WritableStream({
      write: async (chunk) => {
        const text = decoder.decode(chunk);
        for (const rawLine of text.split("\n")) {
          const line = rawLine.trim();
          if (line.length === 0) {
            continue;
          }
          const request = JSON.parse(line);
          this.requests.push(request);
          const response = this.#responseForRequest(request);
          if (response === null) {
            this.#controller?.close();
            continue;
          }
          this.#controller?.enqueue(encoder.encode(typeof response === "string" ? response : `${JSON.stringify(response)}\n`));
        }
      },
    });
  }

  async close() {
    try {
      this.#controller?.close();
    } catch {
      // The reader may already have cancelled the stream.
    }
    this.#controller = null;
    this.readable = null;
    this.writable = null;
  }
}

function createFakeBrowserProtocolResponse(request) {
  const device = {
    deviceId: "device-1",
    state: "idle",
    firmwareName: "Agent-Q Firmware",
    hardware: "stackchan-cores3",
    firmwareVersion: "0.0.0",
  };
  switch (request.type) {
    case "connect":
      return {
        id: request.id,
        version: 1,
        type: "connect_result",
        status: "approved",
        sessionId: "session_abcdef0123456789",
        sessionTtlMs: 60000,
        device,
      };
    case "disconnect":
      return {
        id: request.id,
        version: 1,
        type: "disconnect_result",
        status: "disconnected",
      };
    case "get_capabilities":
      return {
        id: request.id,
        version: 1,
        type: "capabilities",
        chains: [
          {
            id: "sui",
            accounts: [{ keyScheme: "ed25519", derivationPath: SUI_DERIVATION_PATH }],
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
      };
    case "get_accounts":
      return {
        id: request.id,
        version: 1,
        type: "accounts",
        accounts: [
          {
            chain: "sui",
            address: SUI_ADDRESS,
            publicKey: SUI_PUBLIC_KEY,
            keyScheme: "ed25519",
            derivationPath: SUI_DERIVATION_PATH,
          },
        ],
      };
    case "sign_transaction":
      return {
        id: request.id,
        version: 1,
        type: "sign_result",
        status: "signed",
        authorization: "user",
        chain: "sui",
        method: "sign_transaction",
        signature: SUI_SIGNATURE,
      };
    case "sign_personal_message":
      return {
        id: request.id,
        version: 1,
        type: "sign_result",
        status: "signed",
        authorization: "user",
        chain: "sui",
        method: "sign_personal_message",
        signature: SUI_SIGNATURE,
        messageBytes: request.params.message,
      };
    default:
      return {
        id: request.id,
        version: 1,
        type: "error",
        error: {
          code: "unsupported_method",
          message: "Unsupported request type.",
        },
      };
  }
}

function makeBrowserTerminalSignResult(status) {
  if (status === "policy_rejected") {
    return {
      type: "sign_result",
      status: "policy_rejected",
      authorization: "policy",
      policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
      ruleRef: "default",
      error: {
        code: "policy_rejected",
        message: SIGN_RESULT_ERROR_MESSAGES.policy_rejected,
      },
    };
  }
  const terminal = {
    type: "sign_result",
    status,
    authorization: "user",
    error: {
      code: status,
      message: SIGN_RESULT_ERROR_MESSAGES[status],
    },
  };
  return terminal;
}

test("provider-sui package metadata exposes only Sui provider and Wallet Standard entrypoints", async () => {
  const packagePath = fileURLToPath(new URL("../package.json", import.meta.url));
  const corePackagePath = fileURLToPath(new URL("../../core/package.json", import.meta.url));
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  const corePackageJson = JSON.parse(await readFile(corePackagePath, "utf8"));
  assert.equal(packageJson.name, "@stelis/agent-q-provider-sui");
  assert.deepEqual(Object.keys(packageJson.exports).sort(), [".", "./browser", "./package.json", "./provider-sui", "./wallet-standard"]);
  assert.equal(packageJson.dependencies["@stelis/agent-q-core"], corePackageJson.version);
  assert.equal(packageJson.dependencies["@mysten/wallet-standard"], "^0.20.3");
  assert.equal(packageJson.dependencies["@mysten/sui"], "^2.17.0");
  assert.equal(packageJson.dependencies["@stelis/agent-q"], undefined);
  assert.equal(packageJson.bin, undefined);
});

test("provider-sui package self-reference resolves Sui provider only", async () => {
  const root = await import("@stelis/agent-q-provider-sui");
  const provider = await import("@stelis/agent-q-provider-sui/provider-sui");
  const walletStandard = await import("@stelis/agent-q-provider-sui/wallet-standard");
  const browser = await import("@stelis/agent-q-provider-sui/browser");
  assert.equal(typeof root.createAgentQSuiProvider, "function");
  assert.equal(typeof provider.AgentQSuiProvider, "function");
  assert.equal(walletStandard.AGENT_Q_SUI_WALLET_ID, AGENT_Q_SUI_WALLET_ID);
  assert.equal(walletStandard.AGENT_Q_SUI_WALLET_NAME, AGENT_Q_SUI_WALLET_NAME);
  assert.equal(typeof walletStandard.createAgentQSuiWallet, "function");
  assert.equal(typeof walletStandard.registerAgentQSuiWallet, "function");
  assert.equal(typeof walletStandard.createAgentQSuiWalletInitializer, "function");
  assert.equal(typeof browser.createAgentQSuiBrowserProvider, "function");
  assert.equal(typeof browser.isAgentQSuiBrowserProviderAvailable, "function");
  await assert.rejects(() => import("@stelis/agent-q-provider-sui/provider"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
  await assert.rejects(() => import("@stelis/agent-q-provider-sui/mcp"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
  await assert.rejects(() => import("@stelis/agent-q-provider-sui/admin"), {
    code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
  });
});

test("provider does not import MCP or Admin adapters", async () => {
  const providerPath = fileURLToPath(new URL("../dist/provider-sui.js", import.meta.url));
  const source = await readFile(providerPath, "utf8");
  assert.doesNotMatch(source, /@stelis\/agent-q(?!-core)/);
  assert.doesNotMatch(source, /mcp/i);
  assert.doesNotMatch(source, /admin/i);
});

test("Wallet Standard entrypoint stays separated from Node device transport", async () => {
  const walletStandardPath = fileURLToPath(new URL("../dist/wallet-standard.js", import.meta.url));
  const source = await readFile(walletStandardPath, "utf8");
  assert.doesNotMatch(source, /@stelis\/agent-q-core/);
  assert.doesNotMatch(source, /\.\/provider-sui\.js/);
  assert.doesNotMatch(source, /node:buffer/);

  const walletStandardTypesPath = fileURLToPath(new URL("../dist/wallet-standard.d.ts", import.meta.url));
  const types = await readFile(walletStandardTypesPath, "utf8");
  assert.doesNotMatch(types, /@stelis\/agent-q-core/);
  assert.doesNotMatch(types, /\.\/provider-sui\.js/);
});

test("browser provider runtime stays separated from Admin, MCP, and Node serial transports", async () => {
  const browserPath = fileURLToPath(new URL("../dist/browser.js", import.meta.url));
  const source = await readFile(browserPath, "utf8");
  assert.match(source, /@stelis\/agent-q-core\/provider-protocol/);
  assert.doesNotMatch(source, /@stelis\/agent-q-core\/protocol/);
  assert.doesNotMatch(source, /@stelis\/agent-q-core\/admin/);
  assert.doesNotMatch(source, /@stelis\/agent-q(?!-core)/);
  assert.doesNotMatch(source, /adapter-internal/);
  assert.doesNotMatch(source, /serialport/);
  assert.doesNotMatch(source, /node:/);
  assert.doesNotMatch(source, /policy_get/);
  assert.doesNotMatch(source, /policy_propose/);
  assert.doesNotMatch(source, /get_approval_history/);
  assert.match(source, /serializeProviderProtocolRequest/);
  assert.doesNotMatch(source, /serializeRequest/);

  const browserTypesPath = fileURLToPath(new URL("../dist/browser.d.ts", import.meta.url));
  const types = await readFile(browserTypesPath, "utf8");
  assert.doesNotMatch(types, /@stelis\/agent-q-core\/admin/);
  assert.doesNotMatch(types, /@stelis\/agent-q(?!-core)/);
  assert.doesNotMatch(types, /requestTimeoutMs/);
  assert.doesNotMatch(types, /requestPort/);
  assert.doesNotMatch(types, /serial\?/);
  assert.doesNotMatch(types, /baudRate/);
  assert.doesNotMatch(types, /adapter-internal/);
  assert.doesNotMatch(types, /serialport/);
  assert.doesNotMatch(types, /node:/);
});

test("browser provider runtime defers Web Serial port selection until connectDevice", async () => {
  let requestPortCalls = 0;
  const port = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {},
    });
    assert.equal(isAgentQSuiBrowserProviderAvailable(), false);

    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            return port;
          },
        },
      },
    });
    const provider = createAgentQSuiBrowserProvider({ clientName: "Agent-Q Sui dapp-kit Example" });
    assert.equal(provider instanceof AgentQSuiBrowserProvider, true);
    assert.equal(isAgentQSuiBrowserProviderAvailable(), true);
    assert.equal(requestPortCalls, 0);

    const notConnected = await provider.getCapabilities();
    assert.deepEqual(notConnected, {
      source: "not_connected",
      deviceId: "browser",
      reason: "not_connected",
    });
    assert.equal(requestPortCalls, 0);
    assert.deepEqual(port.requests, []);

    const connected = await provider.connectDevice();
    assert.equal(requestPortCalls, 1);
    assert.equal(connected.source, "connected");
    assert.equal(connected.deviceId, "device-1");
    assertNoSecretFields(connected);

    const capabilities = await provider.getCapabilities();
    assert.equal(capabilities.source, "live");
    assert.equal(capabilities.deviceId, "device-1");
    assert.deepEqual(capabilities.signing.methods, [
      { chain: "sui", method: "sign_transaction" },
      { chain: "sui", method: "sign_personal_message" },
    ]);

    const accounts = await provider.getAccounts();
    assert.equal(accounts.source, "live");
    assert.equal(accounts.accounts[0].address, SUI_ADDRESS);
    assertNoSecretFields(accounts);

    const transactionResult = await provider.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "AQID",
    });
    assert.deepEqual(transactionResult, validSignedTransactionResult());

    const personalMessageResult = await provider.signPersonalMessage({
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: PERSONAL_MESSAGE_BYTES,
    });
    assert.deepEqual(personalMessageResult, validSignedPersonalMessageResult(PERSONAL_MESSAGE_BYTES));

    const disconnected = await provider.disconnectDevice();
    assert.deepEqual(disconnected, {
      source: "disconnected",
      deviceId: "device-1",
      reason: "firmware_confirmed",
    });
    assert.deepEqual(port.requests.map((request) => request.type), [
      "connect",
      "get_capabilities",
      "get_accounts",
      "sign_transaction",
      "sign_personal_message",
      "disconnect",
    ]);
    assert.equal(port.requests.some((request) => request.type === "policy_get" || request.type === "policy_propose"), false);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider disconnects approved sessions that fail requested device matching", async () => {
  let requestPortCalls = 0;
  const mismatchedPort = new FakeBrowserSerialPort((request) => {
    if (request.type === "connect") {
      return {
        ...createFakeBrowserProtocolResponse(request),
        device: {
          ...createFakeBrowserProtocolResponse(request).device,
          deviceId: "other-device",
        },
      };
    }
    return createFakeBrowserProtocolResponse(request);
  });
  const matchedPort = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            return requestPortCalls === 1 ? mismatchedPort : matchedPort;
          },
        },
      },
    });
    const provider = createAgentQSuiBrowserProvider();
    await assert.rejects(
      () => provider.connectDevice({ deviceId: "device-1" }),
      { code: "device_mismatch" },
    );
    assert.equal(requestPortCalls, 1);
    assert.deepEqual(mismatchedPort.requests.map((request) => request.type), ["connect", "disconnect"]);
    assert.equal(mismatchedPort.requests[1].sessionId, "session_abcdef0123456789");
    assert.deepEqual(await provider.getCapabilities({ deviceId: "device-1" }), {
      source: "not_connected",
      deviceId: "device-1",
      reason: "not_connected",
    });
    const connected = await provider.connectDevice({ deviceId: "device-1" });
    assert.equal(requestPortCalls, 2);
    assert.equal(connected.source, "connected");
    assert.deepEqual(matchedPort.requests.map((request) => request.type), ["connect"]);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

function waitMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// A fake Web Serial port that mimics real Web Serial: open() throws when the port
// is already open. It records the peak number of simultaneous opens so a missing
// request lock surfaces as maxConcurrentOpens > 1 (or a rejected open). An optional
// per-write delay holds a request "in flight" so queue behavior is observable.
class SerializationProbePort {
  openCount = 0;
  closeCount = 0;
  maxConcurrentOpens = 0;
  requests = [];
  readable = null;
  writable = null;
  #open = 0;
  #controller = null;
  #responder;
  #responseDelayMs;
  #beforeRespond;

  constructor(responder, { responseDelayMs = 0, beforeRespond = null } = {}) {
    this.#responder = responder;
    this.#responseDelayMs = responseDelayMs;
    this.#beforeRespond = beforeRespond;
  }

  async open() {
    this.#open += 1;
    this.maxConcurrentOpens = Math.max(this.maxConcurrentOpens, this.#open);
    if (this.#open > 1) {
      this.#open -= 1;
      throw new Error("Failed to open serial port: the port is already open.");
    }
    this.openCount += 1;
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    this.readable = new ReadableStream({
      start: (controller) => {
        this.#controller = controller;
      },
      cancel: () => {
        this.#controller = null;
      },
    });
    this.writable = new WritableStream({
      write: async (chunk) => {
        const text = decoder.decode(chunk);
        for (const rawLine of text.split("\n")) {
          const line = rawLine.trim();
          if (line.length === 0) {
            continue;
          }
          const request = JSON.parse(line);
          this.requests.push(request);
          const response = this.#responder(request);
          if (this.#beforeRespond) {
            // Deterministic hold point: a test can hold a request mid-write with
            // no timers, so queue/invalidation behavior is observable.
            await this.#beforeRespond(request);
          } else if (this.#responseDelayMs > 0) {
            await waitMs(this.#responseDelayMs);
          }
          if (response === null) {
            this.#controller?.close();
            continue;
          }
          this.#controller?.enqueue(
            encoder.encode(typeof response === "string" ? response : `${JSON.stringify(response)}\n`),
          );
        }
      },
    });
  }

  async close() {
    // Real Web Serial rejects close() while a stream is locked (a reader/writer is
    // active), so an in-flight request survives a concurrent close attempt.
    if (this.readable?.locked === true || this.writable?.locked === true) {
      throw new Error("Cannot close a serial port while its streams are locked.");
    }
    this.#open = Math.max(0, this.#open - 1);
    this.closeCount += 1;
    try {
      this.#controller?.close();
    } catch {
      // The reader may already have cancelled the stream.
    }
    this.#controller = null;
    this.readable = null;
    this.writable = null;
  }
}

function createDisconnectableSerial(port) {
  const listeners = new Map();
  let requestPortCalls = 0;
  return {
    serial: {
      requestPort: async () => {
        requestPortCalls += 1;
        return port;
      },
      addEventListener: (type, listener) => {
        listeners.set(type, listener);
      },
      removeEventListener: (type) => {
        listeners.delete(type);
      },
    },
    fireDisconnect: (target) => {
      const listener = listeners.get("disconnect");
      if (listener !== undefined) {
        listener({ target });
      }
    },
    get requestPortCalls() {
      return requestPortCalls;
    },
  };
}

test("browser provider serializes concurrent Web Serial requests through one open at a time", async () => {
  const port = new SerializationProbePort(createFakeBrowserProtocolResponse, { responseDelayMs: 5 });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    // Without the request queue, the second open() would throw on the already-open
    // port (or two requests would interleave reads on one stream).
    const results = await Promise.all([
      provider.getCapabilities(),
      provider.getAccounts(),
      provider.getCapabilities(),
    ]);
    assert.equal(results.every((result) => result.source === "live"), true);
    assert.equal(port.maxConcurrentOpens, 1, "the port must never be open more than once at a time");
    assert.equal(port.openCount, 1, "the persistent port opens once and is reused by serialized requests");
    assert.equal(port.closeCount, 0, "a successful session leaves the port open for reuse");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider invalidates queued requests when the device disconnects mid-flight", async () => {
  // Deterministic, timer-free: the probe holds the first post-connect request
  // mid-write until the test releases it, and signals exactly when it is in flight.
  let signalInFlight;
  const firstRequestInFlight = new Promise((resolve) => { signalInFlight = resolve; });
  let releaseInFlight;
  const inFlightGate = new Promise((resolve) => { releaseInFlight = resolve; });
  let heldOne = false;
  const port = new SerializationProbePort(createFakeBrowserProtocolResponse, {
    beforeRespond: async (request) => {
      if (request.type !== "connect" && !heldOne) {
        heldOne = true;
        signalInFlight();
        await inFlightGate;
      }
    },
  });
  const mock = createDisconnectableSerial(port);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: mock.serial },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    // The first request is held mid-write (already opened + past its generation
    // check); the rest wait behind it in the queue.
    const inFlight = provider.getCapabilities();
    const queuedA = provider.getCapabilities();
    const queuedB = provider.getAccounts();
    await firstRequestInFlight;
    mock.fireDisconnect(port);
    releaseInFlight();

    const settled = await Promise.all([inFlight, queuedA, queuedB]);
    // The in-flight request completes; the queued ones must not re-prompt for a
    // dead port — they report session_ended via the generation guard.
    assert.equal(settled[0].source, "live");
    assert.equal(settled[1].source, "session_ended");
    assert.equal(settled[1].reason, "transport_closed");
    assert.equal(settled[2].source, "session_ended");
    assert.equal(mock.requestPortCalls, 1, "queued requests must not re-prompt for a port after disconnect");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider keeps serving requests after one request rejects", async () => {
  let capabilityCalls = 0;
  const port = new SerializationProbePort((request) => {
    if (request.type === "get_capabilities") {
      capabilityCalls += 1;
      if (capabilityCalls === 1) {
        return { id: request.id, version: 1, type: "error", error: { code: "internal_error", message: "transient device error" } };
      }
    }
    return createFakeBrowserProtocolResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    // A failing request must not wedge the queue: the following request still runs.
    const [failed, recovered] = await Promise.allSettled([
      provider.getCapabilities(),
      provider.getCapabilities(),
    ]);
    assert.equal(failed.status, "rejected");
    assert.equal(failed.reason.code, "internal_error");
    assert.equal(recovered.status, "fulfilled");
    assert.equal(recovered.value.source, "live");
    assert.equal(port.maxConcurrentOpens, 1);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider recovers a buffered signing result when the sign response is lost", async () => {
  const port = new FakeBrowserSerialPort((request) => {
    if (request.type === "sign_transaction") {
      // The device signed and buffered the result, but the response is lost in transit.
      return { id: request.id, version: 1, type: "error", error: { code: "internal_error", message: "lost" } };
    }
    if (request.type === "get_result") {
      // The device returns the buffered signature for the original request id.
      return {
        id: request.id, version: 1, type: "sign_result", status: "signed",
        authorization: "user", chain: "sui", method: "sign_transaction", signature: SUI_SIGNATURE,
      };
    }
    return createFakeBrowserProtocolResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const result = await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.equal(result.source, "live", "the buffered result is recovered, not surfaced as an error");
    const signReq = port.requests.find((r) => r.type === "sign_transaction");
    const getResultReq = port.requests.find((r) => r.type === "get_result");
    assert.ok(getResultReq, "provider must issue a get_result after a lost sign response");
    assert.equal(getResultReq.id, signReq.id, "get_result must target the original sign request id");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

for (const status of ["user_rejected", "user_timed_out", "signing_failed", "policy_rejected"]) {
  test(`browser provider recovers a buffered ${status} sign_transaction result when the sign response is lost`, async () => {
    const port = new FakeBrowserSerialPort((request) => {
      if (request.type === "sign_transaction") {
        return { id: request.id, version: 1, type: "error", error: { code: "internal_error", message: "lost" } };
      }
      if (request.type === "get_result") {
        return {
          id: request.id,
          version: 1,
          ...makeBrowserTerminalSignResult(status),
        };
      }
      if (request.type === "ack_result") {
        return { id: request.id, version: 1, type: "ack_result", status: "acked" };
      }
      return createFakeBrowserProtocolResponse(request);
    });
    const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    try {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: { serial: { requestPort: async () => port } },
      });
      const provider = createAgentQSuiBrowserProvider();
      assert.equal((await provider.connectDevice()).source, "connected");

      const result = await provider.signTransaction({
        chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
      });
      assert.equal(result.source, "live");
      assert.equal(result.status, status);
      const signReq = port.requests.find((r) => r.type === "sign_transaction");
      const getResultReq = port.requests.find((r) => r.type === "get_result");
      const ackReq = port.requests.find((r) => r.type === "ack_result");
      assert.ok(getResultReq, "provider must issue get_result after a lost sign response");
      assert.equal(getResultReq.id, signReq.id, "get_result must target the original request id");
      assert.ok(ackReq, "provider must send ack_result after recovering terminal result");
      assert.equal(ackReq.id, signReq.id, "ack_result must target the original request id");
      if (status === "policy_rejected") {
        assert.equal(result.authorization, "policy");
        assert.equal(result.error.code, "policy_rejected");
        assert.equal(result.error.message, SIGN_RESULT_ERROR_MESSAGES.policy_rejected);
      } else {
        assert.equal(result.authorization, "user");
        assert.equal(result.error.code, status);
        assert.equal(result.error.message, SIGN_RESULT_ERROR_MESSAGES[status]);
      }
    } finally {
      if (previousNavigator === undefined) {
        delete globalThis.navigator;
      } else {
        Object.defineProperty(globalThis, "navigator", previousNavigator);
      }
    }
  });
}

for (const status of ["user_rejected", "user_timed_out", "signing_failed"]) {
  test(`browser provider recovers a buffered ${status} sign_personal_message result when the sign response is lost`, async () => {
    const port = new FakeBrowserSerialPort((request) => {
      if (request.type === "sign_personal_message") {
        return { id: request.id, version: 1, type: "error", error: { code: "internal_error", message: "lost" } };
      }
      if (request.type === "get_result") {
        return {
          id: request.id,
          version: 1,
          ...makeBrowserTerminalSignResult(status),
        };
      }
      if (request.type === "ack_result") {
        return { id: request.id, version: 1, type: "ack_result", status: "acked" };
      }
      return createFakeBrowserProtocolResponse(request);
    });
    const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    try {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: { serial: { requestPort: async () => port } },
      });
      const provider = createAgentQSuiBrowserProvider();
      assert.equal((await provider.connectDevice()).source, "connected");

      const result = await provider.signPersonalMessage({
        chain: "sui", method: "sign_personal_message", network: "mainnet", message: PERSONAL_MESSAGE_BYTES,
      });
      assert.equal(result.source, "live");
      assert.equal(result.status, status);
      assert.equal(result.authorization, "user");
      assert.equal(result.error.code, status);
      assert.equal(result.error.message, SIGN_RESULT_ERROR_MESSAGES[status]);
      const signReq = port.requests.find((r) => r.type === "sign_personal_message");
      const getResultReq = port.requests.find((r) => r.type === "get_result");
      const ackReq = port.requests.find((r) => r.type === "ack_result");
      assert.ok(getResultReq, "provider must issue get_result after a lost sign response");
      assert.equal(getResultReq.id, signReq.id, "get_result must target the original request id");
      assert.ok(ackReq, "provider must send ack_result after recovering terminal result");
      assert.equal(ackReq.id, signReq.id, "ack_result must target the original request id");
    } finally {
      if (previousNavigator === undefined) {
        delete globalThis.navigator;
      } else {
        Object.defineProperty(globalThis, "navigator", previousNavigator);
      }
    }
  });
}

test("browser provider surfaces the original error when no buffered result exists", async () => {
  const port = new FakeBrowserSerialPort((request) => {
    if (request.type === "sign_transaction") {
      return { id: request.id, version: 1, type: "error", error: { code: "invalid_params", message: "bad tx" } };
    }
    if (request.type === "get_result") {
      // The device never signed, so there is nothing buffered to recover.
      return { id: request.id, version: 1, type: "error", error: { code: "unknown_request", message: "no result" } };
    }
    return createFakeBrowserProtocolResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    await assert.rejects(
      () => provider.signTransaction({ chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID" }),
      (error) => error.code === "invalid_params",
      "the original sign error must surface when get_result finds nothing to recover",
    );
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider uses a caller-provided requestId for idempotent retries", async () => {
  const port = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const stableId = `req_${"ab".repeat(12)}`;
    await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID", requestId: stableId,
    });
    const signReq = port.requests.find((r) => r.type === "sign_transaction");
    assert.equal(signReq.id, stableId, "the provider must use the caller-provided requestId");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("provider protocol parser accepts a valid ack_result and fails closed on a malformed one", () => {
  const valid = parseProviderProtocolResponse(
    JSON.stringify({ id: "req_ack_1", version: 1, type: "ack_result", status: "acked" }),
    "req_ack_1",
  );
  assert.equal(valid.type, "ack_result");
  assert.equal(valid.status, "acked");
  // Fail closed on a wrong status, and on any extra (possibly secret-like) field.
  assert.throws(() =>
    parseProviderProtocolResponse(
      JSON.stringify({ id: "req_ack_1", version: 1, type: "ack_result", status: "nope" }),
      "req_ack_1",
    ),
  );
  assert.throws(() =>
    parseProviderProtocolResponse(
      JSON.stringify({ id: "req_ack_1", version: 1, type: "ack_result", status: "acked", signature: "x" }),
      "req_ack_1",
    ),
  );
});

test("browser provider releases a recovered result with ack_result", async () => {
  let ackReceived = false;
  const port = new FakeBrowserSerialPort((request) => {
    if (request.type === "sign_transaction") {
      return { id: request.id, version: 1, type: "error", error: { code: "internal_error", message: "lost" } };
    }
    if (request.type === "get_result") {
      return {
        id: request.id, version: 1, type: "sign_result", status: "signed",
        authorization: "user", chain: "sui", method: "sign_transaction", signature: SUI_SIGNATURE,
      };
    }
    if (request.type === "ack_result") {
      ackReceived = true;
      return { id: request.id, version: 1, type: "ack_result", status: "acked" };
    }
    return createFakeBrowserProtocolResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    const result = await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.equal(result.source, "live");
    // The ack is fire-and-forget; a follow-up request serializes after it, so awaiting the
    // follow-up guarantees the ack has been sent.
    await provider.getCapabilities();
    const signReq = port.requests.find((r) => r.type === "sign_transaction");
    const getReq = port.requests.find((r) => r.type === "get_result");
    const ackReq = port.requests.find((r) => r.type === "ack_result");
    assert.ok(ackReq, "the recovery must release the buffered result with ack_result");
    assert.equal(getReq.id, signReq.id);
    assert.equal(ackReq.id, signReq.id, "ack must target the original request id");
    assert.ok(ackReceived, "the device received the ack");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider recovery still returns the result when the ack fails", async () => {
  const port = new FakeBrowserSerialPort((request) => {
    if (request.type === "sign_transaction") {
      return { id: request.id, version: 1, type: "error", error: { code: "internal_error", message: "lost" } };
    }
    if (request.type === "get_result") {
      return {
        id: request.id, version: 1, type: "sign_result", status: "signed",
        authorization: "user", chain: "sui", method: "sign_transaction", signature: SUI_SIGNATURE,
      };
    }
    if (request.type === "ack_result") {
      return { id: request.id, version: 1, type: "error", error: { code: "internal_error", message: "ack failed" } };
    }
    return createFakeBrowserProtocolResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    const result = await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.equal(result.source, "live", "a failed ack must not turn a successful buffered-result fetch into a failure");
    await provider.getCapabilities();
    assert.ok(port.requests.find((r) => r.type === "ack_result"), "the recovery attempted the ack");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider invalidates a queued request when disconnectDevice tears down the transport", async () => {
  const port = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    // Fire a disconnect and a request together: the request queues behind the disconnect.
    const disconnectP = provider.disconnectDevice();
    const queuedP = provider.getCapabilities();
    assert.equal((await disconnectP).source, "disconnected");
    // The disconnect is a full teardown that bumps the transport generation, so the queued
    // request is invalidated upfront (never sent) instead of running over a dead transport.
    const queuedResult = await queuedP;
    assert.equal(queuedResult.source, "session_ended");
    assert.ok(
      !port.requests.some((r) => r.type === "get_capabilities"),
      "the invalidated request must not be sent over the torn-down transport",
    );
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider clears a prior session when a later connect mismatches the requested deviceId", async () => {
  const port = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    // A later connect for a different deviceId mismatches (the device reports device-1).
    await assert.rejects(() => provider.connectDevice({ deviceId: "device-2" }), { code: "device_mismatch" });
    // The mismatch is a full teardown: the prior device-1 session must not be left stale.
    const result = await provider.getCapabilities();
    assert.equal(result.source, "not_connected");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider clears stale port after session-ended responses", async () => {
  let requestPortCalls = 0;
  const staleSessionPort = new FakeBrowserSerialPort((request) => {
    if (request.type === "get_capabilities") {
      return {
        id: request.id,
        version: 1,
        type: "error",
        error: {
          code: "invalid_session",
          message: "Session is not active.",
        },
      };
    }
    return createFakeBrowserProtocolResponse(request);
  });
  const freshPort = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            return requestPortCalls === 1 ? staleSessionPort : freshPort;
          },
        },
      },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    assert.deepEqual(await provider.getCapabilities(), {
      source: "session_ended",
      deviceId: "device-1",
      reason: "invalid_session",
    });
    assert.deepEqual(staleSessionPort.requests.map((request) => request.type), ["connect", "get_capabilities"]);

    const reconnected = await provider.connectDevice();
    assert.equal(requestPortCalls, 2);
    assert.equal(reconnected.source, "connected");
    assert.deepEqual(freshPort.requests.map((request) => request.type), ["connect"]);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider clears stale port after connect transport failure", async () => {
  let requestPortCalls = 0;
  const closedPort = new FakeBrowserSerialPort((request) => request.type === "connect" ? null : createFakeBrowserProtocolResponse(request));
  const freshPort = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            return requestPortCalls === 1 ? closedPort : freshPort;
          },
        },
      },
    });
    const provider = createAgentQSuiBrowserProvider();
    await assert.rejects(
      () => provider.connectDevice(),
      { code: "transport_closed" },
    );
    assert.deepEqual(closedPort.requests.map((request) => request.type), ["connect"]);

    const connected = await provider.connectDevice();
    assert.equal(requestPortCalls, 2);
    assert.equal(connected.source, "connected");
    assert.deepEqual(freshPort.requests.map((request) => request.type), ["connect"]);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider connect fails closed when Web Serial is unavailable", async () => {
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {},
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.deepEqual(await provider.getCapabilities({ deviceId: "device-1" }), {
      source: "unavailable",
      deviceId: "device-1",
      reason: "unsupported_transport",
    });
    await assert.rejects(
      () => provider.connectDevice({ deviceId: "device-1" }),
      { code: "unsupported_transport" },
    );
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider rejects oversized Web Serial response lines", async () => {
  const { MAX_PROTOCOL_RESPONSE_LINE_BYTES } = await import("@stelis/agent-q-core/provider-protocol");
  const port = new FakeBrowserSerialPort(() => `{"${"x".repeat(MAX_PROTOCOL_RESPONSE_LINE_BYTES)}":0}\n`);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => port,
        },
      },
    });
    const provider = createAgentQSuiBrowserProvider();
    await assert.rejects(
      () => provider.connectDevice(),
      { code: "protocol_error" },
    );
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider settles a request even when Web Serial cleanup hangs", async () => {
  const port = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  // Simulate a device that disconnected/reset right after responding: close() never resolves.
  port.close = () => new Promise(() => {});
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => port,
        },
      },
    });
    const provider = createAgentQSuiBrowserProvider();
    // Must resolve (not hang forever) despite the hung close(); the cleanup step is timeout-guarded.
    const connected = await provider.connectDevice();
    assert.equal(connected.source, "connected");
    assert.equal(connected.deviceId, "device-1");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider clears the cached port when Web Serial reports a device disconnect", async () => {
  let requestPortCalls = 0;
  const firstPort = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  const secondPort = new FakeBrowserSerialPort(createFakeBrowserProtocolResponse);
  let disconnectHandler = null;
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            return requestPortCalls === 1 ? firstPort : secondPort;
          },
          addEventListener: (type, handler) => {
            if (type === "disconnect") {
              disconnectHandler = handler;
            }
          },
          removeEventListener: () => {},
        },
      },
    });
    const provider = createAgentQSuiBrowserProvider();
    assert.equal(typeof disconnectHandler, "function");
    assert.equal((await provider.connectDevice()).source, "connected");
    assert.equal(requestPortCalls, 1);

    // Simulate a physical disconnect / Firmware reboot re-enumeration.
    disconnectHandler({ target: firstPort });

    // The next connect must re-request the port (browser menu reappears),
    // not silently reuse the dead cached port.
    assert.equal((await provider.connectDevice()).source, "connected");
    assert.equal(requestPortCalls, 2);
    assert.deepEqual(secondPort.requests.map((request) => request.type), ["connect"]);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("provider object presents the Sui dapp-facing adapter API including signing methods", () => {
  const provider = createAgentQSuiProvider({ core: createFakeCore() });
  const methodNames = Object.getOwnPropertyNames(Object.getPrototypeOf(provider))
    .filter((name) => name !== "constructor")
    .sort();
  assert.equal(provider instanceof AgentQSuiProvider, true);
  assert.deepEqual(methodNames, [
    "connectDevice",
    "disconnectDevice",
    "getAccounts",
    "getCapabilities",
    "identifyDevices",
    "listDevices",
    "scanDevices",
    "selectDevice",
    "signPersonalMessage",
    "signTransaction",
  ]);
  assert.equal(typeof provider.signTransaction, "function");
  assert.equal(typeof provider.signPersonalMessage, "function");
  assert.equal(provider.signByUser, undefined);
  assert.equal(provider.signByPolicy, undefined);
  assert.equal(provider.policyPropose, undefined);
  assert.equal(provider.policyGet, undefined);
  assert.equal(provider.getApprovalHistory, undefined);
});

test("provider delegates current methods and signing methods without exposing session ids or secrets", async () => {
  const provider = createAgentQSuiProvider({ core: createFakeCore() });
  const outputs = [
    await provider.scanDevices(),
    await provider.identifyDevices(),
    await provider.selectDevice({ deviceId: "device-1" }),
    await provider.listDevices(),
    await provider.connectDevice({ deviceId: "device-1" }),
    await provider.disconnectDevice({ deviceId: "device-1" }),
    await provider.getCapabilities({ deviceId: "device-1" }),
    await provider.getAccounts({ deviceId: "device-1" }),
    await provider.signTransaction({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "AQID",
    }),
    await provider.signPersonalMessage({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: PERSONAL_MESSAGE_BYTES,
    }),
  ];
  for (const output of outputs) {
    assertNoSecretFields(output);
  }
  const capabilities = outputs[6];
  assert.deepEqual(capabilities.signing, {
    authorization: "user",
    methods: [
      { chain: "sui", method: "sign_transaction" },
      { chain: "sui", method: "sign_personal_message" },
    ],
  });
  assert.equal(JSON.stringify(capabilities).includes('"signByPolicy"'), false);
});

test("provider getCapabilities applies the provider capability schema", async () => {
  const core = {
    ...createFakeCore(),
    async getCapabilities() {
      return {
        source: "live",
        deviceId: "device-1",
        capabilities: [
          {
            id: "sui",
            accounts: [{ keyScheme: "ed25519", derivationPath: SUI_DERIVATION_PATH }],
            methods: [],
          },
        ],
        signing: {
          authorization: "user",
          methods: [{ chain: "sui", method: "sign_personal_message" }],
        },
      };
    },
  };
  const provider = createAgentQSuiProvider({ core });
  await assert.rejects(
    () => provider.getCapabilities({ deviceId: "device-1" }),
  );
});

test("provider applies output boundary to every custom core method", async () => {
  const calls = [
    ["scanDevices", (provider) => provider.scanDevices()],
    ["identifyDevices", (provider) => provider.identifyDevices()],
    ["selectDevice", (provider) => provider.selectDevice({ deviceId: "device-1" })],
    ["listDevices", (provider) => provider.listDevices()],
    ["connectDevice", (provider) => provider.connectDevice({ deviceId: "device-1" })],
    ["disconnectDevice", (provider) => provider.disconnectDevice({ deviceId: "device-1" })],
    ["getCapabilities", (provider) => provider.getCapabilities({ deviceId: "device-1" })],
    ["getAccounts", (provider) => provider.getAccounts({ deviceId: "device-1" })],
    ["signTransaction", (provider) => provider.signTransaction({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "AQID",
    })],
    ["signPersonalMessage", (provider) => provider.signPersonalMessage({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: PERSONAL_MESSAGE_BYTES,
    })],
  ];

  for (const [methodName, callProvider] of calls) {
    const baseCore = createFakeCore();
    const original = baseCore[methodName].bind(baseCore);
    const core = {
      ...baseCore,
      async [methodName](...args) {
        return { ...(await original(...args)), sessionId: "session_should_not_leak" };
      },
    };
    const provider = createAgentQSuiProvider({ core });
    await assert.rejects(
      () => callProvider(provider),
      /forbidden output field/,
      `${methodName} must reject forbidden custom-core output fields`,
    );
  }
});

test("provider output boundary rejects malformed signing and account projections", async () => {
  {
    const provider = createAgentQSuiProvider({
      core: {
        ...createFakeCore(),
        async getAccounts() {
          const output = await createFakeCore().getAccounts();
          return {
            ...output,
            accounts: [
              {
                ...output.accounts[0],
                label: "unexpected-account-metadata",
              },
            ],
          };
        },
      },
    });
    await assert.rejects(() => provider.getAccounts({ deviceId: "device-1" }));
  }

  {
    const provider = createAgentQSuiProvider({
      core: {
        ...createFakeCore(),
        async signTransaction() {
          return {
            ...validSignedTransactionResult(),
            messageBytes: PERSONAL_MESSAGE_BYTES,
          };
        },
      },
    });
    await assert.rejects(() => provider.signTransaction({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "AQID",
    }));
  }

  {
    const provider = createAgentQSuiProvider({
      core: {
        ...createFakeCore(),
        async signPersonalMessage() {
          return {
            ...validSignedPersonalMessageResult(),
            txBytes: "AQID",
          };
        },
      },
    });
    await assert.rejects(() => provider.signPersonalMessage({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: PERSONAL_MESSAGE_BYTES,
    }));
  }
});

test("provider signTransaction returns Firmware-authored policy terminal results", async () => {
  const core = {
    ...createFakeCore(),
    async signTransaction() {
      return {
        source: "live",
        deviceId: "device-1",
        status: "policy_rejected",
        authorization: "policy",
        policyHash: "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
        ruleRef: "default",
        error: {
          code: "policy_rejected",
          message: "The signing request was rejected by device policy.",
        },
      };
    },
  };
  const provider = createAgentQSuiProvider({ core });
  const result = await provider.signTransaction({
    deviceId: "device-1",
    chain: "sui",
    method: "sign_transaction",
    network: "devnet",
    txBytes: "AQID",
  });
  assert.equal(result.status, "policy_rejected");
  assert.equal(result.authorization, "policy");
  assert.equal(result.error.code, "policy_rejected");
});

test("provider object omits policy signing and Admin management entrypoints", () => {
  const provider = createAgentQSuiProvider({ core: createFakeCore() });
  assert.equal(provider.signByUser, undefined);
  assert.equal(provider.signByPolicy, undefined);
  assert.equal(provider.policyPropose, undefined);
  assert.equal(provider.policyGet, undefined);
  assert.equal(provider.getApprovalHistory, undefined);
  assert.equal(typeof provider.signTransaction, "function");
  assert.equal(typeof provider.signPersonalMessage, "function");
});

test("Wallet Standard adapter advertises only current Agent-Q Sui signing features", () => {
  const { core } = createSigningCore();
  const wallet = createAgentQSuiWallet({
    provider: createAgentQSuiProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  assert.equal(wallet instanceof AgentQSuiWallet, true);
  assert.equal(wallet.name, "Agent-Q");
  assert.deepEqual(wallet.chains, ["sui:devnet"]);
  assert.deepEqual(Object.keys(wallet.features).sort(), [
    "standard:connect",
    "standard:disconnect",
    "standard:events",
    "sui:signPersonalMessage",
    "sui:signTransaction",
  ]);
  assert.equal(typeof wallet.features["sui:signPersonalMessage"].signPersonalMessage, "function");
  assert.equal(wallet.features["sui:signMessage"], undefined);
  assert.equal(wallet.features["sui:signAndExecuteTransaction"], undefined);
  assert.equal(wallet.features["sui:signTransactionBlock"], undefined);
});

test("Wallet Standard adapter rejects malformed chain and initializer network inputs", () => {
  const { core } = createSigningCore();
  const provider = createAgentQSuiProvider({ core });
  assert.throws(
    () => createAgentQSuiWallet({
      provider,
      getClient: fakeClient,
      chains: ["evm:mainnet"],
    }),
    /unsupported chain/,
  );
  assert.throws(
    () => createAgentQSuiWallet({
      provider,
      getClient: fakeClient,
      chains: [],
    }),
    /requires at least one Sui chain/,
  );
  const initializer = createAgentQSuiWalletInitializer({ provider });
  assert.throws(
    () => initializer.initialize({
      networks: ["customnet"],
      getClient: fakeClient,
    }),
    /unsupported network/,
  );
  assert.throws(
    () => initializer.initialize({
      networks: [],
      getClient: fakeClient,
    }),
    /requires at least one Sui network/,
  );
});

test("Wallet Standard connect and disconnect delegate through provider-sui without leaking management APIs", async () => {
  const { core } = createSigningCore();
  const wallet = createAgentQSuiWallet({
    provider: createAgentQSuiProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  const changes = [];
  const unsubscribe = wallet.features[StandardEvents].on("change", (properties) => {
    changes.push(properties);
  });
  const silent = await wallet.features[StandardConnect].connect({ silent: true });
  assert.deepEqual(silent.accounts, []);
  const connected = await wallet.features[StandardConnect].connect();
  assert.equal(connected.accounts.length, 1);
  assert.equal(connected.accounts[0].address, SUI_ADDRESS);
  assert.deepEqual(connected.accounts[0].chains, ["sui:devnet"]);
  assert.deepEqual(connected.accounts[0].features, [SuiSignTransaction, SuiSignPersonalMessage]);
  assertNoSecretFields(connected);
  assert.equal(wallet.policyGet, undefined);
  assert.equal(wallet.getApprovalHistory, undefined);
  assert.equal(wallet.signTransaction, undefined);
  await wallet.features[StandardDisconnect].disconnect();
  unsubscribe();
  assert.equal(wallet.accounts.length, 0);
  assert.equal(changes.length, 2);
  assert.deepEqual(changes.map((change) => change.accounts.length), [1, 0]);
});

test("Wallet Standard account features follow Firmware signing capability", async () => {
  const core = {
    ...createFakeCore(),
    async getCapabilities() {
      return {
        source: "live",
        deviceId: "device-1",
        capabilities: [
          {
            id: "sui",
            accounts: [{ keyScheme: "ed25519", derivationPath: SUI_DERIVATION_PATH }],
            methods: [],
          },
        ],
        signing: {
          authorization: "policy",
          methods: [
            { chain: "sui", method: "sign_transaction" },
          ],
        },
      };
    },
  };
  const wallet = createAgentQSuiWallet({
    provider: createAgentQSuiProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  const { accounts } = await wallet.features[StandardConnect].connect();
  assert.deepEqual(accounts[0].features, [SuiSignTransaction]);
  await assert.rejects(
    () => wallet.features[SuiSignPersonalMessage].signPersonalMessage({
      account: accounts[0],
      chain: "sui:devnet",
      message: new TextEncoder().encode("hello Agent-Q"),
    }),
    /does not support/,
  );
});

test("Wallet Standard direct capabilities exact validator maps current signing matrices", async () => {
  const cases = [
    {
      output: validCapabilitiesResult(),
      expectedFeatures: [SuiSignTransaction, SuiSignPersonalMessage],
      label: "user mode",
    },
    {
      output: validCapabilitiesResult({ authorization: "policy" }),
      expectedFeatures: [SuiSignTransaction],
      label: "policy mode",
    },
  ];
  for (const { output, expectedFeatures, label } of cases) {
    const wallet = createAgentQSuiWallet({
      provider: {
        ...createFakeCore(),
        async getCapabilities() {
          return output;
        },
      },
      getClient: fakeClient,
      chains: ["sui:devnet"],
    });
    const connected = await wallet.features[StandardConnect].connect();
    assert.deepEqual(connected.accounts[0].features, expectedFeatures, label);
  }
});

test("Wallet Standard direct capabilities exact validator rejects malformed provider output", async () => {
  const mutate = (fn) => {
    const output = cloneJson(validCapabilitiesResult());
    fn(output);
    return output;
  };
  const cases = [
    {
      output: mutate((output) => {
        delete output.deviceId;
      }),
      label: "missing deviceId",
    },
    {
      output: mutate((output) => {
        output.deviceId = "device id with spaces";
      }),
      label: "malformed deviceId",
    },
    {
      output: mutate((output) => {
        delete output.capabilities;
      }),
      label: "missing capabilities",
    },
    {
      output: mutate((output) => {
        delete output.signing;
      }),
      label: "missing signing capability",
    },
    {
      output: mutate((output) => {
        output.sessionId = "session_should_not_leak";
      }),
      label: "top-level extra field",
    },
    {
      output: mutate((output) => {
        output.source = "cached";
      }),
      label: "invalid source",
    },
    {
      output: mutate((output) => {
        output.capabilities[0].id = "solana";
      }),
      label: "unsupported chain id",
    },
    {
      output: mutate((output) => {
        output.capabilities.push(cloneJson(output.capabilities[0]));
      }),
      label: "multiple chains",
    },
    {
      output: mutate((output) => {
        output.capabilities[0].network = "devnet";
      }),
      label: "chain extra field",
    },
    {
      output: mutate((output) => {
        output.capabilities[0].methods = ["sign_transaction"];
      }),
      label: "non-empty chain methods",
    },
    {
      output: mutate((output) => {
        output.capabilities[0].accounts[0].keyScheme = "secp256k1";
      }),
      label: "wrong capability account key scheme",
    },
    {
      output: mutate((output) => {
        output.capabilities[0].accounts[0].derivationPath = "m/44'/784'/1'/0'/0'";
      }),
      label: "wrong capability account derivation path",
    },
    {
      output: mutate((output) => {
        output.capabilities[0].accounts[0].label = "unexpected";
      }),
      label: "capability account extra field",
    },
    {
      output: mutate((output) => {
        output.signing.methods.push({ chain: "sui", method: "sign_transaction" });
      }),
      label: "duplicate signing method",
    },
    {
      output: mutate((output) => {
        output.signing.methods = [{ chain: "sui", method: "sign_transaction" }];
      }),
      label: "user mode missing personal-message signing",
    },
    {
      output: validCapabilitiesResult({
        authorization: "policy",
        methods: [
          { chain: "sui", method: "sign_transaction" },
          { chain: "sui", method: "sign_personal_message" },
        ],
      }),
      label: "policy mode must not advertise personal-message signing",
    },
    {
      output: mutate((output) => {
        output.signing.maxBatchSize = 1;
      }),
      label: "signing extra field",
    },
    {
      output: mutate((output) => {
        output.signing.methods[0].label = "transaction";
      }),
      label: "signing method entry extra field",
    },
  ];
  for (const { output, label } of cases) {
    let disconnectCalls = 0;
    const wallet = createAgentQSuiWallet({
      provider: {
        ...createFakeCore(),
        async disconnectDevice() {
          disconnectCalls += 1;
          return createFakeCore().disconnectDevice();
        },
        async getCapabilities() {
          return output;
        },
      },
      getClient: fakeClient,
      chains: ["sui:devnet"],
    });
    await assert.rejects(
      () => wallet.features[StandardConnect].connect(),
      /supported signing methods/,
      label,
    );
    assert.equal(wallet.accounts.length, 0, label);
    assert.equal(disconnectCalls, 1, label);
  }
});

test("Wallet Standard connect fails closed when provider-sui returns no Sui account", async () => {
  let disconnectCalls = 0;
  const provider = {
    async connectDevice() {
      return createFakeCore().connectDevice();
    },
    async disconnectDevice() {
      disconnectCalls += 1;
      return createFakeCore().disconnectDevice();
    },
    async getAccounts() {
      return {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            chain: "evm",
            address: SUI_ADDRESS,
            publicKey: SUI_PUBLIC_KEY,
            keyScheme: "ed25519",
            derivationPath: SUI_DERIVATION_PATH,
          },
        ],
      };
    },
    async getCapabilities() {
      return createFakeCore().getCapabilities();
    },
    async signTransaction() {
      return createFakeCore().signTransaction();
    },
    async signPersonalMessage() {
      return createFakeCore().signPersonalMessage();
    },
  };
  const wallet = createAgentQSuiWallet({
    provider,
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  await assert.rejects(
    () => wallet.features[StandardConnect].connect(),
    /could not read a connected Sui account/,
  );
  assert.equal(wallet.accounts.length, 0);
  assert.equal(disconnectCalls, 1);
});

test("Wallet Standard connect exact-validates directly injected Sui accounts", async () => {
  const validAccount = (await createFakeCore().getAccounts()).accounts[0];
  const cases = [
    {
      label: "top-level account output extra field",
      output: {
        source: "live",
        deviceId: "device-1",
        accounts: [validAccount],
        sessionId: "session_should_not_leak",
      },
    },
    {
      label: "account extra field",
      output: {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            ...validAccount,
            label: "unexpected",
          },
        ],
      },
    },
    {
      label: "address/publicKey mismatch",
      output: {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            ...validAccount,
            address: "0x0000000000000000000000000000000000000000000000000000000000000000",
          },
        ],
      },
    },
    {
      label: "short Ed25519 public key",
      output: {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            ...validAccount,
            publicKey: Buffer.alloc(31, 1).toString("base64"),
          },
        ],
      },
    },
    {
      label: "wrong key scheme",
      output: {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            ...validAccount,
            keyScheme: "secp256k1",
          },
        ],
      },
    },
  ];

  for (const { label, output } of cases) {
    let disconnectCalls = 0;
    const provider = {
      ...createFakeCore(),
      async disconnectDevice() {
        disconnectCalls += 1;
        return createFakeCore().disconnectDevice();
      },
      async getAccounts() {
        return output;
      },
    };
    const wallet = createAgentQSuiWallet({
      provider,
      getClient: fakeClient,
      chains: ["sui:devnet"],
    });
    await assert.rejects(
      () => wallet.features[StandardConnect].connect(),
      /could not read a connected Sui account/,
      label,
    );
    assert.equal(wallet.accounts.length, 0, label);
    assert.equal(disconnectCalls, 1, label);
  }
});

test("Wallet Standard signTransaction builds bytes and delegates to signTransaction only", async () => {
  const { core, calls } = createSigningCore();
  const wallet = createAgentQSuiWallet({
    provider: createAgentQSuiProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
    deviceId: "device-1",
    purpose: "sui-dapp",
  });
  const { accounts } = await wallet.features[StandardConnect].connect();
  const transactionJson = await createResolvedTransactionJson();
  const signed = await wallet.features[SuiSignTransaction].signTransaction({
    account: accounts[0],
    chain: "sui:devnet",
    transaction: { toJSON: async () => transactionJson },
  });
  assert.equal(signed.signature, SUI_SIGNATURE);
  assert.equal(typeof signed.bytes, "string");
  assert.deepEqual(calls, [
    {
      deviceId: "device-1",
      purpose: "sui-dapp",
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: signed.bytes,
    },
  ]);
  assertNoSecretFields(signed);
});

test("Wallet Standard signPersonalMessage delegates to signPersonalMessage only", async () => {
  const { core, calls } = createSigningCore();
  const wallet = createAgentQSuiWallet({
    provider: createAgentQSuiProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
    deviceId: "device-1",
    purpose: "sui-dapp",
  });
  const { accounts } = await wallet.features[StandardConnect].connect();
  calls.length = 0;
  const message = new TextEncoder().encode("hello Agent-Q");
  const signed = await wallet.features[SuiSignPersonalMessage].signPersonalMessage({
    account: accounts[0],
    chain: "sui:devnet",
    message,
  });
  assert.equal(signed.signature, SUI_SIGNATURE);
  assert.equal(signed.bytes, Buffer.from(message).toString("base64"));
  assert.deepEqual(calls, [
    {
      deviceId: "device-1",
      purpose: "sui-dapp",
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: signed.bytes,
    },
  ]);
  assertNoSecretFields(signed);
});

test("Wallet Standard signTransaction fails closed for wrong account, wrong chain, and terminal results", async () => {
  const { core } = createSigningCore();
  const wallet = createAgentQSuiWallet({
    provider: createAgentQSuiProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  const { accounts } = await wallet.features[StandardConnect].connect();
  const transactionJson = await createResolvedTransactionJson();
  await assert.rejects(
    () => wallet.features[SuiSignTransaction].signTransaction({
      account: accounts[0],
      chain: "sui:mainnet",
      transaction: { toJSON: async () => transactionJson },
    }),
    /does not support/,
  );
  await assert.rejects(
    () => wallet.features[SuiSignTransaction].signTransaction({
      account: {
        address: "0x0000000000000000000000000000000000000000000000000000000000000000",
        publicKey: accounts[0].publicKey,
        chains: accounts[0].chains,
        features: accounts[0].features,
      },
      chain: "sui:devnet",
      transaction: { toJSON: async () => transactionJson },
    }),
    /not connected/,
  );
  const rejectingCore = {
    ...createFakeCore(),
    async signTransaction() {
      return {
        source: "live",
        deviceId: "device-1",
        status: "user_rejected",
        authorization: "user",
        error: {
          code: "user_rejected",
          message: "The signing request was rejected on the device.",
        },
      };
    },
  };
  const rejectingWallet = createAgentQSuiWallet({
    provider: createAgentQSuiProvider({ core: rejectingCore }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  const rejectingConnect = await rejectingWallet.features[StandardConnect].connect();
  await assert.rejects(
    () => rejectingWallet.features[SuiSignTransaction].signTransaction({
      account: rejectingConnect.accounts[0],
      chain: "sui:devnet",
      transaction: { toJSON: async () => transactionJson },
    }),
    /rejected on the device/,
  );
});

test("Wallet Standard signTransaction emits bounded canonical terminal errors", async () => {
  for (const status of ["user_rejected", "user_timed_out", "signing_failed"]) {
    const core = {
      ...createFakeCore(),
      async signTransaction() {
        return {
          source: "live",
          deviceId: "device-1",
          status,
          authorization: "user",
          error: {
            code: status,
            message: "sessionId=session_should_not_leak rootEntropy=secret_should_not_leak",
          },
        };
      },
    };
    const wallet = createAgentQSuiWallet({
      provider: core,
      getClient: fakeClient,
      chains: ["sui:devnet"],
    });
    const { accounts } = await wallet.features[StandardConnect].connect();
    const transactionJson = await createResolvedTransactionJson();
    await assert.rejects(
      () => wallet.features[SuiSignTransaction].signTransaction({
        account: accounts[0],
        chain: "sui:devnet",
        transaction: { toJSON: async () => transactionJson },
      }),
      (error) => {
        assert.equal(error.message, SIGN_RESULT_ERROR_MESSAGES[status]);
        assert.doesNotMatch(error.message, /sessionId|rootEntropy|secret_should_not_leak/);
        return true;
      },
    );
  }
});

test("Wallet Standard signTransaction bounds unknown injected provider result labels", async () => {
  const cases = [
    {
      signResult: {
        source: "sessionId=session_should_not_leak",
        deviceId: "device-1",
        reason: "transport_unavailable",
      },
    },
    {
      signResult: {
        source: "live",
        deviceId: "device-1",
        status: "rootEntropy=secret_should_not_leak",
        authorization: "user",
      },
    },
  ];
  for (const { signResult } of cases) {
    const core = {
      ...createFakeCore(),
      async signTransaction() {
        return signResult;
      },
    };
    const wallet = createAgentQSuiWallet({
      provider: core,
      getClient: fakeClient,
      chains: ["sui:devnet"],
    });
    const { accounts } = await wallet.features[StandardConnect].connect();
    const transactionJson = await createResolvedTransactionJson();
    await assert.rejects(
      () => wallet.features[SuiSignTransaction].signTransaction({
        account: accounts[0],
        chain: "sui:devnet",
        transaction: { toJSON: async () => transactionJson },
      }),
      (error) => {
        assert.equal(error.message, "Agent-Q signTransaction did not return a signed result.");
        assert.doesNotMatch(error.message, /sessionId|rootEntropy|secret_should_not_leak/);
        return true;
      },
    );
  }
});

test("Wallet Standard signTransaction exact-validates directly injected signed results", async () => {
  const malformedResults = [
    {
      label: "missing method",
      result: (() => {
        const { method, ...rest } = validSignedTransactionResult();
        return rest;
      })(),
    },
    {
      label: "missing authorization",
      result: (() => {
        const { authorization, ...rest } = validSignedTransactionResult();
        return rest;
      })(),
    },
    {
      label: "missing chain",
      result: (() => {
        const { chain, ...rest } = validSignedTransactionResult();
        return rest;
      })(),
    },
    {
      label: "personal-message method",
      result: {
        ...validSignedTransactionResult(),
        method: "sign_personal_message",
      },
    },
    {
      label: "messageBytes on transaction result",
      result: {
        ...validSignedTransactionResult(),
        messageBytes: PERSONAL_MESSAGE_BYTES,
      },
    },
    {
      label: "txBytes on transaction result",
      result: {
        ...validSignedTransactionResult(),
        txBytes: "AQID",
      },
    },
  ];

  for (const { label, result } of malformedResults) {
    const provider = {
      ...createFakeCore(),
      async signTransaction() {
        return result;
      },
    };
    const wallet = createAgentQSuiWallet({
      provider,
      getClient: fakeClient,
      chains: ["sui:devnet"],
    });
    const { accounts } = await wallet.features[StandardConnect].connect();
    const transactionJson = await createResolvedTransactionJson();
    await assert.rejects(
      () => wallet.features[SuiSignTransaction].signTransaction({
        account: accounts[0],
        chain: "sui:devnet",
        transaction: { toJSON: async () => transactionJson },
      }),
      (error) => {
        assert.equal(error.message, "Agent-Q signTransaction did not return a signed result.");
        return true;
      },
      label,
    );
  }
});

test("Wallet Standard signPersonalMessage exact-validates directly injected signed results", async () => {
  const malformedResults = [
    {
      label: "missing authorization",
      result: (() => {
        const { authorization, ...rest } = validSignedPersonalMessageResult();
        return rest;
      })(),
    },
    {
      label: "missing chain",
      result: (() => {
        const { chain, ...rest } = validSignedPersonalMessageResult();
        return rest;
      })(),
    },
    {
      label: "policy authorization",
      result: {
        ...validSignedPersonalMessageResult(),
        authorization: "policy",
      },
    },
    {
      label: "transaction method",
      result: {
        ...validSignedPersonalMessageResult(),
        method: "sign_transaction",
      },
    },
    {
      label: "wrong messageBytes echo",
      result: validSignedPersonalMessageResult(Buffer.from("different").toString("base64")),
    },
    {
      label: "txBytes on personal-message result",
      result: {
        ...validSignedPersonalMessageResult(),
        txBytes: "AQID",
      },
    },
  ];

  for (const { label, result } of malformedResults) {
    const provider = {
      ...createFakeCore(),
      async signPersonalMessage() {
        return result;
      },
    };
    const wallet = createAgentQSuiWallet({
      provider,
      getClient: fakeClient,
      chains: ["sui:devnet"],
    });
    const { accounts } = await wallet.features[StandardConnect].connect();
    await assert.rejects(
      () => wallet.features[SuiSignPersonalMessage].signPersonalMessage({
        account: accounts[0],
        chain: "sui:devnet",
        message: Buffer.from("Agent-Q personal message"),
      }),
      (error) => {
        assert.equal(error.message, "Agent-Q signPersonalMessage did not return a signed result.");
        return true;
      },
      label,
    );
  }
});

test("Wallet Standard signTransaction validates chain support against the connected account", async () => {
  const { core, calls } = createSigningCore();
  const wallet = createAgentQSuiWallet({
    provider: createAgentQSuiProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  const { accounts } = await wallet.features[StandardConnect].connect();
  const transactionJson = await createResolvedTransactionJson();
  await assert.rejects(
    () => wallet.features[SuiSignTransaction].signTransaction({
      account: {
        address: accounts[0].address,
        publicKey: accounts[0].publicKey,
        chains: ["sui:mainnet"],
        features: [SuiSignTransaction],
      },
      chain: "sui:mainnet",
      transaction: { toJSON: async () => transactionJson },
    }),
    /does not support/,
  );
  assert.deepEqual(calls, []);
});

test("Wallet Standard signTransaction clears connected accounts on non-live signing results", async () => {
  const cases = [
    {
      signResult: { source: "session_ended", reason: "transport_unavailable" },
      expectedMessage: "Agent-Q Sui wallet session ended before signing completed.",
    },
    {
      signResult: { source: "not_connected", reason: "not_connected" },
      expectedMessage: "Agent-Q Sui wallet is not connected.",
    },
  ];
  for (const { signResult, expectedMessage } of cases) {
    const core = {
      ...createFakeCore(),
      async signTransaction() {
        return {
          ...signResult,
          deviceId: "device-1",
        };
      },
    };
    const wallet = createAgentQSuiWallet({
      provider: createAgentQSuiProvider({ core }),
      getClient: fakeClient,
      chains: ["sui:devnet"],
    });
    const changes = [];
    const unsubscribe = wallet.features[StandardEvents].on("change", (properties) => {
      changes.push(properties);
    });
    const { accounts } = await wallet.features[StandardConnect].connect();
    const transactionJson = await createResolvedTransactionJson();
    await assert.rejects(
      () => wallet.features[SuiSignTransaction].signTransaction({
        account: accounts[0],
        chain: "sui:devnet",
        transaction: { toJSON: async () => transactionJson },
      }),
      (error) => {
        assert.equal(error.message, expectedMessage);
        return true;
      },
    );
    unsubscribe();
    assert.equal(wallet.accounts.length, 0);
    assert.deepEqual(changes.map((change) => change.accounts.length), [1, 0]);
  }
});

test("Wallet Standard registration functions register, initialize, and unregister Agent-Q wallets", () => {
  const { core } = createSigningCore();
  const provider = createAgentQSuiProvider({ core });
  const before = new Set(getWallets().get());
  const registration = registerAgentQSuiWallet({
    provider,
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  assert.equal(getWallets().get().includes(registration.wallet), true);
  registration.unregister();
  assert.deepEqual(new Set(getWallets().get()), before);

  const initializer = createAgentQSuiWalletInitializer({ provider, id: "agent-q-test" });
  assert.equal(initializer.id, "agent-q-test");
  const initialized = initializer.initialize({
    networks: ["devnet"],
    getClient: fakeClient,
  });
  assert.equal(getWallets().get().includes(initialized.wallet), true);
  assert.deepEqual(initialized.wallet.chains, ["sui:devnet"]);
  initialized.unregister();
  assert.deepEqual(new Set(getWallets().get()), before);
});
