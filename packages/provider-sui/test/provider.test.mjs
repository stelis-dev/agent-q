import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test, { mock } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Transaction } from "@mysten/sui/transactions";
import {
  getWallets,
  StandardConnect,
  StandardDisconnect,
  StandardEvents,
  SuiSignPersonalMessage,
  SuiSignTransaction,
} from "@mysten/wallet-standard";
import { createSuiDeviceProvider, SuiDeviceProvider } from "../dist/provider-sui.js";
import {
  SUI_DEVICE_WALLET_ID,
  SUI_DEVICE_WALLET_NAME,
  SuiDeviceWallet,
  createSuiDeviceWallet,
  createSuiDeviceWalletInitializer,
  registerSuiDeviceWallet,
} from "../dist/wallet-standard.js";
import {
  SuiBrowserDeviceProvider,
  createSuiBrowserDeviceProvider,
  isSuiBrowserDeviceProviderAvailable,
} from "../dist/browser.js";
import { openBrowserLocalTransport } from "../dist/browser-local-transport.js";
import {
  FORBIDDEN_SECRET_FIELD_NAMES,
  makeDeviceError,
  parseDeviceResponse,
  SIGNING_OUTCOME_ERROR_MESSAGES,
  SUI_DERIVATION_PATH,
} from "@stelis/agent-q-core/protocol";
import {
  FIRMWARE_USB_PRODUCT_ID_NUMBER,
  FIRMWARE_USB_VENDOR_ID_NUMBER,
  PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES,
} from "@stelis/agent-q-core/provider-protocol";
import {
  credentialPrepareSuccessOutputShape,
  credentialProposeSuccessOutputShape,
} from "@stelis/agent-q-core/adapter-internal";

const SUI_ADDRESS = "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133";
const SUI_PUBLIC_KEY = "ACJkf+7vNjBgvUIFoWcaFfEKEjZ2WRixtfY42C8zz8Rp";
const ZKLOGIN_ADDRESS = "0xd41c7cbc0cbccb9e7ab701373f3b5f082cc0024098f2ab561ff342107b91491f";
const ZKLOGIN_PUBLIC_KEY =
  "BRtodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ==";
function makeEd25519Signature(fill = 1) {
  const bytes = Buffer.alloc(97, fill);
  bytes[0] = 0;
  return bytes.toString("base64");
}
function makeZkLoginSignature(byteLength = 145) {
  const bytes = Buffer.alloc(byteLength, 6);
  bytes[0] = 5;
  return bytes.toString("base64");
}
const SUI_SIGNATURE = makeEd25519Signature(1);
const ZKLOGIN_SIGNATURE = makeZkLoginSignature();
const PERSONAL_MESSAGE_BYTES = Buffer.from("Agent-Q personal message").toString("base64");
const APP_WEB_SIZED_TRANSACTION_BYTES = Buffer.alloc(656, 1).toString("base64");
const APP_WEB_SIZED_PERSONAL_MESSAGE_BYTES = Buffer.alloc(518, 1).toString("base64");

function assertNoSecretFields(value) {
  const text = JSON.stringify(value).toLowerCase();
  for (const fieldName of FORBIDDEN_SECRET_FIELD_NAMES) {
    assert.equal(text.includes(fieldName.toLowerCase()), false, `${fieldName} must not appear in provider output`);
  }
  assert.equal(text.includes("sessionid"), false, "sessionId must not appear in provider output");
}

const ESM_IMPORT_RE =
  /\bimport\s+(?:[^'"]*?\s+from\s+)?["']([^"']+)["']|\bexport\s+[^'"]*?\s+from\s+["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;

function staticImportSpecifiers(source) {
  const specifiers = [];
  for (const match of source.matchAll(ESM_IMPORT_RE)) {
    specifiers.push(match[1] ?? match[2] ?? match[3]);
  }
  return specifiers;
}

async function collectBrowserRuntimeImportGraph(entryPath) {
  const visited = new Map();
  const edges = [];

  async function visit(filePath) {
    if (visited.has(filePath)) {
      return;
    }
    const source = await readFile(filePath, "utf8");
    visited.set(filePath, source);
    for (const specifier of staticImportSpecifiers(source)) {
      edges.push({ from: filePath, specifier });
      let resolvedPath = null;
      if (specifier.startsWith(".")) {
        resolvedPath = fileURLToPath(new URL(specifier, pathToFileURL(filePath)));
      } else if (specifier.startsWith("@stelis/agent-q-core/")) {
        resolvedPath = fileURLToPath(import.meta.resolve(specifier));
      }
      if (resolvedPath !== null) {
        await visit(resolvedPath);
      }
    }
  }

  await visit(entryPath);
  return { visited, edges };
}

function validCredentialCapability() {
  return {
    chain: "sui",
    credential: "zklogin",
    operations: ["credential_prepare", "credential_propose"],
  };
}

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

function validCredentialPrepareInput(overrides = {}) {
  return {
    deviceId: "device-1",
    chain: "sui",
    credential: "zklogin",
    ...overrides,
  };
}

function validCredentialProposeInput(overrides = {}) {
  return {
    deviceId: "device-1",
    chain: "sui",
    credential: "zklogin",
    network: "testnet",
    address: ZKLOGIN_ADDRESS,
    publicKey: ZKLOGIN_PUBLIC_KEY,
    maxEpoch: "42",
    inputs: validZkLoginInputs(),
    ...overrides,
  };
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
            sponsoredTransactions: {
              acceptGasSponsor: false,
            },
          },
        ],
      };
    },
    async credentialPrepare() {
      return {
        source: "live",
        deviceId: "device-1",
        chain: "sui",
        credential: "zklogin",
        preparation: {
          address: SUI_ADDRESS,
          publicKey: SUI_PUBLIC_KEY,
          keyScheme: "ed25519",
        },
      };
    },
    async credentialPropose() {
      return {
        source: "live",
        deviceId: "device-1",
        status: "activated",
        reasonCode: "activated",
        sessionEnded: true,
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

function createDeviceCore() {
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
  #info;
  #responseForRequest;

  constructor(responseForRequest, info = {
    usbVendorId: FIRMWARE_USB_VENDOR_ID_NUMBER,
    usbProductId: FIRMWARE_USB_PRODUCT_ID_NUMBER,
  }) {
    this.#responseForRequest = responseForRequest;
    this.#info = info;
  }

  getInfo() {
    return this.#info;
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

function requestKind(request) {
  return request.type ?? request.method;
}

function deviceSuccess(request, result, method = requestKind(request)) {
  return {
    id: request.id,
    version: 1,
    success: true,
    method,
    result,
  };
}

function deviceFailure(request, code, method = requestKind(request)) {
  return {
    ...(request?.id === undefined ? {} : { id: request.id }),
    version: 1,
    success: false,
    ...(method === null || method === undefined ? {} : { method }),
    error: makeDeviceError(code),
  };
}

function payloadTransferFailure(request, code) {
  return deviceFailure(request, code, null);
}

function createFakeBrowserDeviceResponse(request) {
  const requestType = requestKind(request);
  const requestParams = request.params ?? request.payload ?? {};
  const device = {
    deviceId: "device-1",
    state: "idle",
    firmwareName: "Agent-Q Firmware",
    hardware: "stackchan-cores3",
    firmwareVersion: "0.0.0",
  };
  switch (requestType) {
    case "connect":
      return deviceSuccess(request, {
        sessionId: "session_abcdef0123456789",
        sessionTtlMs: 60000,
        device,
      });
    case "disconnect":
      return deviceSuccess(request, {});
    case "get_capabilities":
      return deviceSuccess(request, {
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
        credentials: [validCredentialCapability()],
      });
    case "get_accounts":
      return deviceSuccess(request, {
        accounts: [
          {
            chain: "sui",
            address: SUI_ADDRESS,
            publicKey: SUI_PUBLIC_KEY,
            keyScheme: "ed25519",
            derivationPath: SUI_DERIVATION_PATH,
            sponsoredTransactions: {
              acceptGasSponsor: false,
            },
          },
        ],
      });
    case "sign_transaction":
      return deviceSuccess(request, {
        authorization: "user",
        chain: "sui",
        method: "sign_transaction",
        signature: SUI_SIGNATURE,
      });
    case "sign_personal_message":
      return deviceSuccess(request, {
        authorization: "user",
        chain: "sui",
        method: "sign_personal_message",
        signature: SUI_SIGNATURE,
        messageBytes: requestParams.message,
      });
    case "credential_prepare":
      return deviceSuccess(request, {
        chain: "sui",
        credential: "zklogin",
        preparation: {
          address: SUI_ADDRESS,
          publicKey: SUI_PUBLIC_KEY,
          keyScheme: "ed25519",
        },
      });
    case "credential_propose":
      return deviceSuccess(request, {
        status: "activated",
        reasonCode: "activated",
        sessionEnded: true,
      });
    default:
      return deviceFailure(request, "unsupported_method");
  }
}

function browserSignedTransactionResult(request) {
  return deviceSuccess(request, {
    authorization: "user",
    chain: "sui",
    method: "sign_transaction",
    signature: SUI_SIGNATURE,
  }, "get_result");
}

function browserSignedPersonalMessageResult(request, messageBytes = PERSONAL_MESSAGE_BYTES) {
  return deviceSuccess(request, {
    authorization: "user",
    chain: "sui",
    method: "sign_personal_message",
    signature: SUI_SIGNATURE,
    messageBytes,
  }, "get_result");
}

function browserAckResult(request) {
  return deviceSuccess(request, {}, "ack_result");
}

function browserTerminalSigningOutcome(request, status) {
  if (status === "policy_rejected") {
    return deviceFailure(request, "policy_rejected", "get_result");
  }
  if (status === "user_timed_out") {
    return deviceFailure(request, "timeout", "get_result");
  }
  return deviceFailure(request, status, "get_result");
}

function terminalStatusDeviceErrorCode(status) {
  return status === "user_timed_out" ? "timeout" : status;
}

function browserSignErrorResult(request, code) {
  return deviceFailure(request, code, requestKind(request));
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
  assert.equal(typeof root.createSuiDeviceProvider, "function");
  assert.equal(typeof provider.SuiDeviceProvider, "function");
  assert.equal(walletStandard.SUI_DEVICE_WALLET_ID, SUI_DEVICE_WALLET_ID);
  assert.equal(walletStandard.SUI_DEVICE_WALLET_NAME, SUI_DEVICE_WALLET_NAME);
  assert.equal(typeof walletStandard.createSuiDeviceWallet, "function");
  assert.equal(typeof walletStandard.registerSuiDeviceWallet, "function");
  assert.equal(typeof walletStandard.createSuiDeviceWalletInitializer, "function");
  assert.equal(typeof browser.createSuiBrowserDeviceProvider, "function");
  assert.equal(typeof browser.isSuiBrowserDeviceProviderAvailable, "function");
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
  assert.match(source, /@stelis\/agent-q-core\/protocol["']/);
  assert.match(source, /@stelis\/agent-q-core\/device-request-internal/);
  assert.doesNotMatch(source, /@stelis\/agent-q-core\/adapter-internal/);
  assert.doesNotMatch(source, /@stelis\/agent-q-core\/admin/);
  assert.doesNotMatch(source, /@stelis\/agent-q(?!-core)/);
  assert.doesNotMatch(source, /serialport/);
  assert.doesNotMatch(source, /node:/);
  assert.doesNotMatch(source, /policy_get/);
  assert.doesNotMatch(source, /policy_propose/);
  assert.doesNotMatch(source, /get_approval_history/);
  assert.match(source, /requestDevice/);

  const browserTypesPath = fileURLToPath(new URL("../dist/browser.d.ts", import.meta.url));
  const types = await readFile(browserTypesPath, "utf8");
  assert.doesNotMatch(types, /@stelis\/agent-q-core\/admin/);
  assert.doesNotMatch(types, /@stelis\/agent-q(?!-core)/);
  assert.doesNotMatch(types, /requestTimeoutMs/);
  assert.doesNotMatch(types, /requestPort/);
  assert.doesNotMatch(types, /serial\?/);
  assert.doesNotMatch(types, /baudRate/);
  assert.doesNotMatch(types, /adapter-internal/);
  assert.doesNotMatch(types, /payload-delivery-internal/);
  assert.doesNotMatch(types, /serialport/);
  assert.doesNotMatch(types, /node:/);
});

test("browser provider runtime import graph stays separated from host-only core modules", async () => {
  const browserPath = fileURLToPath(new URL("../dist/browser.js", import.meta.url));
  const { visited, edges } = await collectBrowserRuntimeImportGraph(browserPath);
  const visitedPaths = [...visited.keys()].join("\n");

  assert.doesNotMatch(visitedPaths, /(?:^|\/)adapter-internal\.(?:js|d\.ts)$/);
  assert.doesNotMatch(visitedPaths, /(?:^|\/)host-output-schema\.js$/);
  assert.doesNotMatch(visitedPaths, /(?:^|\/)config\.js$/);
  assert.doesNotMatch(visitedPaths, /(?:^|\/)usb\.js$/);

  for (const edge of edges) {
    assert.notEqual(edge.specifier, "@stelis/agent-q-core/adapter-internal");
    assert.notEqual(edge.specifier, "serialport");
    assert.equal(edge.specifier.startsWith("node:"), false, `${edge.from} imports ${edge.specifier}`);
  }
});

test("browser provider runtime defers Web Serial port selection until connectDevice", async () => {
  let requestPortCalls = 0;
  const port = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {},
    });
    assert.equal(isSuiBrowserDeviceProviderAvailable(), false);

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
    const provider = createSuiBrowserDeviceProvider({ clientName: "Agent-Q Sui dapp-kit Sample" });
    const explicitProvider = createSuiBrowserDeviceProvider({ transport: "web_serial" });
    assert.equal(provider instanceof SuiBrowserDeviceProvider, true);
    assert.equal(explicitProvider instanceof SuiBrowserDeviceProvider, true);
    assert.equal(typeof provider.credentialPrepare, "function");
    assert.equal(typeof provider.credentialPropose, "function");
    assert.equal(isSuiBrowserDeviceProviderAvailable(), true);
    assert.equal(isSuiBrowserDeviceProviderAvailable({ transport: "web_serial" }), true);
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
    assert.deepEqual(capabilities.credentials, [validCredentialCapability()]);

    const accounts = await provider.getAccounts();
    assert.equal(accounts.source, "live");
    assert.equal(accounts.accounts[0].address, SUI_ADDRESS);
    assert.deepEqual(accounts.accounts[0].sponsoredTransactions, {
      acceptGasSponsor: false,
    });
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
    assert.deepEqual(port.requests.map((request) => requestKind(request)), [
      "connect",
      "get_capabilities",
      "get_accounts",
      "sign_transaction",
      "sign_personal_message",
      "disconnect",
    ]);
    assert.equal(port.requests.some((request) => requestKind(request) === "policy_get" || requestKind(request) === "policy_propose"), false);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider exposes BLE only with browser support and an optical payload source", async () => {
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const previousSecureContext = Object.getOwnPropertyDescriptor(globalThis, "isSecureContext");
  let requestDeviceCalls = 0;
  let opticalPayloadReads = 0;
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        bluetooth: {
          requestDevice: async () => {
            requestDeviceCalls += 1;
            throw new Error("chooser rejected");
          },
        },
      },
    });
    Object.defineProperty(globalThis, "isSecureContext", {
      configurable: true,
      value: true,
    });
    assert.equal(isSuiBrowserDeviceProviderAvailable({ transport: "ble" }), true);
    assert.throws(
      () => createSuiBrowserDeviceProvider({ transport: "ble" }),
      { code: "invalid_params" },
    );
    const provider = createSuiBrowserDeviceProvider({
      transport: "ble",
      getOpticalPayload: () => {
        opticalPayloadReads += 1;
        return "aqlt:1?k=ble&svc=a6e31d1051a14f7a9b0a0a1c00000001&idfp=0011223344556677&non=8899aabbccddeeff&exp=120";
      },
    });
    await assert.rejects(
      () => provider.connectDevice(),
      { code: "transport_error" },
    );
    assert.equal(opticalPayloadReads, 1);
    assert.equal(requestDeviceCalls, 1);
  } finally {
    if (previousNavigator === undefined) {
      Reflect.deleteProperty(globalThis, "navigator");
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
    if (previousSecureContext === undefined) {
      Reflect.deleteProperty(globalThis, "isSecureContext");
    } else {
      Object.defineProperty(globalThis, "isSecureContext", previousSecureContext);
    }
  }
});

test("browser local transport bounds a never-settling GATT connection", async () => {
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const previousSecureContext = Object.getOwnPropertyDescriptor(globalThis, "isSecureContext");
  let disconnected = false;
  try {
    const gatt = {
      connected: false,
      connect: () => new Promise((resolve) => {
        setTimeout(() => {
          gatt.connected = true;
          resolve(gatt);
        }, 30);
      }),
      getPrimaryService: async () => {
        throw new Error("unreachable");
      },
      disconnect: () => {
        disconnected = true;
        gatt.connected = false;
      },
    };
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        bluetooth: {
          requestDevice: async () => ({
            gatt,
            addEventListener() {},
            removeEventListener() {},
          }),
        },
      },
    });
    Object.defineProperty(globalThis, "isSecureContext", {
      configurable: true,
      value: true,
    });
    const started = Date.now();
    await assert.rejects(
      () => openBrowserLocalTransport(
        "aqlt:1?k=ble&svc=a6e31d1051a14f7a9b0a0a1c00000001&idfp=0011223344556677&non=8899aabbccddeeff&exp=120",
        undefined,
        { handshakeTimeoutMs: 10, cleanupTimeoutMs: 10 },
      ),
      { code: "timeout" },
    );
    assert.equal(Date.now() - started < 500, true);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(disconnected, true);
  } finally {
    if (previousNavigator === undefined) {
      Reflect.deleteProperty(globalThis, "navigator");
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
    if (previousSecureContext === undefined) {
      Reflect.deleteProperty(globalThis, "isSecureContext");
    } else {
      Object.defineProperty(globalThis, "isSecureContext", previousSecureContext);
    }
  }
});

test("browser provider sends app-web-sized signing payloads through the current request path", async () => {
  assert.equal(Buffer.from(APP_WEB_SIZED_TRANSACTION_BYTES, "base64").length, 656);
  assert.equal(APP_WEB_SIZED_TRANSACTION_BYTES.length, 876);
  assert.equal(Buffer.from(APP_WEB_SIZED_PERSONAL_MESSAGE_BYTES, "base64").length, 518);
  assert.equal(APP_WEB_SIZED_PERSONAL_MESSAGE_BYTES.length, 692);

  const port = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const transactionResult = await provider.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: APP_WEB_SIZED_TRANSACTION_BYTES,
    });
    assert.deepEqual(transactionResult, validSignedTransactionResult());

    const personalMessageResult = await provider.signPersonalMessage({
      chain: "sui",
      method: "sign_personal_message",
      network: "devnet",
      message: APP_WEB_SIZED_PERSONAL_MESSAGE_BYTES,
    });
    assert.deepEqual(personalMessageResult, validSignedPersonalMessageResult(APP_WEB_SIZED_PERSONAL_MESSAGE_BYTES));

    assert.deepEqual(port.requests.map((request) => requestKind(request)), [
      "connect",
      "sign_transaction",
      "sign_personal_message",
    ]);
    assert.equal(port.requests[1].payload.txBytes, APP_WEB_SIZED_TRANSACTION_BYTES);
    assert.equal(port.requests[2].payload.message, APP_WEB_SIZED_PERSONAL_MESSAGE_BYTES);
    assert.equal(port.requests.some((request) => requestKind(request) === "payload_transfer"), false);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider sends credential setup over the active Web Serial session", async () => {
  const port = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const prepare = await provider.credentialPrepare({
      chain: "sui",
      credential: "zklogin",
      purpose: "test-web",
      signerKind: "native",
    });
    const proposeInput = {
      ...validCredentialProposeInput({ purpose: "test-web" }),
      signerKind: "zklogin",
    };
    const propose = await provider.credentialPropose(proposeInput);

    assert.deepEqual(prepare, {
      source: "live",
      deviceId: "device-1",
      chain: "sui",
      credential: "zklogin",
      preparation: {
        address: SUI_ADDRESS,
        publicKey: SUI_PUBLIC_KEY,
        keyScheme: "ed25519",
      },
    });
    assert.deepEqual(propose, {
      source: "live",
      deviceId: "device-1",
      status: "activated",
      reasonCode: "activated",
      sessionEnded: true,
    });
    assert.deepEqual(await provider.getAccounts(), {
      source: "not_connected",
      deviceId: "browser",
      reason: "not_connected",
    });
    assert.deepEqual(port.requests.map((request) => requestKind(request)), [
      "connect",
      "credential_prepare",
      "credential_propose",
    ]);
    assert.deepEqual(port.requests[1].payload, {
      chain: "sui",
      credential: "zklogin",
    });
    assert.equal(Object.hasOwn(port.requests[1].payload, "purpose"), false);
    assert.equal(Object.hasOwn(port.requests[1].payload, "signerKind"), false);
    assert.deepEqual(port.requests[2].payload, {
      chain: "sui",
      credential: "zklogin",
      network: "testnet",
      address: ZKLOGIN_ADDRESS,
      publicKey: ZKLOGIN_PUBLIC_KEY,
      maxEpoch: "42",
      inputs: validZkLoginInputs(),
    });
    assert.equal(Object.hasOwn(port.requests[2].payload, "deviceId"), false);
    assert.equal(Object.hasOwn(port.requests[2].payload, "purpose"), false);
    assert.equal(Object.hasOwn(port.requests[2].payload, "signerKind"), false);
    assertNoSecretFields(prepare);
    assertNoSecretFields(propose);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider credential setup returns not_connected before connect", async () => {
  let requestPortCalls = 0;
  const port = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
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
    const provider = createSuiBrowserDeviceProvider();
    assert.deepEqual(await provider.credentialPrepare({ chain: "sui", credential: "zklogin" }), {
      source: "not_connected",
      deviceId: "browser",
      reason: "not_connected",
    });
    assert.deepEqual(await provider.credentialPropose(validCredentialProposeInput({ deviceId: undefined })), {
      source: "not_connected",
      deviceId: "browser",
      reason: "not_connected",
    });
    assert.equal(requestPortCalls, 0);
    assert.deepEqual(port.requests, []);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider credential setup clears stale sessions on invalid_session", async () => {
  const port = new FakeBrowserSerialPort((request) => {
      if (requestKind(request) === "credential_prepare") {
        return deviceFailure(request, "invalid_session");
      }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    assert.deepEqual(await provider.credentialPrepare({ chain: "sui", credential: "zklogin" }), {
      source: "session_ended",
      deviceId: "device-1",
      reason: "invalid_session",
    });
    assert.deepEqual(await provider.getCapabilities(), {
      source: "not_connected",
      deviceId: "browser",
      reason: "not_connected",
    });
    assert.deepEqual(port.requests.map((request) => requestKind(request)), ["connect", "credential_prepare"]);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider credential setup rejects malformed and secret-bearing responses", async () => {
  {
    const port = new FakeBrowserSerialPort((request) => {
      if (requestKind(request) === "credential_prepare") {
        return {
          ...createFakeBrowserDeviceResponse(request),
          preparation: {
            address: ZKLOGIN_ADDRESS,
            publicKey: SUI_PUBLIC_KEY,
            keyScheme: "ed25519",
          },
        };
      }
      return createFakeBrowserDeviceResponse(request);
    });
    const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    try {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: { serial: { requestPort: async () => port } },
      });
      const provider = createSuiBrowserDeviceProvider();
      assert.equal((await provider.connectDevice()).source, "connected");
      await assert.rejects(
        () => provider.credentialPrepare({ chain: "sui", credential: "zklogin" }),
        { code: "invalid_response" },
      );
    } finally {
      if (previousNavigator === undefined) {
        delete globalThis.navigator;
      } else {
        Object.defineProperty(globalThis, "navigator", previousNavigator);
      }
    }
  }

  {
    const port = new FakeBrowserSerialPort((request) => {
      if (requestKind(request) === "credential_propose") {
        return {
          ...createFakeBrowserDeviceResponse(request),
          jwt: "must_not_leak",
        };
      }
      return createFakeBrowserDeviceResponse(request);
    });
    const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    try {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: { serial: { requestPort: async () => port } },
      });
      const provider = createSuiBrowserDeviceProvider();
      assert.equal((await provider.connectDevice()).source, "connected");
      await assert.rejects(
        () => provider.credentialPropose(validCredentialProposeInput()),
        { code: "invalid_response" },
      );
    } finally {
      if (previousNavigator === undefined) {
        delete globalThis.navigator;
      } else {
        Object.defineProperty(globalThis, "navigator", previousNavigator);
      }
    }
  }
});

test("Wallet Standard does not project browser provider credential setup methods", () => {
  const provider = createSuiBrowserDeviceProvider();
  assert.equal(typeof provider.credentialPrepare, "function");
  assert.equal(typeof provider.credentialPropose, "function");
  const wallet = createSuiDeviceWallet({
    provider,
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  assert.deepEqual(Object.keys(wallet.features).sort(), [
    "standard:connect",
    "standard:disconnect",
    "standard:events",
    "sui:signPersonalMessage",
    "sui:signTransaction",
  ]);
  assert.equal(wallet.features["signing:credentialPrepare"], undefined);
  assert.equal(wallet.features["signing:credentialPropose"], undefined);
  assert.equal(wallet.credentialPrepare, undefined);
  assert.equal(wallet.credentialPropose, undefined);
  assert.equal(wallet.signerKind, undefined);
});

test("browser provider reuses a single granted Agent-Q Web Serial port before prompting", async () => {
  let getPortsCalls = 0;
  let requestPortCalls = 0;
  const otherPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse, {
    usbVendorId: 0x1111,
    usbProductId: 0x2222,
  });
  const grantedPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          getPorts: async () => {
            getPortsCalls += 1;
            return [otherPort, grantedPort];
          },
          requestPort: async () => {
            requestPortCalls += 1;
            throw new Error("requestPort should not run when one granted Agent-Q port exists");
          },
        },
      },
    });
    const provider = createSuiBrowserDeviceProvider();
    const connected = await provider.connectDevice();
    assert.equal(connected.source, "connected");
    assert.equal(connected.deviceId, "device-1");
    assert.equal(getPortsCalls, 1);
    assert.equal(requestPortCalls, 0);
    assert.deepEqual(grantedPort.requests.map((request) => requestKind(request)), ["connect"]);
    assert.deepEqual(otherPort.requests, []);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider falls back to requestPort when granted Agent-Q ports are ambiguous", async () => {
  let getPortsCalls = 0;
  let requestPortCalls = 0;
  const firstGrantedPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const secondGrantedPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const selectedPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          getPorts: async () => {
            getPortsCalls += 1;
            return [firstGrantedPort, secondGrantedPort];
          },
          requestPort: async () => {
            requestPortCalls += 1;
            return selectedPort;
          },
        },
      },
    });
    const provider = createSuiBrowserDeviceProvider();
    const connected = await provider.connectDevice();
    assert.equal(connected.source, "connected");
    assert.equal(connected.deviceId, "device-1");
    assert.equal(getPortsCalls, 1);
    assert.equal(requestPortCalls, 1);
    assert.deepEqual(firstGrantedPort.requests, []);
    assert.deepEqual(secondGrantedPort.requests, []);
    assert.deepEqual(selectedPort.requests.map((request) => requestKind(request)), ["connect"]);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider transfers a synthetic large transaction payload before signing", async () => {
  const payload = Buffer.alloc(16 * 1024);
  for (let index = 0; index < payload.length; index += 1) {
    payload[index] = (index * 29 + 23) & 0xff;
  }
  const methodPayload = {
    chain: "sui",
    network: "mainnet",
    txBytes: payload.toString("base64"),
  };
  const transferredPayload = Buffer.from(JSON.stringify(methodPayload));
  const payloadDigest = `sha256:${createHash("sha256").update(transferredPayload).digest("hex")}`;
  const chunkMaxBytes = 2048;
  const chunks = [];
  let receivedBytes = 0;
  const port = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "payload_transfer" && request.action === "begin") {
      assert.equal(request.totalBytes, String(transferredPayload.length));
      assert.equal(request.payloadDigest, payloadDigest);
      return {
        id: request.id,
        version: 1,
        success: true,
        result: {
          transferId: "transfer_browser_synthetic_0001",
          receivedBytes: "0",
          chunkMaxBytes: String(chunkMaxBytes),
        },
      };
    }
    if (requestKind(request) === "payload_transfer" && request.action === "chunk") {
      assert.equal(request.transferId, "transfer_browser_synthetic_0001");
      assert.equal(request.offsetBytes, String(receivedBytes));
      const chunk = Buffer.from(request.chunk, "base64");
      chunks.push(chunk);
      receivedBytes += chunk.length;
      return {
        id: request.id,
        version: 1,
        success: true,
        result: { receivedBytes: String(receivedBytes) },
      };
    }
    if (requestKind(request) === "payload_transfer" && request.action === "finish") {
      assert.equal(request.transferId, "transfer_browser_synthetic_0001");
      assert.equal(receivedBytes, transferredPayload.length);
      return {
        id: request.id,
        version: 1,
        success: true,
        result: { payloadRef: "payload_browser_synthetic_0001" },
      };
    }
    if (requestKind(request) === "sign_transaction") {
      assert.deepEqual(request.payload, { payloadRef: "payload_browser_synthetic_0001" });
      return deviceSuccess(request, {
        authorization: "user",
        chain: "sui",
        method: "sign_transaction",
        signature: SUI_SIGNATURE,
      });
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    const result = await provider.signTransaction({
      chain: "sui",
      method: "sign_transaction",
      network: "mainnet",
      txBytes: payload.toString("base64"),
    });
    assert.equal(result.source, "live");
    assert.equal(result.status, "signed");
    const requestTypes = port.requests.map((request) => requestKind(request));
    assert.equal(requestTypes[0], "connect");
    assert.equal(requestTypes[1], "payload_transfer");
    assert.equal(port.requests[1].action, "begin");
    assert.equal(requestTypes.at(-2), "payload_transfer");
    assert.equal(port.requests.at(-2).action, "finish");
    assert.equal(requestTypes.at(-1), "sign_transaction");
    assert.equal(
      port.requests.filter((request) => requestKind(request) === "payload_transfer" && request.action === "chunk").length,
      Math.ceil(transferredPayload.length / chunkMaxBytes),
    );
    assert.deepEqual(Buffer.concat(chunks), transferredPayload);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider aborts active payload transfer after progress mismatch", async () => {
  const payload = Buffer.alloc(8 * 1024, 0x52);
  const chunkMaxBytes = payload.length;
  let abortRequest = null;
  const port = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "payload_transfer" && request.action === "begin") {
      return {
        id: request.id,
        version: 1,
        success: true,
        result: {
          transferId: "transfer_browser_progress_mismatch",
          receivedBytes: "0",
          chunkMaxBytes: String(chunkMaxBytes),
        },
      };
    }
    if (requestKind(request) === "payload_transfer" && request.action === "chunk") {
      return {
        id: request.id,
        version: 1,
        success: true,
        result: { receivedBytes: "1" },
      };
    }
    if (requestKind(request) === "payload_transfer" && request.action === "abort") {
      abortRequest = request;
      return {
        id: request.id,
        version: 1,
        success: true,
        result: {},
      };
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    await assert.rejects(
      () => provider.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: "mainnet",
        txBytes: payload.toString("base64"),
      }),
      (error) => error.code === "invalid_response",
    );
    assert.equal(abortRequest.transferId, "transfer_browser_progress_mismatch");
    assert.equal("payloadRef" in abortRequest, false);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider preserves transfer failure and clears session when abort reports invalid_session", async () => {
  const payload = Buffer.alloc(8 * 1024, 0x53);
  const chunkMaxBytes = payload.length;
  const port = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "payload_transfer" && request.action === "begin") {
      return {
        id: request.id,
        version: 1,
        success: true,
        result: {
          transferId: "transfer_browser_abort_invalid_session",
          receivedBytes: "0",
          chunkMaxBytes: String(chunkMaxBytes),
        },
      };
    }
    if (requestKind(request) === "payload_transfer" && request.action === "chunk") {
      return {
        id: request.id,
        version: 1,
        success: true,
        result: { receivedBytes: "1" },
      };
    }
    if (requestKind(request) === "payload_transfer" && request.action === "abort") {
      return payloadTransferFailure(request, "invalid_session");
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    await assert.rejects(
      () => provider.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: "mainnet",
        txBytes: payload.toString("base64"),
      }),
      (error) => error.code === "invalid_response",
    );
    const abortRequest = port.requests.find((request) => requestKind(request) === "payload_transfer" && request.action === "abort");
    assert.equal(abortRequest.transferId, "transfer_browser_abort_invalid_session");
    assert.equal((await provider.getAccounts()).source, "not_connected");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider rejects payloads above the common transfer max before upload", async () => {
  const payload = Buffer.alloc(100 * 1024, 0x47);
  const port = new FakeBrowserSerialPort((request) => {
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    await assert.rejects(
      () => provider.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: "mainnet",
        txBytes: payload.toString("base64"),
      }),
      (error) => error.code === "payload_too_large",
    );
    assert.equal(
      port.requests.some((request) => requestKind(request) === "payload_transfer" && request.action === "begin"),
      false,
      "payload over common transfer max must fail before transfer begins",
    );
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
    if (requestKind(request) === "connect") {
      const response = createFakeBrowserDeviceResponse(request);
      return {
        ...response,
        result: {
          ...response.result,
          device: {
            ...response.result.device,
            deviceId: "other-device",
          },
        },
      };
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const matchedPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
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
    const provider = createSuiBrowserDeviceProvider();
    await assert.rejects(
      () => provider.connectDevice({ deviceId: "device-1" }),
      { code: "device_mismatch" },
    );
    assert.equal(requestPortCalls, 1);
    assert.deepEqual(mismatchedPort.requests.map((request) => requestKind(request)), ["connect", "disconnect"]);
    assert.equal(mismatchedPort.requests[1].sessionId, "session_abcdef0123456789");
    assert.deepEqual(await provider.getCapabilities({ deviceId: "device-1" }), {
      source: "not_connected",
      deviceId: "device-1",
      reason: "not_connected",
    });
    const connected = await provider.connectDevice({ deviceId: "device-1" });
    assert.equal(requestPortCalls, 2);
    assert.equal(connected.source, "connected");
    assert.deepEqual(matchedPort.requests.map((request) => requestKind(request)), ["connect"]);
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

async function waitForRecordedRequest(port, type, attempts = 50) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const request = port.requests.find((candidate) => (requestKind(candidate) ?? candidate.method) === type);
    if (request !== undefined) {
      return request;
    }
    await Promise.resolve();
  }
  return undefined;
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
  const port = new SerializationProbePort(createFakeBrowserDeviceResponse, { responseDelayMs: 5 });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
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
  const port = new SerializationProbePort(createFakeBrowserDeviceResponse, {
    beforeRespond: async (request) => {
      if (requestKind(request) !== "connect" && !heldOne) {
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
    const provider = createSuiBrowserDeviceProvider();
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
    if (requestKind(request) === "get_capabilities") {
      capabilityCalls += 1;
      if (capabilityCalls === 1) {
        return deviceFailure(request, "unknown_error");
      }
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    // A failing request must not wedge the queue: the following request still runs.
    const [failed, recovered] = await Promise.allSettled([
      provider.getCapabilities(),
      provider.getCapabilities(),
    ]);
    assert.equal(failed.status, "rejected");
    assert.equal(failed.reason.code, "unknown_error");
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

test("browser provider recovers a buffered signing response when the signing response is lost", async () => {
  const port = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "sign_transaction") {
      // The device signed and buffered the result, but the response is lost in transit.
      return null;
    }
    if (requestKind(request) === "get_result") {
      // The device returns the buffered signature for the original request id.
      return browserSignedTransactionResult(request);
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const result = await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.equal(result.source, "live", "the buffered result is recovered, not surfaced as an error");
    const signReq = port.requests.find((r) => requestKind(r) === "sign_transaction");
    const getResultReq = port.requests.find((r) => requestKind(r) === "get_result");
    assert.ok(getResultReq, "provider must issue a get_result after a lost signing response");
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
  test(`browser provider acks a buffered ${status} sign_transaction failure when the signing response is lost`, async () => {
    const port = new FakeBrowserSerialPort((request) => {
      if (requestKind(request) === "sign_transaction") {
        return null;
      }
      if (requestKind(request) === "get_result") {
        return browserTerminalSigningOutcome(request, status);
      }
      if (requestKind(request) === "ack_result") {
        return browserAckResult(request);
      }
      return createFakeBrowserDeviceResponse(request);
    });
    const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    try {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: { serial: { requestPort: async () => port } },
      });
      const provider = createSuiBrowserDeviceProvider();
      assert.equal((await provider.connectDevice()).source, "connected");

      const expectedError = makeDeviceError(terminalStatusDeviceErrorCode(status));
      await assert.rejects(
        () => provider.signTransaction({
          chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
        }),
        { code: expectedError.code, message: expectedError.message },
      );
      const signReq = port.requests.find((r) => requestKind(r) === "sign_transaction");
      const getResultReq = port.requests.find((r) => requestKind(r) === "get_result");
      const ackReq = port.requests.find((r) => requestKind(r) === "ack_result");
      assert.ok(getResultReq, "provider must issue get_result after a lost signing response");
      assert.equal(getResultReq.id, signReq.id, "get_result must target the original request id");
      assert.ok(ackReq, "provider must send ack_result after recovering terminal failure");
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

for (const status of ["user_rejected", "user_timed_out", "signing_failed"]) {
  test(`browser provider acks a buffered ${status} sign_personal_message failure when the signing response is lost`, async () => {
    const port = new FakeBrowserSerialPort((request) => {
      if (requestKind(request) === "sign_personal_message") {
        return null;
      }
      if (requestKind(request) === "get_result") {
        return browserTerminalSigningOutcome(request, status);
      }
      if (requestKind(request) === "ack_result") {
        return browserAckResult(request);
      }
      return createFakeBrowserDeviceResponse(request);
    });
    const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    try {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: { serial: { requestPort: async () => port } },
      });
      const provider = createSuiBrowserDeviceProvider();
      assert.equal((await provider.connectDevice()).source, "connected");

      const expectedError = makeDeviceError(terminalStatusDeviceErrorCode(status));
      await assert.rejects(
        () => provider.signPersonalMessage({
          chain: "sui", method: "sign_personal_message", network: "mainnet", message: PERSONAL_MESSAGE_BYTES,
        }),
        { code: expectedError.code, message: expectedError.message },
      );
      const signReq = port.requests.find((r) => requestKind(r) === "sign_personal_message");
      const getResultReq = port.requests.find((r) => requestKind(r) === "get_result");
      const ackReq = port.requests.find((r) => requestKind(r) === "ack_result");
      assert.ok(getResultReq, "provider must issue get_result after a lost signing response");
      assert.equal(getResultReq.id, signReq.id, "get_result must target the original request id");
      assert.ok(ackReq, "provider must send ack_result after recovering terminal failure");
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
    if (requestKind(request) === "sign_transaction") {
      return browserSignErrorResult(request, "invalid_params");
    }
    if (requestKind(request) === "get_result") {
      // The device never signed, so there is nothing buffered to recover.
      return deviceFailure(request, "unknown_request", "get_result");
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    await assert.rejects(
      () => provider.signTransaction({ chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID" }),
      (error) => error.code === "invalid_params",
      "the original sign error must surface without recovery",
    );
    assert.equal(
      port.requests.some((request) => requestKind(request) === "get_result"),
      false,
      "deterministic Firmware errors must not issue get_result recovery",
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
  const port = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const stableId = `req_${"ab".repeat(12)}`;
    await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID", requestId: stableId,
    });
    const signReq = port.requests.find((r) => requestKind(r) === "sign_transaction");
    assert.equal(signReq.id, stableId, "the provider must use the caller-provided requestId");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("provider protocol parser keeps retained recovery response exact", () => {
  assert.throws(() =>
    parseDeviceResponse({ id: "req_ack_1", version: 1, success: true, result: {} }, { expectedId: "req_ack_1" }),
  );
  const valid = parseDeviceResponse(browserAckResult({ id: "req_ack_1", method: "ack_result" }), {
    expectedId: "req_ack_1",
    expectedMethod: "ack_result",
  });
  assert.equal(valid.success, true);
  assert.equal(valid.method, "ack_result");
  assert.deepEqual(valid.result, {});
  // The DeviceResponse parser fails closed on missing method identity and on
  // any extra top-level field.
  assert.throws(() =>
    parseDeviceResponse({ ...browserAckResult({ id: "req_ack_1", method: "ack_result" }), unexpected: "field" }, { expectedId: "req_ack_1" }),
  );
  assert.throws(() =>
    parseDeviceResponse({ ...browserAckResult({ id: "req_ack_1", method: "ack_result" }), signature: "x" }, { expectedId: "req_ack_1" }),
  );
});

test("browser provider releases a recovered result with ack_result", async () => {
  let ackReceived = false;
  const port = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "sign_transaction") {
      return null;
    }
    if (requestKind(request) === "get_result") {
      return browserSignedTransactionResult(request);
    }
    if (requestKind(request) === "ack_result") {
      ackReceived = true;
      return browserAckResult(request);
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    const result = await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.equal(result.source, "live");
    const signReq = port.requests.find((r) => requestKind(r) === "sign_transaction");
    const getReq = port.requests.find((r) => requestKind(r) === "get_result");
    const ackReq = port.requests.find((r) => requestKind(r) === "ack_result");
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
    if (requestKind(request) === "sign_transaction") {
      return null;
    }
    if (requestKind(request) === "get_result") {
      return browserSignedTransactionResult(request);
    }
    if (requestKind(request) === "ack_result") {
      return deviceFailure(request, "unknown_error", "ack_result");
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    const result = await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.equal(result.source, "live", "a failed ack must not turn a successful buffered-result fetch into a failure");
    assert.ok(port.requests.find((r) => requestKind(r) === "ack_result"), "the recovery attempted the ack");
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider returns session_ended when get_result reports invalid_session", async () => {
  const port = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "sign_transaction") {
      return null;
    }
    if (requestKind(request) === "get_result") {
      return deviceFailure(request, "invalid_session", "get_result");
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    const result = await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.deepEqual(result, {
      source: "session_ended",
      deviceId: "device-1",
      reason: "invalid_session",
    });
    assert.deepEqual(await provider.getCapabilities(), {
      source: "not_connected",
      deviceId: "browser",
      reason: "not_connected",
    });
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider returns recovered result and clears the session when ack_result reports invalid_session", async () => {
  const port = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "sign_transaction") {
      return null;
    }
    if (requestKind(request) === "get_result") {
      return browserSignedTransactionResult(request);
    }
    if (requestKind(request) === "ack_result") {
      return deviceFailure(request, "invalid_session", "ack_result");
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    const result = await provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.equal(result.source, "live");
    assert.equal(result.status, "signed");
    assert.deepEqual(await provider.getCapabilities(), {
      source: "not_connected",
      deviceId: "browser",
      reason: "not_connected",
    });
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider keeps signing recovery as one queued transaction", async () => {
  const port = new SerializationProbePort((request) => {
    if (requestKind(request) === "sign_transaction") {
      return null;
    }
    if (requestKind(request) === "get_result") {
      return browserSignedTransactionResult(request);
    }
    if (requestKind(request) === "ack_result") {
      return browserAckResult(request);
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const [signed, capabilities] = await Promise.all([
      provider.signTransaction({
        chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
      }),
      provider.getCapabilities(),
    ]);

    assert.equal(signed.source, "live");
    assert.equal(capabilities.source, "live");
    assert.deepEqual(
      port.requests.map((request) => requestKind(request)).filter((type) => type !== "connect"),
      ["sign_transaction", "get_result", "ack_result", "get_capabilities"],
      "queued provider requests must not interleave with sign/get/ack recovery",
    );
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider does not resolve recovered signing outcome before ack_result settles", async () => {
  let releaseAck;
  let signResolved = false;
  const port = new SerializationProbePort(
    (request) => {
      if (requestKind(request) === "sign_transaction") {
        return null;
      }
      if (requestKind(request) === "get_result") {
        return browserSignedTransactionResult(request);
      }
      if (requestKind(request) === "ack_result") {
        return browserAckResult(request);
      }
      return createFakeBrowserDeviceResponse(request);
    },
    {
      beforeRespond: async (request) => {
        if (requestKind(request) === "ack_result") {
          await new Promise((resolve) => {
            releaseAck = resolve;
          });
        }
      },
    },
  );
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const signPromise = provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    }).then((result) => {
      signResolved = true;
      return result;
    });

    for (let attempts = 0; attempts < 20 && releaseAck === undefined; attempts += 1) {
      await waitMs(1);
    }
    assert.equal(releaseAck !== undefined, true, "ack_result should be in flight");
    assert.equal(signResolved, false, "recovered result must wait for ack_result ordering");
    releaseAck();
    const result = await signPromise;
    assert.equal(result.source, "live");
    assert.equal(signResolved, true);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider abandons a stale port when writer.write hangs and recovers on a fresh port", async () => {
  const firstPort = new SerializationProbePort(
    createFakeBrowserDeviceResponse,
    {
      beforeRespond: async (request) => {
        if (requestKind(request) === "sign_transaction") {
          await new Promise(() => {});
        }
      },
    },
  );
  const recoveryPort = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "get_result") {
      return browserSignedTransactionResult(request);
    }
    if (requestKind(request) === "ack_result") {
      return browserAckResult(request);
    }
    return createFakeBrowserDeviceResponse(request);
  });
  let requestPortCalls = 0;
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            return requestPortCalls === 1 ? firstPort : recoveryPort;
          },
        },
      },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const signPromise = provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.ok(
      await waitForRecordedRequest(firstPort, "sign_transaction"),
      "the stale port must receive the original sign write",
    );

    mock.timers.runAll();
    await Promise.resolve();
    mock.timers.runAll();
    await Promise.resolve();
    const result = await signPromise;
    assert.equal(result.source, "live");
    assert.equal(requestPortCalls, 2, "recovery must acquire a fresh port after abandoning the stale one");
    assert.deepEqual(
      recoveryPort.requests.map((request) => requestKind(request)),
      ["get_result", "ack_result"],
      "fresh recovery port must carry retained response read and cleanup only",
    );
  } finally {
    mock.timers.reset();
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider does not reuse the same stale port object for recovery", async () => {
  class HangingCloseProbePort extends SerializationProbePort {
    async close() {
      this.closeCount += 1;
      await new Promise(() => {});
    }
  }
  const port = new HangingCloseProbePort(
    createFakeBrowserDeviceResponse,
    {
      beforeRespond: async (request) => {
        if (requestKind(request) === "sign_transaction") {
          await new Promise(() => {});
        }
      },
    },
  );
  let requestPortCalls = 0;
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
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
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const signPromise = provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.ok(
      await waitForRecordedRequest(port, "sign_transaction"),
      "the stale port must receive the original sign write",
    );

    const rejection = assert.rejects(signPromise, { code: "timeout" });
    for (let attempts = 0; attempts < 12; attempts += 1) {
      mock.timers.runAll();
      await Promise.resolve();
    }
    await rejection;
    assert.equal(requestPortCalls, 2, "recovery may prompt again but must gate the same stale port object");
    assert.deepEqual(
      port.requests.map((request) => requestKind(request)),
      ["connect", "sign_transaction"],
      "same stale port object must not carry retained response read or cleanup",
    );
  } finally {
    mock.timers.reset();
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider attempts retained recovery after post-write disconnect", async () => {
  const listeners = new Map();
  let requestPortCalls = 0;
  const firstPort = new SerializationProbePort(
    createFakeBrowserDeviceResponse,
    {
      beforeRespond: async (request) => {
        if (requestKind(request) === "sign_transaction") {
          listeners.get("disconnect")?.({ target: firstPort });
          await new Promise(() => {});
        }
      },
    },
  );
  const recoveryPort = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "get_result") {
      return browserSignedTransactionResult(request);
    }
    if (requestKind(request) === "ack_result") {
      return browserAckResult(request);
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            return requestPortCalls === 1 ? firstPort : recoveryPort;
          },
          addEventListener: (type, listener) => {
            listeners.set(type, listener);
          },
          removeEventListener: (type) => {
            listeners.delete(type);
          },
        },
      },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const resultPromise = provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.ok(await waitForRecordedRequest(firstPort, "sign_transaction"));
    mock.timers.runAll();
    await Promise.resolve();
    mock.timers.runAll();
    await Promise.resolve();

    const result = await resultPromise;
    assert.equal(result.source, "live");
    assert.equal(result.status, "signed");
    assert.deepEqual(
      recoveryPort.requests.map((request) => requestKind(request)),
      ["get_result", "ack_result"],
      "post-write physical disconnect must not suppress retained-response recovery",
    );
    const capabilities = await provider.getCapabilities();
    assert.equal(capabilities.source, "live", "recovered physical-disconnect session must remain usable");
    assert.deepEqual(
      recoveryPort.requests.map((request) => requestKind(request)),
      ["get_result", "ack_result", "get_capabilities"],
    );
  } finally {
    mock.timers.reset();
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider stale queued request cannot clear a recovered physical-disconnect session", async () => {
  const listeners = new Map();
  let requestPortCalls = 0;
  const firstPort = new SerializationProbePort(
    createFakeBrowserDeviceResponse,
    {
      beforeRespond: async (request) => {
        if (requestKind(request) === "sign_transaction") {
          listeners.get("disconnect")?.({ target: firstPort });
          await new Promise(() => {});
        }
      },
    },
  );
  const recoveryPort = new FakeBrowserSerialPort((request) => {
    if (requestKind(request) === "get_result") {
      return browserSignedTransactionResult(request);
    }
    if (requestKind(request) === "ack_result") {
      return browserAckResult(request);
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            return requestPortCalls === 1 ? firstPort : recoveryPort;
          },
          addEventListener: (type, listener) => {
            listeners.set(type, listener);
          },
          removeEventListener: (type) => {
            listeners.delete(type);
          },
        },
      },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const signPromise = provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    const staleCapabilitiesPromise = provider.getCapabilities();
    assert.ok(await waitForRecordedRequest(firstPort, "sign_transaction"));
    mock.timers.runAll();
    await Promise.resolve();
    mock.timers.runAll();
    await Promise.resolve();

    const result = await signPromise;
    assert.equal(result.source, "live");
    assert.equal(result.status, "signed");

    const staleCapabilities = await staleCapabilitiesPromise;
    assert.equal(staleCapabilities.source, "session_ended");
    assert.equal(staleCapabilities.reason, "transport_closed");

    const freshCapabilities = await provider.getCapabilities();
    assert.equal(
      freshCapabilities.source,
      "live",
      "old-generation queued requests must not clear a session restored by retained recovery",
    );
    assert.deepEqual(
      recoveryPort.requests.map((request) => requestKind(request)),
      ["get_result", "ack_result", "get_capabilities"],
    );
  } finally {
    mock.timers.reset();
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider does not recover signing after dispose tears down the transport", async () => {
  let requestPortCalls = 0;
  const firstPort = new SerializationProbePort(
    createFakeBrowserDeviceResponse,
    {
      beforeRespond: async (request) => {
        if (requestKind(request) === "sign_transaction") {
          await new Promise(() => {});
        }
      },
    },
  );
  const recoveryPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            return requestPortCalls === 1 ? firstPort : recoveryPort;
          },
          addEventListener: () => {},
          removeEventListener: () => {},
        },
      },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");

    const signPromise = provider.signTransaction({
      chain: "sui", method: "sign_transaction", network: "mainnet", txBytes: "AQID",
    });
    assert.ok(await waitForRecordedRequest(firstPort, "sign_transaction"));
    provider.dispose();
    mock.timers.runAll();
    await Promise.resolve();
    mock.timers.runAll();

    await assert.rejects(
      signPromise,
      (error) => error.code === "timeout" || error.code === "transport_closed",
    );
    assert.equal(requestPortCalls, 1, "dispose must not re-prompt for retained-response recovery");
    assert.equal(recoveryPort.requests.length, 0);
  } finally {
    mock.timers.reset();
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("browser provider invalidates a queued request when disconnectDevice tears down the transport", async () => {
  const port = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
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
      !port.requests.some((r) => requestKind(r) === "get_capabilities"),
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
  const port = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serial: { requestPort: async () => port } },
    });
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    // A subsequent connect for a different deviceId mismatches (the device reports device-1).
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
    if (requestKind(request) === "get_capabilities") {
      return deviceFailure(request, "invalid_session", "get_capabilities");
    }
    return createFakeBrowserDeviceResponse(request);
  });
  const freshPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
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
    const provider = createSuiBrowserDeviceProvider();
    assert.equal((await provider.connectDevice()).source, "connected");
    assert.deepEqual(await provider.getCapabilities(), {
      source: "session_ended",
      deviceId: "device-1",
      reason: "invalid_session",
    });
    assert.deepEqual(staleSessionPort.requests.map((request) => requestKind(request)), ["connect", "get_capabilities"]);

    const reconnected = await provider.connectDevice();
    assert.equal(requestPortCalls, 2);
    assert.equal(reconnected.source, "connected");
    assert.deepEqual(freshPort.requests.map((request) => requestKind(request)), ["connect"]);
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
  const closedPort = new FakeBrowserSerialPort((request) => requestKind(request) === "connect" ? null : createFakeBrowserDeviceResponse(request));
  const freshPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
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
    const provider = createSuiBrowserDeviceProvider();
    await assert.rejects(
      () => provider.connectDevice(),
      { code: "transport_closed" },
    );
    assert.deepEqual(closedPort.requests.map((request) => requestKind(request)), ["connect"]);

    const connected = await provider.connectDevice();
    assert.equal(requestPortCalls, 2);
    assert.equal(connected.source, "connected");
    assert.deepEqual(freshPort.requests.map((request) => requestKind(request)), ["connect"]);
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
    const provider = createSuiBrowserDeviceProvider();
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

test("browser provider maps Web Serial chooser failure to transport_error", async () => {
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  let requestPortCalls = 0;
  try {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serial: {
          requestPort: async () => {
            requestPortCalls += 1;
            throw new Error("chooser rejected");
          },
        },
      },
    });
    const provider = createSuiBrowserDeviceProvider();
    await assert.rejects(
      () => provider.connectDevice({ deviceId: "device-1" }),
      { code: "transport_error" },
    );
    assert.equal(requestPortCalls, 1);
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
    const provider = createSuiBrowserDeviceProvider();
    await assert.rejects(
      () => provider.connectDevice(),
      { code: "invalid_response" },
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
  const port = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
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
    const provider = createSuiBrowserDeviceProvider();
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
  const firstPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
  const secondPort = new FakeBrowserSerialPort(createFakeBrowserDeviceResponse);
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
    const provider = createSuiBrowserDeviceProvider();
    assert.equal(typeof disconnectHandler, "function");
    assert.equal((await provider.connectDevice()).source, "connected");
    assert.equal(requestPortCalls, 1);

    // Simulate a physical disconnect / Firmware reboot re-enumeration.
    disconnectHandler({ target: firstPort });

    // The next connect must re-request the port (browser menu reappears),
    // not silently reuse the dead cached port.
    assert.equal((await provider.connectDevice()).source, "connected");
    assert.equal(requestPortCalls, 2);
    assert.deepEqual(secondPort.requests.map((request) => requestKind(request)), ["connect"]);
  } finally {
    if (previousNavigator === undefined) {
      delete globalThis.navigator;
    } else {
      Object.defineProperty(globalThis, "navigator", previousNavigator);
    }
  }
});

test("provider object presents the Sui dapp-facing adapter API including signing methods", () => {
  const provider = createSuiDeviceProvider({ core: createFakeCore() });
  const methodNames = Object.getOwnPropertyNames(Object.getPrototypeOf(provider))
    .filter((name) => name !== "constructor")
    .sort();
  assert.equal(provider instanceof SuiDeviceProvider, true);
  assert.deepEqual(methodNames, [
    "connectDevice",
    "credentialPrepare",
    "credentialPropose",
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
  assert.equal(typeof provider.credentialPrepare, "function");
  assert.equal(typeof provider.credentialPropose, "function");
  assert.equal(typeof provider.signTransaction, "function");
  assert.equal(typeof provider.signPersonalMessage, "function");
  assert.equal(provider.signByUser, undefined);
  assert.equal(provider.signByPolicy, undefined);
  assert.equal(provider.policyPropose, undefined);
  assert.equal(provider.policyGet, undefined);
  assert.equal(provider.getApprovalHistory, undefined);
  assert.equal(provider.clearZkLoginProof, undefined);
  assert.equal(provider.signZkLoginTransaction, undefined);
});

test("provider delegates current methods and signing methods without exposing session ids or secrets", async () => {
  const provider = createSuiDeviceProvider({ core: createFakeCore() });
  const outputs = [
    await provider.scanDevices(),
    await provider.identifyDevices(),
    await provider.selectDevice({ deviceId: "device-1" }),
    await provider.listDevices(),
    await provider.connectDevice({ deviceId: "device-1" }),
    await provider.disconnectDevice({ deviceId: "device-1" }),
    await provider.getCapabilities({ deviceId: "device-1" }),
    await provider.getAccounts({ deviceId: "device-1" }),
    await provider.credentialPrepare(validCredentialPrepareInput()),
    await provider.credentialPropose(validCredentialProposeInput()),
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

test("provider credential methods delegate through Core and expose no signer selection", async () => {
  const calls = [];
  const core = {
    ...createFakeCore(),
    async credentialPrepare(input) {
      calls.push(["credentialPrepare", input]);
      return {
        source: "live",
        deviceId: "device-1",
        chain: "sui",
        credential: "zklogin",
        preparation: {
          address: SUI_ADDRESS,
          publicKey: SUI_PUBLIC_KEY,
          keyScheme: "ed25519",
        },
      };
    },
    async credentialPropose(input) {
      calls.push(["credentialPropose", input]);
      return {
        source: "live",
        deviceId: "device-1",
        status: "activated",
        reasonCode: "activated",
        sessionEnded: true,
      };
    },
  };
  const provider = createSuiDeviceProvider({ core });

  const prepareInput = validCredentialPrepareInput({ purpose: "test-web" });
  const proposeInput = validCredentialProposeInput({ purpose: "test-web" });
  const prepare = await provider.credentialPrepare(prepareInput);
  const propose = await provider.credentialPropose(proposeInput);

  assert.equal(prepare.source, "live");
  assert.equal(prepare.chain, "sui");
  assert.equal(prepare.credential, "zklogin");
  assert.equal(prepare.preparation.keyScheme, "ed25519");
  assert.equal(propose.source, "live");
  assert.equal(propose.status, "activated");
  assert.equal(propose.sessionEnded, true);
  assert.deepEqual(calls, [
    ["credentialPrepare", prepareInput],
    ["credentialPropose", proposeInput],
  ]);
  assert.equal(Object.hasOwn(prepareInput, "deadlineMs"), false);
  assert.equal(Object.hasOwn(proposeInput, "deadlineMs"), false);
  assert.equal(Object.hasOwn(proposeInput, "signerKind"), false);
  assertNoSecretFields(prepare);
  assertNoSecretFields(propose);
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
  const provider = createSuiDeviceProvider({ core });
  await assert.rejects(
    () => provider.getCapabilities({ deviceId: "device-1" }),
  );
});

test("provider getCapabilities preserves credential capability metadata and rejects malformed entries", async () => {
  {
    const core = {
      ...createFakeCore(),
      async getCapabilities() {
        return {
          ...(await createFakeCore().getCapabilities()),
          credentials: [validCredentialCapability()],
        };
      },
    };
    const provider = createSuiDeviceProvider({ core });
    const capabilities = await provider.getCapabilities({ deviceId: "device-1" });
    assert.deepEqual(capabilities.credentials, [validCredentialCapability()]);
    assertNoSecretFields(capabilities);
  }

  {
    const core = {
      ...createFakeCore(),
      async getCapabilities() {
        return {
          ...(await createFakeCore().getCapabilities()),
          credentials: [
            {
              ...validCredentialCapability(),
              operations: ["credential_propose", "credential_prepare"],
            },
          ],
        };
      },
    };
    const provider = createSuiDeviceProvider({ core });
    await assert.rejects(() => provider.getCapabilities({ deviceId: "device-1" }));
  }

  {
    const core = {
      ...createFakeCore(),
      async getCapabilities() {
        return {
          ...(await createFakeCore().getCapabilities()),
          credentials: [{ ...validCredentialCapability(), jwt: "must_not_leak" }],
        };
      },
    };
    const provider = createSuiDeviceProvider({ core });
    await assert.rejects(
      () => provider.getCapabilities({ deviceId: "device-1" }),
      /forbidden output field/,
    );
  }
});

test("provider-facing credential result schemas accept bounded outputs and reject secrets", () => {
  const prepare = {
    source: "live",
    deviceId: "device-1",
    chain: "sui",
    credential: "zklogin",
    preparation: {
      address: SUI_ADDRESS,
      publicKey: SUI_PUBLIC_KEY,
      keyScheme: "ed25519",
    },
  };
  const propose = {
    source: "live",
    deviceId: "device-1",
    status: "activated",
    reasonCode: "activated",
    sessionEnded: true,
  };

  assert.deepEqual(credentialPrepareSuccessOutputShape.parse(prepare), prepare);
  assert.deepEqual(credentialProposeSuccessOutputShape.parse(propose), propose);
  assert.throws(() => credentialPrepareSuccessOutputShape.parse({
    ...prepare,
    preparation: { ...prepare.preparation, jwt: "must_not_leak" },
  }));
  assert.throws(() => credentialPrepareSuccessOutputShape.parse({
    ...prepare,
    preparation: { ...prepare.preparation, address: ZKLOGIN_ADDRESS },
  }));
  assert.throws(() => credentialProposeSuccessOutputShape.parse({
    ...propose,
    salt: "must_not_leak",
  }));
  assert.throws(() => credentialProposeSuccessOutputShape.parse({
    ...propose,
    status: "pending",
  }));
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
    ["credentialPrepare", (provider) => provider.credentialPrepare(validCredentialPrepareInput())],
    ["credentialPropose", (provider) => provider.credentialPropose(validCredentialProposeInput())],
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
    const provider = createSuiDeviceProvider({ core });
    await assert.rejects(
      () => callProvider(provider),
      /forbidden output field/,
      `${methodName} must reject forbidden custom-core output fields`,
    );
  }
});

test("provider output boundary rejects malformed signing and account projections", async () => {
  {
    const provider = createSuiDeviceProvider({
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
    const provider = createSuiDeviceProvider({
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
    const provider = createSuiDeviceProvider({
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
  const provider = createSuiDeviceProvider({ core });
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
  const provider = createSuiDeviceProvider({ core: createFakeCore() });
  assert.equal(provider.signByUser, undefined);
  assert.equal(provider.signByPolicy, undefined);
  assert.equal(provider.policyPropose, undefined);
  assert.equal(provider.policyGet, undefined);
  assert.equal(provider.getApprovalHistory, undefined);
  assert.equal(provider.clearZkLoginProof, undefined);
  assert.equal(provider.signZkLoginTransaction, undefined);
  assert.equal(provider.signerKind, undefined);
  assert.equal(typeof provider.credentialPrepare, "function");
  assert.equal(typeof provider.credentialPropose, "function");
  assert.equal(typeof provider.signTransaction, "function");
  assert.equal(typeof provider.signPersonalMessage, "function");
});

test("Wallet Standard adapter advertises only current Agent-Q Sui signing features", () => {
  const { core } = createDeviceCore();
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  assert.equal(wallet instanceof SuiDeviceWallet, true);
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
  assert.equal(wallet.features["signing:credentialPrepare"], undefined);
  assert.equal(wallet.features["signing:credentialPropose"], undefined);
  assert.equal(wallet.features["signing:clearZkLoginProof"], undefined);
  assert.equal(wallet.credentialPrepare, undefined);
  assert.equal(wallet.credentialPropose, undefined);
  assert.equal(wallet.clearZkLoginProof, undefined);
  assert.equal(wallet.signerKind, undefined);
  assert.equal(wallet.features["sui:signMessage"], undefined);
  assert.equal(wallet.features["sui:signAndExecuteTransaction"], undefined);
  assert.equal(wallet.features["sui:signTransactionBlock"], undefined);
});

test("Wallet Standard adapter rejects malformed chain and initializer network inputs", () => {
  const { core } = createDeviceCore();
  const provider = createSuiDeviceProvider({ core });
  assert.throws(
    () => createSuiDeviceWallet({
      provider,
      getClient: fakeClient,
      chains: ["evm:mainnet"],
    }),
    /unsupported chain/,
  );
  assert.throws(
    () => createSuiDeviceWallet({
      provider,
      getClient: fakeClient,
      chains: [],
    }),
    /requires at least one Sui chain/,
  );
  const initializer = createSuiDeviceWalletInitializer({ provider });
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
  const { core } = createDeviceCore();
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
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
  assert.equal(Object.prototype.hasOwnProperty.call(connected.accounts[0], "sponsoredTransactions"), false);
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

test("Wallet Standard connect projects a zkLogin active account", async () => {
  const core = {
    ...createFakeCore(),
    async getCapabilities() {
      return {
        source: "live",
        deviceId: "device-1",
        capabilities: [
          {
            id: "sui",
            accounts: [{ keyScheme: "zklogin" }],
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
    async getAccounts() {
      return {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            chain: "sui",
            address: ZKLOGIN_ADDRESS,
            publicKey: ZKLOGIN_PUBLIC_KEY,
            keyScheme: "zklogin",
            sponsoredTransactions: {
              acceptGasSponsor: true,
            },
          },
        ],
      };
    },
  };
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  const connected = await wallet.features[StandardConnect].connect();
  assert.equal(connected.accounts.length, 1);
  assert.equal(connected.accounts[0].address, ZKLOGIN_ADDRESS);
  assert.equal(Buffer.from(connected.accounts[0].publicKey).toString("base64"), ZKLOGIN_PUBLIC_KEY);
  assert.deepEqual(connected.accounts[0].features, [SuiSignTransaction]);
  assert.equal(Object.prototype.hasOwnProperty.call(connected.accounts[0], "sponsoredTransactions"), false);
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
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
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
    {
      output: {
        ...validCapabilitiesResult(),
        credentials: [validCredentialCapability()],
      },
      expectedFeatures: [SuiSignTransaction, SuiSignPersonalMessage],
      label: "credential metadata stays outside Wallet Standard features",
    },
  ];
  for (const { output, expectedFeatures, label } of cases) {
    const wallet = createSuiDeviceWallet({
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
    assert.deepEqual(Object.keys(wallet.features).sort(), [
      "standard:connect",
      "standard:disconnect",
      "standard:events",
      "sui:signPersonalMessage",
      "sui:signTransaction",
    ], label);
    assert.deepEqual(connected.accounts[0].features, expectedFeatures, label);
    assert.equal(connected.accounts[0].features.includes("credential_prepare"), false, label);
    assert.equal(connected.accounts[0].features.includes("credential_propose"), false, label);
    assert.equal(connected.accounts[0].features.includes("clear_zklogin_proof"), false, label);
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
    {
      output: mutate((output) => {
        output.signing.methods[0].payload = { kind: "transaction" };
      }),
      label: "signing method entry must not carry payload delivery metadata",
    },
    {
      output: mutate((output) => {
        output.signing.methods[1].payload = { kind: "transaction" };
      }),
      label: "personal-message signing must not carry payload delivery metadata",
    },
  ];
  for (const { output, label } of cases) {
    let disconnectCalls = 0;
    const wallet = createSuiDeviceWallet({
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
  const wallet = createSuiDeviceWallet({
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
      label: "sponsoredTransactions malformed",
      output: {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            ...validAccount,
            sponsoredTransactions: {
              acceptGasSponsor: "true",
            },
          },
        ],
      },
    },
    {
      label: "sponsoredTransactions extra field",
      output: {
        source: "live",
        deviceId: "device-1",
        accounts: [
          {
            ...validAccount,
            sponsoredTransactions: {
              acceptGasSponsor: false,
              mode: "extra",
            },
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
    const wallet = createSuiDeviceWallet({
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
  const { core, calls } = createDeviceCore();
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
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

test("Wallet Standard signTransaction accepts zkLogin transaction signatures", async () => {
  const { core } = createDeviceCore();
  core.signTransaction = async () => ({
    ...validSignedTransactionResult(),
    signature: ZKLOGIN_SIGNATURE,
  });
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  const { accounts } = await wallet.features[StandardConnect].connect();
  const transactionJson = await createResolvedTransactionJson();
  const signed = await wallet.features[SuiSignTransaction].signTransaction({
    account: accounts[0],
    chain: "sui:devnet",
    transaction: { toJSON: async () => transactionJson },
  });
  assert.equal(signed.signature, ZKLOGIN_SIGNATURE);
  assertNoSecretFields(signed);
});

test("Wallet Standard signPersonalMessage delegates to signPersonalMessage only", async () => {
  const { core, calls } = createDeviceCore();
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
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

test("Wallet Standard signPersonalMessage accepts zkLogin personal-message signatures", async () => {
  const { core } = createDeviceCore();
  core.signPersonalMessage = async (input) => ({
    ...validSignedPersonalMessageResult(input.message),
    signature: ZKLOGIN_SIGNATURE,
  });
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  const { accounts } = await wallet.features[StandardConnect].connect();
  const message = new TextEncoder().encode("hello Agent-Q");
  const signed = await wallet.features[SuiSignPersonalMessage].signPersonalMessage({
    account: accounts[0],
    chain: "sui:devnet",
    message,
  });
  assert.equal(signed.signature, ZKLOGIN_SIGNATURE);
  assert.equal(signed.bytes, Buffer.from(message).toString("base64"));
  assertNoSecretFields(signed);
});

test("Wallet Standard signTransaction fails closed for wrong account, wrong chain, and terminal results", async () => {
  const { core } = createDeviceCore();
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
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
  const rejectingWallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core: rejectingCore }),
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
    const wallet = createSuiDeviceWallet({
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
        assert.equal(error.message, SIGNING_OUTCOME_ERROR_MESSAGES[status]);
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
    const wallet = createSuiDeviceWallet({
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
    const wallet = createSuiDeviceWallet({
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
    const wallet = createSuiDeviceWallet({
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
  const { core, calls } = createDeviceCore();
  const wallet = createSuiDeviceWallet({
    provider: createSuiDeviceProvider({ core }),
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

test("Wallet Standard signTransaction clears connected accounts on non-live signing outcomes", async () => {
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
    const wallet = createSuiDeviceWallet({
      provider: createSuiDeviceProvider({ core }),
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
  const { core } = createDeviceCore();
  const provider = createSuiDeviceProvider({ core });
  const before = new Set(getWallets().get());
  const registration = registerSuiDeviceWallet({
    provider,
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  assert.equal(getWallets().get().includes(registration.wallet), true);
  registration.unregister();
  assert.deepEqual(new Set(getWallets().get()), before);

  const initializer = createSuiDeviceWalletInitializer({ provider, id: "signing-test" });
  assert.equal(initializer.id, "signing-test");
  const initialized = initializer.initialize({
    networks: ["devnet"],
    getClient: fakeClient,
  });
  assert.equal(getWallets().get().includes(initialized.wallet), true);
  assert.deepEqual(initialized.wallet.chains, ["sui:devnet"]);
  initialized.unregister();
  assert.deepEqual(new Set(getWallets().get()), before);
});
