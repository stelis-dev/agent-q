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
  SuiSignTransaction,
} from "@mysten/wallet-standard";
import { createAgentQSuiProvider, AgentQSuiProvider } from "../dist/provider-sui.js";
import {
  AgentQSuiWallet,
  createAgentQSuiWallet,
  createAgentQSuiWalletInitializer,
  registerAgentQSuiWallet,
} from "../dist/wallet-standard.js";
import { FORBIDDEN_SECRET_FIELD_NAMES, SUI_DERIVATION_PATH } from "@stelis/agent-q-client/protocol";

const SUI_ADDRESS = "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133";
const SUI_PUBLIC_KEY = "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk=";
const SUI_SIGNATURE = Buffer.alloc(97, 1).toString("base64");

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
          user: [{ chain: "sui", method: "sign_transaction" }],
          policy: [{ chain: "sui", method: "sign_transaction" }],
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
    async signByUser() {
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
      async signByUser(input) {
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

test("provider-sui package metadata exposes only Sui provider and Wallet Standard entrypoints", async () => {
  const packagePath = fileURLToPath(new URL("../package.json", import.meta.url));
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  assert.equal(packageJson.name, "@stelis/agent-q-provider-sui");
  assert.deepEqual(Object.keys(packageJson.exports).sort(), [".", "./package.json", "./provider-sui", "./wallet-standard"]);
  assert.equal(packageJson.dependencies["@stelis/agent-q-client"], "0.0.0");
  assert.equal(packageJson.dependencies["@mysten/wallet-standard"], "^0.20.3");
  assert.equal(packageJson.dependencies["@mysten/sui"], "^2.17.0");
  assert.equal(packageJson.dependencies["@stelis/agent-q-mcp"], undefined);
  assert.equal(packageJson.bin, undefined);
});

test("provider-sui package self-reference resolves Sui provider only", async () => {
  const root = await import("@stelis/agent-q-provider-sui");
  const provider = await import("@stelis/agent-q-provider-sui/provider-sui");
  const walletStandard = await import("@stelis/agent-q-provider-sui/wallet-standard");
  assert.equal(typeof root.createAgentQSuiProvider, "function");
  assert.equal(typeof provider.AgentQSuiProvider, "function");
  assert.equal(typeof walletStandard.createAgentQSuiWallet, "function");
  assert.equal(typeof walletStandard.registerAgentQSuiWallet, "function");
  assert.equal(typeof walletStandard.createAgentQSuiWalletInitializer, "function");
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
  assert.doesNotMatch(source, /@stelis\/agent-q-mcp/);
  assert.doesNotMatch(source, /mcp/i);
  assert.doesNotMatch(source, /admin/i);
});

test("provider exposes the Sui dapp-facing adapter API including signByUser", () => {
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
    "signByUser",
  ]);
  assert.equal(typeof provider.signByUser, "function");
  assert.equal(provider.signByPolicy, undefined);
  assert.equal(provider.proposePolicyUpdate, undefined);
  assert.equal(provider.getPolicy, undefined);
  assert.equal(provider.getApprovalHistory, undefined);
});

test("provider delegates current methods and signByUser without exposing session ids or secrets", async () => {
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
    await provider.signByUser({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "AQID",
    }),
  ];
  for (const output of outputs) {
    assertNoSecretFields(output);
  }
  const capabilities = outputs[6];
  assert.deepEqual(capabilities.signing, {
    user: [{ chain: "sui", method: "sign_transaction" }],
  });
  assert.equal(JSON.stringify(capabilities).includes('"policy"'), false);
});

test("provider getCapabilities applies the provider capability schema after projection", async () => {
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
          user: [{ chain: "sui", method: "sign_personal_message" }],
          policy: [{ chain: "sui", method: "sign_transaction" }],
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
    ["signByUser", (provider) => provider.signByUser({
      deviceId: "device-1",
      chain: "sui",
      method: "sign_transaction",
      network: "devnet",
      txBytes: "AQID",
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

test("provider signByUser rejects non-user signing results from custom cores", async () => {
  const core = {
    ...createFakeCore(),
    async signByUser() {
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
  await assert.rejects(() => provider.signByUser({
    deviceId: "device-1",
    chain: "sui",
    method: "sign_transaction",
    network: "devnet",
    txBytes: "AQID",
  }));
});

test("provider does not expose raw method or Admin policy update entrypoints", () => {
  const provider = createAgentQSuiProvider({ core: createFakeCore() });
  assert.equal(provider.signByPolicy, undefined);
  assert.equal(provider.proposePolicyUpdate, undefined);
  assert.equal(provider.getPolicy, undefined);
  assert.equal(provider.getApprovalHistory, undefined);
  assert.equal(typeof provider.signByUser, "function");
});

test("Wallet Standard adapter advertises only current Agent-Q Sui signing features", () => {
  const { core } = createSigningCore();
  const wallet = createAgentQSuiWallet({
    provider: createAgentQSuiProvider({ core }),
    getClient: fakeClient,
    chains: ["sui:devnet"],
  });
  assert.equal(wallet instanceof AgentQSuiWallet, true);
  assert.equal(wallet.name, "Agent-Q Sui");
  assert.deepEqual(wallet.chains, ["sui:devnet"]);
  assert.deepEqual(Object.keys(wallet.features).sort(), [
    "standard:connect",
    "standard:disconnect",
    "standard:events",
    "sui:signTransaction",
  ]);
  assert.equal(wallet.features["sui:signPersonalMessage"], undefined);
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
  assert.deepEqual(connected.accounts[0].features, [SuiSignTransaction]);
  assertNoSecretFields(connected);
  assert.equal(wallet.getPolicy, undefined);
  assert.equal(wallet.getApprovalHistory, undefined);
  assert.equal(wallet.signByPolicy, undefined);
  await wallet.features[StandardDisconnect].disconnect();
  unsubscribe();
  assert.equal(wallet.accounts.length, 0);
  assert.equal(changes.length, 2);
  assert.deepEqual(changes.map((change) => change.accounts.length), [1, 0]);
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
    async signByUser() {
      return createFakeCore().signByUser();
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

test("Wallet Standard signTransaction builds bytes and delegates to signByUser only", async () => {
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
    async signByUser() {
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
    { source: "session_ended", reason: "transport_unavailable" },
    { source: "not_connected", reason: "not_connected" },
  ];
  for (const signResult of cases) {
    const core = {
      ...createFakeCore(),
      async signByUser() {
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
      new RegExp(signResult.source),
    );
    unsubscribe();
    assert.equal(wallet.accounts.length, 0);
    assert.deepEqual(changes.map((change) => change.accounts.length), [1, 0]);
  }
});

test("Wallet Standard registration helpers register, initialize, and unregister Agent-Q wallets", () => {
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
