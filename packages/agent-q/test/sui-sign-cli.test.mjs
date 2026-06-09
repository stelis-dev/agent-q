import assert from "node:assert/strict";
import { createServer } from "node:net";
import test from "node:test";

import { createAdminHttpServer } from "../dist/admin.js";
import { createLocalServerSuiSignCliCore } from "../dist/sui-signer-local-client.js";
import { runSuiSignCli } from "../dist/sui-sign-cli.js";

const SIGNATURE = `${"A".repeat(130)}==`;
const TX_BYTES = Buffer.from("test transaction").toString("base64");
const DEVICE_ID = "a508d833-5c83-4680-88bb-18aee976881e";
const ACCOUNT = {
  chain: "sui",
  address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
  publicKey: "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk=",
  keyScheme: "ed25519",
  derivationPath: "m/44'/784'/0'/0'/0'",
};

function makeHarness(overrides = {}) {
  const calls = [];
  const stdout = [];
  const stderr = [];
  const core = {
    async connectDevice() {
      calls.push("connect");
      return { source: "connected" };
    },
    async disconnectDevice() {
      calls.push("disconnect");
      return { source: "disconnected" };
    },
    async getAccounts() {
      calls.push("accounts");
      return { source: "live", accounts: [ACCOUNT] };
    },
    async signTransaction(input) {
      calls.push(["sign", input.txBytes]);
      return {
        source: "live",
        status: "signed",
        signature: SIGNATURE,
      };
    },
    ...overrides.core,
  };
  const dependencies = {
    core,
    async readStdin() {
      calls.push("stdin");
      return TX_BYTES;
    },
    async writeStdout(text) {
      stdout.push(text);
    },
    async writeStderr(text) {
      stderr.push(text);
    },
    async loadConfig() {
      return { network: "testnet" };
    },
    async saveConfig(config) {
      calls.push(["saveConfig", config]);
    },
    ...overrides.dependencies,
  };
  return { calls, stdout, stderr, dependencies };
}

test("help describes the Sui CLI external signer", async () => {
  const harness = makeHarness();
  assert.equal(await runSuiSignCli(["--help"], harness.dependencies), 0);
  assert.match(harness.stdout.join(""), /Sui CLI external signer/);
  assert.match(harness.stdout.join(""), /private key stays on/);
  assert.doesNotMatch(harness.stdout.join(""), /offline-signing bridge/);
  assert.deepEqual(harness.calls, []);
});

test("invalid local arguments fail before connecting", async () => {
  const harness = makeHarness();
  assert.equal(await runSuiSignCli([], harness.dependencies), 1);
  assert.equal(harness.stdout.join(""), "");
  assert.equal(JSON.parse(harness.stderr.join("")).code, "invalid_params");
  assert.deepEqual(harness.calls, []);
});

test("configure stores signer settings", async () => {
  const harness = makeHarness();
  assert.equal(
    await runSuiSignCli(
      ["configure", "--network", "testnet", "--device-id", "dev1", "--purpose", "Sui CLI"],
      harness.dependencies,
    ),
    0,
  );
  assert.deepEqual(harness.calls, [
    [
      "saveConfig",
      {
        network: "testnet",
        deviceId: "dev1",
        purpose: "Sui CLI",
      },
    ],
  ]);
  assert.match(harness.stdout.join(""), /configured/);
});

test("Sui CLI call keys returns external signer key records", async () => {
  const harness = makeHarness();
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return '{"jsonrpc":"2.0","method":"keys","params":null,"id":0}\n';
        },
      },
    ),
    0,
  );
  const response = JSON.parse(harness.stdout.join(""));
  assert.equal(response.jsonrpc, "2.0");
  assert.equal(response.id, 0);
  assert.deepEqual(response.result.keys, [
    {
      key_id: ACCOUNT.derivationPath,
      public_key: { Ed25519: ACCOUNT.publicKey },
      sui_address: ACCOUNT.address,
    },
  ]);
  assert.deepEqual(harness.calls, ["connect", "accounts", "disconnect"]);
});

test("Sui CLI call public_key returns one key", async () => {
  const harness = makeHarness();
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return `{"jsonrpc":"2.0","method":"public_key","params":{"key_id":"${ACCOUNT.derivationPath}"},"id":1}\n`;
        },
      },
    ),
    0,
  );
  const response = JSON.parse(harness.stdout.join(""));
  assert.deepEqual(response.result, {
    key_id: ACCOUNT.derivationPath,
    public_key: { Ed25519: ACCOUNT.publicKey },
    sui_address: ACCOUNT.address,
  });
  assert.deepEqual(harness.calls, ["connect", "accounts", "disconnect"]);
});

test("Sui CLI call sign returns JSON-RPC signature and signs once", async () => {
  const harness = makeHarness();
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return `{"jsonrpc":"2.0","method":"sign","params":{"key_id":"${ACCOUNT.derivationPath}","msg":"${TX_BYTES}"},"id":2}\n`;
        },
      },
    ),
    0,
  );
  const response = JSON.parse(harness.stdout.join(""));
  assert.deepEqual(response.result, { signature: SIGNATURE });
  assert.equal(harness.stderr.join(""), "");
  assert.deepEqual(harness.calls, [
    "connect",
    "accounts",
    ["sign", TX_BYTES],
    "disconnect",
  ]);
});

test("Sui CLI call sign can use the local Agent-Q server API", async () => {
  const calls = [];
  await withLocalServer(
    {
      async connectDevice(input) {
        calls.push(["connect", input]);
        return {
          source: "connected",
          deviceId: DEVICE_ID,
          sessionTtlMs: 4294967295,
          connectedAt: "2026-05-28T00:00:00.000Z",
          device: {
            deviceId: DEVICE_ID,
            state: "idle",
            firmwareName: "Agent-Q Firmware",
            hardware: "stackchan-cores3",
            firmwareVersion: "0.0.0",
          },
        };
      },
      async disconnectDevice(input) {
        calls.push(["disconnect", input]);
        return { source: "disconnected", deviceId: DEVICE_ID, reason: "firmware_confirmed" };
      },
      async getAccounts(input) {
        calls.push(["accounts", input]);
        return { source: "live", deviceId: DEVICE_ID, accounts: [ACCOUNT] };
      },
      async signTransaction(input) {
        calls.push(["sign", input]);
        return {
          source: "live",
          deviceId: DEVICE_ID,
          status: "signed",
          authorization: "user",
          chain: "sui",
          method: "sign_transaction",
          signature: SIGNATURE,
        };
      },
      async listDevices() {
        return { source: "list", devices: [], activeDeviceId: null, activeDeviceIdsByPurpose: {} };
      },
      async scanDevices() {
        return { source: "live", devices: [], failures: [], activeDeviceId: null };
      },
      async policyGet() {
        return { source: "not_connected", deviceId: DEVICE_ID, reason: "not_connected" };
      },
      async getApprovalHistory() {
        return { source: "not_connected", deviceId: DEVICE_ID, reason: "not_connected" };
      },
      async policyPropose() {
        return { source: "not_connected", deviceId: DEVICE_ID, reason: "not_connected" };
      },
    },
    async (baseUrl) => {
      const harness = makeHarness({
        dependencies: {
          core: createLocalServerSuiSignCliCore({ baseUrl }),
          async readStdin() {
            return `{"jsonrpc":"2.0","method":"sign","params":{"key_id":"${ACCOUNT.derivationPath}","msg":"${TX_BYTES}"},"id":22}\n`;
          },
          async loadConfig() {
            return { network: "testnet", deviceId: DEVICE_ID, purpose: "sui-cli" };
          },
        },
      });
      assert.equal(await runSuiSignCli(["call"], harness.dependencies), 0, harness.stdout.join(""));
      assert.deepEqual(JSON.parse(harness.stdout.join("")).result, { signature: SIGNATURE });
    },
  );
  assert.deepEqual(calls.map((call) => call[0]), ["connect", "accounts", "sign", "disconnect"]);
  assert.equal(calls[0][1].purpose, "sui-cli");
  assert.equal(calls[2][1].txBytes, TX_BYTES);
});

test("Sui CLI call returns a clear JSON-RPC error when the local server is absent", async () => {
  const port = await allocatePort();
  const harness = makeHarness({
    dependencies: {
      core: createLocalServerSuiSignCliCore({ baseUrl: `http://127.0.0.1:${port}` }),
      async readStdin() {
        return '{"jsonrpc":"2.0","method":"keys","params":null,"id":23}\n';
      },
    },
  });
  assert.equal(await runSuiSignCli(["call"], harness.dependencies), 1);
  const response = JSON.parse(harness.stdout.join(""));
  assert.equal(response.id, 23);
  assert.equal(response.error.code, 1);
  assert.match(response.error.message, /Start the local Agent-Q server/);
});

test("Sui CLI call sign requires configured network", async () => {
  const harness = makeHarness({
    dependencies: {
      async loadConfig() {
        return {};
      },
    },
  });
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return `{"jsonrpc":"2.0","method":"sign","params":{"key_id":"${ACCOUNT.derivationPath}","msg":"${TX_BYTES}"},"id":3}\n`;
        },
      },
    ),
    1,
  );
  const response = JSON.parse(harness.stdout.join(""));
  assert.equal(response.error.code, 1);
  assert.match(response.error.message, /network is not configured/);
  assert.deepEqual(harness.calls, []);
});

test("Sui CLI call create_key is explicitly unsupported", async () => {
  const harness = makeHarness();
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return '{"jsonrpc":"2.0","method":"create_key","params":{},"id":4}\n';
        },
      },
    ),
    1,
  );
  const response = JSON.parse(harness.stdout.join(""));
  assert.equal(response.error.code, -32601);
  assert.deepEqual(harness.calls, []);
});

test("payload above the current Firmware adapter capacity is forwarded", async () => {
  const harness = makeHarness();
  const oversizedForCurrentAdapter = Buffer.alloc(385).toString("base64");
  assert.equal(
    await runSuiSignCli(
      ["--network", "testnet", "--tx-bytes", oversizedForCurrentAdapter],
      harness.dependencies,
    ),
    0,
  );
  assert.deepEqual(harness.calls.at(-1), "disconnect");
  assert.deepEqual(harness.calls.find((call) => Array.isArray(call)), [
    "sign",
    oversizedForCurrentAdapter,
  ]);
});

test("stdin input is forwarded and success prints only the signature to stdout", async () => {
  const harness = makeHarness();
  assert.equal(
    await runSuiSignCli(["--network", "testnet", "--tx-bytes", "-"], harness.dependencies),
    0,
  );
  assert.equal(harness.stdout.join(""), `${SIGNATURE}\n`);
  assert.match(harness.stderr.join(""), /device address:/);
  assert.deepEqual(harness.calls.at(-1), "disconnect");
});

test("equals-form flags are accepted", async () => {
  const harness = makeHarness();
  assert.equal(
    await runSuiSignCli([`--network=testnet`, `--tx-bytes=${TX_BYTES}`], harness.dependencies),
    0,
  );
  assert.equal(harness.stdout.join(""), `${SIGNATURE}\n`);
  assert.deepEqual(harness.calls.find((call) => Array.isArray(call)), ["sign", TX_BYTES]);
});

for (const [name, args, pattern] of [
  ["duplicate flag", ["--network", "testnet", "--network", "devnet", "--tx-bytes", TX_BYTES], /Duplicate flag: --network/],
  ["flag as value", ["--network", "--tx-bytes", TX_BYTES], /Provide a value for --network/],
  ["unknown positional argument", ["--network", "testnet", "--tx-bytes", TX_BYTES, "extra"], /Unsupported argument: extra/],
  ["unknown flag", ["--network", "testnet", "--tx-bytes", TX_BYTES, "--wat", "1"], /Unsupported flag: --wat/],
]) {
  test(`${name} fails before connecting`, async () => {
    const harness = makeHarness();
    assert.equal(await runSuiSignCli(args, harness.dependencies), 1);
    assert.equal(harness.stdout.join(""), "");
    assert.match(JSON.parse(harness.stderr.join("")).message, pattern);
    assert.deepEqual(harness.calls, []);
  });
}

for (const [name, core] of [
  ["account-read failure", { async getAccounts() { throw new Error("lost"); } }],
  ["terminal signing result", { async signTransaction() { return { source: "live", status: "user_rejected" }; } }],
  ["thrown signing error", { async signTransaction() { throw new Error("lost"); } }],
]) {
  test(`${name} disconnects after connect`, async () => {
    const harness = makeHarness({ core });
    const code = await runSuiSignCli(
      ["--network", "testnet", "--tx-bytes", TX_BYTES],
      harness.dependencies,
    );
    assert.equal(harness.calls.at(-1), "disconnect");
    if (name === "account-read failure") {
      assert.equal(code, 0);
    } else {
      assert.equal(code, 1);
    }
  });
}

test("stdout failure still disconnects", async () => {
  const harness = makeHarness({
    dependencies: {
      async writeStdout() {
        throw new Error("stdout closed");
      },
    },
  });
  assert.equal(
    await runSuiSignCli(["--network", "testnet", "--tx-bytes", TX_BYTES], harness.dependencies),
    1,
  );
  assert.deepEqual(harness.calls.at(-1), "disconnect");
});

test("connect failure does not attempt disconnect", async () => {
  const harness = makeHarness({
    core: {
      async connectDevice() {
        throw new Error("connect failed");
      },
    },
  });
  assert.equal(
    await runSuiSignCli(["--network", "testnet", "--tx-bytes", TX_BYTES], harness.dependencies),
    1,
  );
  assert.equal(harness.calls.includes("disconnect"), false);
});

test("disconnect failure does not replace a produced signature", async () => {
  const harness = makeHarness({
    core: {
      async disconnectDevice() {
        throw new Error("disconnect failed");
      },
    },
  });
  assert.equal(
    await runSuiSignCli(["--network", "testnet", "--tx-bytes", TX_BYTES], harness.dependencies),
    0,
  );
  assert.equal(harness.stdout.join(""), `${SIGNATURE}\n`);
  assert.equal(harness.stderr.filter((line) => line.includes("session cleanup")).length, 1);
});

test("disconnect failure after a failed request is reported without raw error text", async () => {
  const harness = makeHarness({
    core: {
      async signTransaction() {
        return { source: "live", status: "user_rejected" };
      },
      async disconnectDevice() {
        throw new Error("secret transport detail");
      },
    },
  });
  assert.equal(
    await runSuiSignCli(["--network", "testnet", "--tx-bytes", TX_BYTES], harness.dependencies),
    1,
  );
  assert.match(harness.stderr.join(""), /could not confirm session cleanup/);
  assert.doesNotMatch(harness.stderr.join(""), /secret transport detail/);
});

async function withLocalServer(core, callback) {
  const server = createAdminHttpServer(core);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  try {
    await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function allocatePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  const port = address.port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
