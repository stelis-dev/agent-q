import assert from "node:assert/strict";
import test from "node:test";

import { runSuiSignCli } from "../dist/sui-sign-cli.js";

const SIGNATURE = `${"A".repeat(130)}==`;
const TX_BYTES = Buffer.from("test transaction").toString("base64");

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
      return { source: "live", accounts: [{ address: "0x1" }] };
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
    ...overrides.dependencies,
  };
  return { calls, stdout, stderr, dependencies };
}

test("help describes an offline bridge without claiming external-signer compatibility", async () => {
  const harness = makeHarness();
  assert.equal(await runSuiSignCli(["--help"], harness.dependencies), 0);
  assert.match(harness.stdout.join(""), /offline-signing bridge/);
  assert.match(harness.stdout.join(""), /not the Sui CLI JSON-RPC external-signer protocol/);
  assert.deepEqual(harness.calls, []);
});

test("invalid local arguments fail before connecting", async () => {
  const harness = makeHarness();
  assert.equal(await runSuiSignCli([], harness.dependencies), 1);
  assert.equal(harness.stdout.join(""), "");
  assert.equal(JSON.parse(harness.stderr.join("")).code, "invalid_params");
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
  assert.equal(harness.stderr.filter((line) => line.includes("session cleanup")).length, 0);
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
