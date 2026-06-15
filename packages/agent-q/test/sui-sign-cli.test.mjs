import assert from "node:assert/strict";
import test from "node:test";

import { runSuiSignCli } from "../dist/sui-sign-cli.js";
import {
  SIGNATURE,
  TX_BYTES,
  ZKLOGIN_ACCOUNT,
  ZKLOGIN_SIGNATURE,
  makeSuiSignerHarness,
} from "./sui-signer-test-support.mjs";

test("help describes the Sui CLI external signer", async () => {
  const harness = makeSuiSignerHarness();
  assert.equal(await runSuiSignCli(["--help"], harness.dependencies), 0);
  assert.match(harness.stdout.join(""), /Sui CLI external signer/);
  assert.match(harness.stdout.join(""), /npm install -g @stelis\/agent-q/);
  assert.match(harness.stdout.join(""), /agent-q serve --request-connect/);
  assert.match(harness.stdout.join(""), /must be on PATH/);
  assert.match(harness.stdout.join(""), /private key stays on/);
  assert.deepEqual(harness.calls, []);
});

test("invalid local arguments fail before connecting", async () => {
  const harness = makeSuiSignerHarness();
  assert.equal(await runSuiSignCli([], harness.dependencies), 1);
  assert.equal(harness.stdout.join(""), "");
  assert.equal(JSON.parse(harness.stderr.join("")).code, "invalid_params");
  assert.deepEqual(harness.calls, []);
});

test("configure stores signer settings", async () => {
  const harness = makeSuiSignerHarness();
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

test("payload above the current Firmware adapter capacity is forwarded", async () => {
  const harness = makeSuiSignerHarness();
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
  const harness = makeSuiSignerHarness();
  assert.equal(
    await runSuiSignCli(["--network", "testnet", "--tx-bytes", "-"], harness.dependencies),
    0,
  );
  assert.equal(harness.stdout.join(""), `${SIGNATURE}\n`);
  assert.match(harness.stderr.join(""), /device address:/);
  assert.deepEqual(harness.calls.at(-1), "disconnect");
});

test("direct signing accepts zkLogin transaction signature envelopes", async () => {
  const harness = makeSuiSignerHarness({
    core: {
      async getAccounts() {
        harness.calls.push("accounts");
        return {
          source: "live",
          accounts: [
            {
              ...ZKLOGIN_ACCOUNT,
            },
          ],
        };
      },
      async signTransaction() {
        harness.calls.push(["sign", TX_BYTES]);
        return {
          source: "live",
          status: "signed",
          signature: ZKLOGIN_SIGNATURE,
        };
      },
    },
  });
  assert.equal(
    await runSuiSignCli(["--network", "testnet", "--tx-bytes", TX_BYTES], harness.dependencies),
    0,
  );
  assert.equal(harness.stdout.join(""), `${ZKLOGIN_SIGNATURE}\n`);
  assert.match(harness.stderr.join(""), /device address:/);
  assert.deepEqual(harness.calls, ["connect", "accounts", ["sign", TX_BYTES], "disconnect"]);
});

test("equals-form flags are accepted", async () => {
  const harness = makeSuiSignerHarness();
  assert.equal(
    await runSuiSignCli([`--network=testnet`, `--tx-bytes=${TX_BYTES}`], harness.dependencies),
    0,
  );
  assert.equal(harness.stdout.join(""), `${SIGNATURE}\n`);
  assert.deepEqual(harness.calls.find((call) => Array.isArray(call)), ["sign", TX_BYTES]);
});

for (const [name, args, pattern] of [
  [
    "duplicate flag",
    ["--network", "testnet", "--network", "devnet", "--tx-bytes", TX_BYTES],
    /Duplicate flag: --network/,
  ],
  ["flag as value", ["--network", "--tx-bytes", TX_BYTES], /Provide a value for --network/],
  [
    "unknown positional argument",
    ["--network", "testnet", "--tx-bytes", TX_BYTES, "extra"],
    /Unsupported argument: extra/,
  ],
  [
    "unknown flag",
    ["--network", "testnet", "--tx-bytes", TX_BYTES, "--wat", "1"],
    /Unsupported flag: --wat/,
  ],
]) {
  test(`${name} fails before connecting`, async () => {
    const harness = makeSuiSignerHarness();
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
    const harness = makeSuiSignerHarness({ core });
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
  const harness = makeSuiSignerHarness({
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
  const harness = makeSuiSignerHarness({
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
  const harness = makeSuiSignerHarness({
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
  const harness = makeSuiSignerHarness({
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
