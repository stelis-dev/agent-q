import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { runSuiSignCli } from "../dist/sui-sign-cli.js";
import {
  ACCOUNT,
  SIGNATURE,
  TX_BYTES,
  ZKLOGIN_ACCOUNT,
  makeSuiSignerHarness,
} from "./sui-signer-test-support.mjs";

const RAW_ED25519_PUBLIC_KEY = "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk=";

test("Sui CLI call keys returns external signer key records", async () => {
  const harness = makeSuiSignerHarness();
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return '{"jsonrpc":"2.0","method":"keys","params":[null],"id":0}';
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
      public_key: { Ed25519: RAW_ED25519_PUBLIC_KEY },
      sui_address: ACCOUNT.address,
    },
  ]);
  assert.deepEqual(harness.calls, ["connect", "accounts", "disconnect"]);
});

test("Sui CLI call public_key returns one key", async () => {
  const harness = makeSuiSignerHarness();
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return `{"jsonrpc":"2.0","method":"public_key","params":["${ACCOUNT.derivationPath}"],"id":1}\n`;
        },
      },
    ),
    0,
  );
  const response = JSON.parse(harness.stdout.join(""));
  assert.deepEqual(response.result, {
    key_id: ACCOUNT.derivationPath,
    public_key: { Ed25519: RAW_ED25519_PUBLIC_KEY },
    sui_address: ACCOUNT.address,
  });
  assert.deepEqual(harness.calls, ["connect", "accounts", "disconnect"]);
});

test("Sui CLI call sign returns JSON-RPC signature and signs once", async () => {
  const harness = makeSuiSignerHarness();
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return `{"jsonrpc":"2.0","method":"sign","params":{"key_id":"${ACCOUNT.derivationPath}","msg":"${TX_BYTES}","intent":{"scope":"TransactionData","version":"V0","app_id":"Sui"}},"id":2}\n`;
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

test("Sui CLI external signer does not advertise zkLogin active accounts", async () => {
  const harness = makeSuiSignerHarness({
    core: {
      async getAccounts() {
        harness.calls.push("accounts");
        return { source: "live", accounts: [ZKLOGIN_ACCOUNT] };
      },
    },
  });
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return '{"jsonrpc":"2.0","method":"keys","params":[null],"id":20}';
        },
      },
    ),
    1,
  );
  const response = JSON.parse(harness.stdout.join(""));
  assert.equal(response.jsonrpc, "2.0");
  assert.equal(response.id, 20);
  assert.equal(response.error.code, 1);
  assert.match(response.error.message, /native single-key signatures/);
  assert.deepEqual(harness.calls, ["connect", "accounts", "disconnect"]);
});

test("Sui CLI external signer sign fails closed for zkLogin active accounts", async () => {
  const harness = makeSuiSignerHarness({
    core: {
      async getAccounts() {
        harness.calls.push("accounts");
        return { source: "live", accounts: [ZKLOGIN_ACCOUNT] };
      },
      async signTransaction() {
        harness.calls.push("sign");
        throw new Error("signTransaction should not be called for zkLogin external signer.");
      },
    },
  });
  assert.equal(
    await runSuiSignCli(
      ["call"],
      {
        ...harness.dependencies,
        async readStdin() {
          return `{"jsonrpc":"2.0","method":"sign","params":{"key_id":"${ZKLOGIN_ACCOUNT.address}","msg":"${TX_BYTES}","intent":{"scope":"TransactionData","version":"V0","app_id":"Sui"}},"id":21}\n`;
        },
      },
    ),
    1,
  );
  const response = JSON.parse(harness.stdout.join(""));
  assert.equal(response.id, 21);
  assert.equal(response.error.code, 1);
  assert.match(response.error.message, /native single-key signatures/);
  assert.deepEqual(harness.calls, ["connect", "accounts", "disconnect"]);
});

const packageRoot = fileURLToPath(new URL("..", import.meta.url));

test("Sui CLI signer process exits after one complete JSON object without stdin close", async () => {
  const child = spawn(process.execPath, ["dist/bin/agent-q-sui-signer.js", "call"], {
    cwd: packageRoot,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  child.stdin.write('{"jsonrpc":"2.0","method":"create_key","params":{},"id":44}');

  const exit = await waitForExitOrTimeout(child, 2_000);
  assert.equal(exit.code, 1, stderr);
  const response = JSON.parse(stdout);
  assert.equal(response.id, 44);
  assert.equal(response.error.code, -32601);
});

test("Sui CLI call sign requires configured network", async () => {
  const harness = makeSuiSignerHarness({
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
  const harness = makeSuiSignerHarness();
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

function waitForExitOrTimeout(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("agent-q-sui-signer did not exit after one JSON-RPC object."));
    }, timeoutMs);
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal });
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}
