import assert from "node:assert/strict";
import { createServer } from "node:net";

import { createLocalApiHttpServer } from "../dist/local-api.js";

export const SIGNATURE = `${"A".repeat(130)}==`;
export const ZKLOGIN_SIGNATURE = Buffer.concat([Buffer.from([5]), Buffer.alloc(144, 1)]).toString(
  "base64",
);
export const TX_BYTES = Buffer.from("test transaction").toString("base64");
export const DEVICE_ID = "a508d833-5c83-4680-88bb-18aee976881e";
export const ACCOUNT = {
  chain: "sui",
  address: "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
  publicKey: "ACJkf+7vNjBgvUIFoWcaFfEKEjZ2WRixtfY42C8zz8Rp",
  keyScheme: "ed25519",
  derivationPath: "m/44'/784'/0'/0'/0'",
  sponsoredTransactions: {
    acceptGasSponsor: false,
  },
};
export const ZKLOGIN_ACCOUNT = {
  chain: "sui",
  address: "0xd41c7cbc0cbccb9e7ab701373f3b5f082cc0024098f2ab561ff342107b91491f",
  publicKey:
    "BRtodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ==",
  keyScheme: "zklogin",
  sponsoredTransactions: {
    acceptGasSponsor: false,
  },
};

export function makeSuiSignerHarness(overrides = {}) {
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

export async function withLocalServer(core, callback) {
  const server = createLocalApiHttpServer(core);
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

export async function allocatePort() {
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
