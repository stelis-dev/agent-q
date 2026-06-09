#!/usr/bin/env node
import { createDefaultGatewayCore } from "@stelis/agent-q-client/admin";

import { runSuiSignCli } from "../sui-sign-cli.js";

process.exitCode = await runSuiSignCli(process.argv.slice(2), {
  core: createDefaultGatewayCore(),
  async readStdin() {
    process.stdin.setEncoding("utf8");
    let data = "";
    for await (const chunk of process.stdin) {
      data += chunk;
    }
    return data;
  },
  writeStdout: (text) =>
    new Promise<void>((resolve, reject) => {
      process.stdout.write(text, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    }),
  writeStderr: (text) =>
    new Promise<void>((resolve, reject) => {
      process.stderr.write(text, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    }),
});
