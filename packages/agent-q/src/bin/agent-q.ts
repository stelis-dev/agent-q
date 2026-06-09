#!/usr/bin/env node
const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`Agent-Q

Usage:
  agent-q
  agent-q serve
  agent-q serve --request-connect
  agent-q serve --request-connect --device-id <id>
  agent-q serve --request-connect --purpose <purpose>
  agent-q serve --port N
  agent-q --help

Exposes stdio MCP tools, a local HTTP API, and the Admin Page through one
shared Agent-Q session owner. Connection sessions do not authorize signing.

When stdin is a terminal, agent-q keeps the local HTTP API and Admin Page
running. When an MCP client starts agent-q with stdio pipes, MCP tools are
served over stdio by the same process.

--request-connect sends a connection request when the server starts. The device
must still approve the request locally before a session exists.`);
  process.exit(0);
}

const parsedArgs = parseAgentQArgs(args);

await startAgentQ(parsedArgs);

interface AgentQArgs {
  port: number | undefined;
  requestConnect: boolean;
  deviceId: string | undefined;
  purpose: string | undefined;
}

async function startAgentQ(agentQArgs: AgentQArgs): Promise<void> {
  let localApiServer: import("node:http").Server | undefined;
  let localApiServerClosed = false;
  const closeLocalApiServer = async (): Promise<void> => {
    const server = localApiServer;
    if (server === undefined || localApiServerClosed) {
      return;
    }
    localApiServerClosed = true;
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  };
  try {
    const { createDefaultAgentQCore } = await import("@stelis/agent-q-core");
    const { DEFAULT_LOCAL_API_PORT, startLocalApiServer } = await import("../local-api.js");
    const { startStdioMcpServer } = await import("../mcp.js");
    const { requestDeviceConnectionOnStart } = await import("../startup-connect.js");
    const core = createDefaultAgentQCore();
    const port = agentQArgs.port ?? DEFAULT_LOCAL_API_PORT;
    const localApi = await startLocalApiServer({ core, port });
    localApiServer = localApi.server;
    console.error(`Agent-Q local API listening on ${localApi.url}`);
    if (agentQArgs.requestConnect) {
      await requestDeviceConnectionOnStart(core, {
        deviceId: agentQArgs.deviceId,
        purpose: agentQArgs.purpose,
      });
    }
    if (process.stdin.isTTY) {
      console.error("Agent-Q MCP stdio disabled because stdin is a terminal.");
      await waitForProcessShutdown();
      await closeLocalApiServer();
      return;
    }
    process.stdin.once("end", () => {
      void closeLocalApiServer();
    });
    process.stdin.once("close", () => {
      void closeLocalApiServer();
    });
    await startStdioMcpServer(core, {
      onClose: () => {
        void closeLocalApiServer();
      },
    });
  } catch {
    await closeLocalApiServer();
    // Do not interpolate the raw error: a startup failure can carry OS/transport
    // text, and stderr is a shared diagnostic channel. A fixed line signals the
    // failure; the non-zero exit code is the machine-readable signal.
    console.error("Agent-Q failed to start.");
    process.exit(1);
  }
}

function waitForProcessShutdown(): Promise<void> {
  return new Promise((resolve) => {
    const shutdown = () => {
      process.off("SIGINT", shutdown);
      process.off("SIGTERM", shutdown);
      resolve();
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });
}

function parseAgentQArgs(rawArgs: string[]): AgentQArgs {
  const args = rawArgs[0] === "serve" ? rawArgs.slice(1) : rawArgs;
  const parsed: AgentQArgs = {
    port: undefined,
    requestConnect: false,
    deviceId: undefined,
    purpose: undefined,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--port":
        if (parsed.port !== undefined) {
          return unsupportedArgs();
        }
        parsed.port = parseLocalApiPort(readOptionValue(args, index));
        index += 1;
        break;
      case "--request-connect":
        if (parsed.requestConnect) {
          return unsupportedArgs();
        }
        parsed.requestConnect = true;
        break;
      case "--device-id":
        if (parsed.deviceId !== undefined) {
          return unsupportedArgs();
        }
        parsed.deviceId = readOptionValue(args, index);
        index += 1;
        break;
      case "--purpose":
        if (parsed.purpose !== undefined) {
          return unsupportedArgs();
        }
        parsed.purpose = readOptionValue(args, index);
        index += 1;
        break;
      default:
        return unsupportedArgs();
    }
  }

  if (!parsed.requestConnect && (parsed.deviceId !== undefined || parsed.purpose !== undefined)) {
    return unsupportedArgs();
  }
  return parsed;
}

function readOptionValue(args: string[], optionIndex: number): string {
  const value = args[optionIndex + 1];
  if (value === undefined || value.startsWith("--")) {
    unsupportedArgs();
  }
  return value;
}

function parseLocalApiPort(value: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    console.error("Invalid port. Run agent-q --help.");
    process.exit(1);
  }
  return port;
}

function unsupportedArgs(): never {
  console.error("Unsupported arguments. Run agent-q --help.");
  process.exit(1);
}
