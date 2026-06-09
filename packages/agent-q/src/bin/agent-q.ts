#!/usr/bin/env node
const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`Agent-Q

Usage:
  agent-q           Start the local Agent-Q process
  agent-q --port N  Start the local Agent-Q process with the Admin Page on port N
  agent-q --help             Show this help

Exposes stdio MCP tools and a local Admin Page through one shared Agent-Q
session owner. Connection sessions do not authorize signing.`);
  process.exit(0);
}

if (args.length !== 0 && (args.length !== 2 || args[0] !== "--port")) {
  console.error("Unsupported arguments. Run agent-q --help.");
  process.exit(1);
}

await startAgentQ(args);

async function startAgentQ(agentQArgs: string[]): Promise<void> {
  let adminServer: import("node:http").Server | undefined;
  let adminServerClosed = false;
  const closeAdminServer = async (): Promise<void> => {
    const server = adminServer;
    if (server === undefined || adminServerClosed) {
      return;
    }
    adminServerClosed = true;
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  };
  try {
    const { createDefaultAgentQCore } = await import("@stelis/agent-q-core");
    const { DEFAULT_ADMIN_PORT, startAdminServer } = await import("../admin.js");
    const { startStdioMcpServer } = await import("../mcp.js");
    const core = createDefaultAgentQCore();
    const port = parseAdminPort(agentQArgs, DEFAULT_ADMIN_PORT);
    const admin = await startAdminServer({ core, port });
    adminServer = admin.server;
    console.error(`Agent-Q Admin listening on ${admin.url}`);
    process.stdin.once("end", () => {
      void closeAdminServer();
    });
    process.stdin.once("close", () => {
      void closeAdminServer();
    });
    await startStdioMcpServer(core, {
      onClose: () => {
        void closeAdminServer();
      },
    });
  } catch {
    await closeAdminServer();
    // Do not interpolate the raw error: a startup failure can carry OS/transport
    // text, and stderr is a shared diagnostic channel. A fixed line signals the
    // failure; the non-zero exit code is the machine-readable signal.
    console.error("Agent-Q failed to start.");
    process.exit(1);
  }
}

function parseAdminPort(agentQArgs: string[], defaultPort: number): number {
  if (agentQArgs.length === 0) {
    return defaultPort;
  }
  const port = Number(agentQArgs[1]);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    console.error("Invalid port. Run agent-q --help.");
    process.exit(1);
  }
  return port;
}
