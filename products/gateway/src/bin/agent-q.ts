#!/usr/bin/env node
import { startStdioGateway } from "../mcp.js";

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`Agent-Q Gateway

Usage:
  agent-q          Start the stdio MCP server
  agent-q --help   Show this help

Exposes device discovery, identification, selection, status, registry, and
connection-session MCP tools. Connection sessions do not authorize signing.`);
  process.exit(0);
}

if (args.length > 0) {
  console.error("Unsupported arguments. Run agent-q --help.");
  process.exit(1);
}

startStdioGateway().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Agent-Q Gateway failed: ${message}`);
  process.exit(1);
});
