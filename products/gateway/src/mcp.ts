import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";
import { ConfigStore } from "./config.js";
import {
  GatewayCore,
  MAX_IDENTIFY_DURATION_MS,
  toErrorToolResult,
  type DeviceStatusToolResult,
} from "./core.js";
import { toGatewayError } from "./errors.js";
import { SerialPortUsbDriver, MAX_SCAN_TIMEOUT_MS } from "./usb.js";

const errorShape = z.object({
  code: z.string(),
  message: z.string(),
  retryable: z.boolean(),
});

const deviceShape = z.object({
  deviceId: z.string(),
  state: z.enum(["idle", "busy", "awaiting_approval", "locked", "error"]),
  firmwareName: z.string(),
  hardware: z.string(),
  firmwareVersion: z.string(),
});

const statusResponseShape = z.object({
  id: z.string(),
  version: z.literal(1),
  type: z.literal("status"),
  device: deviceShape,
});

const identifyResponseShape = z.object({
  id: z.string(),
  version: z.literal(1),
  type: z.literal("identify_device_result"),
  status: z.literal("displayed"),
  code: z.string(),
  device: deviceShape,
});

const liveStatusShape = z.object({
  source: z.literal("live"),
  connected: z.literal(true),
  portPath: z.string(),
  protocolResponse: statusResponseShape,
});

const identifiedDeviceShape = z.object({
  source: z.literal("live"),
  connected: z.literal(true),
  portPath: z.string(),
  code: z.string(),
  protocolResponse: identifyResponseShape,
});

export const gatewayToolDefinitions = {
  scanDevices: {
    name: "scan_devices",
    inputSchema: {
      timeoutMs: z.number().int().positive().max(MAX_SCAN_TIMEOUT_MS).optional(),
    },
    outputSchema: {
      source: z.enum(["live", "error"]),
      devices: z.array(liveStatusShape).optional(),
      activeDeviceId: z.string().nullable().optional(),
      connected: z.literal(false).optional(),
      error: errorShape.optional(),
    },
  },
  identifyDevices: {
    name: "identify_devices",
    inputSchema: {
      timeoutMs: z.number().int().positive().max(MAX_SCAN_TIMEOUT_MS).optional(),
      durationMs: z.number().int().positive().max(MAX_IDENTIFY_DURATION_MS).optional(),
    },
    outputSchema: {
      source: z.enum(["live", "error"]),
      devices: z.array(identifiedDeviceShape).optional(),
      activeDeviceId: z.string().nullable().optional(),
      connected: z.literal(false).optional(),
      error: errorShape.optional(),
    },
  },
  selectDevice: {
    name: "select_device",
    inputSchema: {
      deviceId: z.string().min(1),
    },
    outputSchema: {
      source: z.enum(["selected", "error"]),
      activeDeviceId: z.string().optional(),
      device: deviceShape.optional(),
      connected: z.literal(false).optional(),
      error: errorShape.optional(),
    },
  },
  getDeviceStatus: {
    name: "get_device_status",
    inputSchema: {
      deviceId: z.string().optional(),
    },
    outputSchema: {
      source: z.enum(["live", "cached", "error"]),
      connected: z.boolean(),
      portPath: z.string().optional(),
      protocolResponse: statusResponseShape.optional(),
      statusObservedAt: z.string().optional(),
      unavailableReason: z
        .enum([
          "timeout",
          "port_not_found",
          "port_in_use",
          "handshake_failed",
          "incompatible_version",
          "transport_closed",
        ])
        .optional(),
      cachedStatus: z
        .object({
          device: deviceShape,
        })
        .optional(),
      error: errorShape.optional(),
    },
  },
} as const;

export function createGatewayMcpServer(core = createDefaultGatewayCore()): McpServer {
  const server = new McpServer({
    name: "agent-q-gateway",
    version: "0.0.0",
  });

  server.registerTool(
    gatewayToolDefinitions.scanDevices.name,
    {
      title: "Scan devices",
      description: "Find USB-connected Agent-Q Firmware devices.",
      inputSchema: gatewayToolDefinitions.scanDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.scanDevices.outputSchema,
    },
    async ({ timeoutMs }) => {
      try {
        const structuredContent = await core.scanDevices({ timeoutMs });
        return withStructuredContent(structuredContent);
      } catch (error) {
        const structuredContent = toErrorToolResult(toGatewayError(error));
        return withStructuredContent(structuredContent, true);
      }
    },
  );

  server.registerTool(
    gatewayToolDefinitions.identifyDevices.name,
    {
      title: "Identify devices",
      description: "Ask discovered Agent-Q Firmware devices to display short identification codes.",
      inputSchema: gatewayToolDefinitions.identifyDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.identifyDevices.outputSchema,
    },
    async ({ timeoutMs, durationMs }) => {
      try {
        const structuredContent = await core.identifyDevices({ timeoutMs, durationMs });
        return withStructuredContent(structuredContent);
      } catch (error) {
        const structuredContent = toErrorToolResult(toGatewayError(error));
        return withStructuredContent(structuredContent, true);
      }
    },
  );

  server.registerTool(
    gatewayToolDefinitions.selectDevice.name,
    {
      title: "Select device",
      description: "Set one previously discovered Agent-Q Firmware device as the active device.",
      inputSchema: gatewayToolDefinitions.selectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.selectDevice.outputSchema,
    },
    async ({ deviceId }) => {
      try {
        const structuredContent = await core.selectDevice({ deviceId });
        return withStructuredContent(structuredContent);
      } catch (error) {
        const structuredContent = toErrorToolResult(toGatewayError(error));
        return withStructuredContent(structuredContent, true);
      }
    },
  );

  server.registerTool(
    gatewayToolDefinitions.getDeviceStatus.name,
    {
      title: "Get device status",
      description: "Read live or cached status for a known Agent-Q Firmware device.",
      inputSchema: gatewayToolDefinitions.getDeviceStatus.inputSchema,
      outputSchema: gatewayToolDefinitions.getDeviceStatus.outputSchema,
    },
    async ({ deviceId }) => {
      try {
        const structuredContent = await core.getDeviceStatus({ deviceId });
        return withStructuredContent(structuredContent);
      } catch (error) {
        const structuredContent = toErrorToolResult(toGatewayError(error));
        return withStructuredContent(structuredContent, true);
      }
    },
  );

  return server;
}

export async function startStdioGateway(): Promise<void> {
  const server = createGatewayMcpServer();
  await server.connect(new StdioServerTransport());
}

function createDefaultGatewayCore(): GatewayCore {
  return new GatewayCore(new ConfigStore(), new SerialPortUsbDriver());
}

function withStructuredContent(structuredContent: DeviceStatusToolResult | object, isError = false) {
  return {
    isError,
    structuredContent: structuredContent as Record<string, unknown>,
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(structuredContent, null, 2),
      },
    ],
  };
}
