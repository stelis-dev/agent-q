import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";
import { ConfigStore, MAX_LABEL_LENGTH, PURPOSE_PATTERN } from "./config.js";
import {
  GatewayCore,
  MAX_IDENTIFY_DURATION_MS,
  toErrorToolResult,
  type ConnectDeviceResult,
  type DeviceListResult,
  type DeviceStatusToolResult,
  type DisconnectDeviceResult,
  type SetDeviceMetadataResult,
} from "./core.js";
import { toGatewayError } from "./errors.js";
import { MAX_APPROVAL_TIMEOUT_MS } from "./protocol.js";
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
  status: z.literal("displayed"),
  code: z.string(),
  protocolResponse: identifyResponseShape,
});

const failedIdentificationShape = z.object({
  source: z.literal("error"),
  connected: z.literal(false),
  portPath: z.string(),
  deviceId: z.string(),
  status: z.literal("error"),
  error: errorShape,
});

const errorToolResultShape = z.object({
  source: z.literal("error"),
  connected: z.literal(false),
  error: errorShape,
});

// sessionId is a Firmware-issued token held only inside Gateway. It is never
// exposed to MCP clients, which are untrusted request sources.
const runtimeSessionShape = z.object({
  sessionTtlMs: z.number().int().positive(),
  connectedAt: z.string(),
  expiresAt: z.string(),
});

const deviceListEntryShape = z.object({
  deviceId: z.string(),
  transport: z.literal("usb"),
  lastPortHint: z.string(),
  lastSeenAt: z.string(),
  label: z.string().nullable(),
  lastStatus: z.object({
    device: deviceShape,
  }),
  assignedPurposes: z.array(z.string()),
  isDefaultActive: z.boolean(),
  runtimeSession: runtimeSessionShape.nullable(),
});

const scanDevicesOutputShape = z.discriminatedUnion("source", [
  z.object({
    source: z.literal("live"),
    devices: z.array(liveStatusShape),
    activeDeviceId: z.string().nullable(),
  }),
  errorToolResultShape,
]);

const identifyDevicesOutputShape = z.discriminatedUnion("source", [
  z.object({
    source: z.literal("live"),
    devices: z.array(z.discriminatedUnion("source", [identifiedDeviceShape, failedIdentificationShape])),
    activeDeviceId: z.string().nullable(),
  }),
  errorToolResultShape,
]);

const selectDeviceOutputShape = z.discriminatedUnion("source", [
  z.object({
    source: z.literal("selected"),
    activeDeviceId: z.string(),
    purpose: z.string().nullable(),
    device: deviceShape,
  }),
  errorToolResultShape,
]);

const listDevicesOutputShape = z.discriminatedUnion("source", [
  z.object({
    source: z.literal("list"),
    devices: z.array(deviceListEntryShape),
    activeDeviceId: z.string().nullable(),
    activeDeviceIdsByPurpose: z.record(z.string(), z.string()),
  }),
  errorToolResultShape,
]);

const setDeviceMetadataOutputShape = z.discriminatedUnion("source", [
  z.object({
    source: z.literal("metadata"),
    deviceId: z.string(),
    label: z.string().nullable(),
  }),
  errorToolResultShape,
]);

const connectDeviceOutputShape = z.discriminatedUnion("source", [
  z.object({
    source: z.literal("connected"),
    deviceId: z.string(),
    reused: z.boolean(),
    sessionTtlMs: z.number().int().positive(),
    connectedAt: z.string(),
    expiresAt: z.string(),
    device: deviceShape,
  }),
  errorToolResultShape,
]);

const disconnectDeviceOutputShape = z.discriminatedUnion("source", [
  z.object({
    source: z.enum(["disconnected", "not_connected"]),
    deviceId: z.string(),
  }),
  errorToolResultShape,
]);

const getDeviceStatusOutputShape = z.discriminatedUnion("source", [
  liveStatusShape,
  z.object({
    source: z.literal("cached"),
    connected: z.literal(false),
    statusObservedAt: z.string(),
    unavailableReason: z.enum([
      "timeout",
      "port_not_found",
      "port_in_use",
      "handshake_failed",
      "incompatible_version",
      "transport_closed",
    ]),
    firmwareErrorCode: z.string().optional(),
    cachedStatus: z.object({
      device: deviceShape,
    }),
  }),
  errorToolResultShape,
]);

const purposeSchema = z.string().regex(PURPOSE_PATTERN).refine((value) => value !== "default", {
  message: "purpose 'default' is reserved.",
});

export const gatewayToolDefinitions = {
  scanDevices: {
    name: "scan_devices",
    title: "Scan devices",
    description:
      "Find USB-connected Agent-Q Firmware devices by writing a status handshake to candidate USB serial ports.",
    inputSchema: {
      timeoutMs: z.number().int().positive().max(MAX_SCAN_TIMEOUT_MS).optional(),
    },
    outputSchema: scanDevicesOutputShape,
  },
  identifyDevices: {
    name: "identify_devices",
    title: "Identify devices",
    description:
      "Ask discovered Agent-Q Firmware devices to display short identification codes. Writes a status handshake to candidate USB serial ports before sending the identify request.",
    inputSchema: {
      timeoutMs: z.number().int().positive().max(MAX_SCAN_TIMEOUT_MS).optional(),
      durationMs: z.number().int().positive().max(MAX_IDENTIFY_DURATION_MS).optional(),
    },
    outputSchema: identifyDevicesOutputShape,
  },
  selectDevice: {
    name: "select_device",
    title: "Select device",
    description:
      "Set a previously discovered Agent-Q Firmware device as the default active device, or as the active device for a named routing purpose. 'purpose' is local Gateway routing metadata, not security policy. Updates local Gateway state only; does not contact Firmware.",
    inputSchema: {
      deviceId: z.string().min(1),
      purpose: purposeSchema.optional(),
    },
    outputSchema: selectDeviceOutputShape,
  },
  getDeviceStatus: {
    name: "get_device_status",
    title: "Get device status",
    description:
      "Read live or cached status for a known Agent-Q Firmware device by writing a status handshake to candidate USB serial ports. Resolves the device by deviceId, by purpose, or by the default active device.",
    inputSchema: {
      deviceId: z.string().optional(),
      purpose: purposeSchema.optional(),
      timeoutMs: z.number().int().positive().max(MAX_SCAN_TIMEOUT_MS).optional(),
    },
    outputSchema: getDeviceStatusOutputShape,
  },
  listDevices: {
    name: "list_devices",
    title: "List devices",
    description:
      "List Agent-Q Firmware devices known to Gateway, including Gateway-local label, purpose routing assignments, and any in-memory connection session metadata. Reads from local Gateway state only; does not contact Firmware.",
    inputSchema: {},
    outputSchema: listDevicesOutputShape,
  },
  setDeviceMetadata: {
    name: "set_device_metadata",
    title: "Set device metadata",
    description:
      "Set Gateway-local metadata for a known Agent-Q Firmware device. 'label' is human-readable Gateway-local metadata, not a security boundary and not device authority. Pass null to clear the label. Updates local Gateway state only; does not contact Firmware.",
    inputSchema: {
      deviceId: z.string().min(1),
      label: z.union([z.string().min(1).max(MAX_LABEL_LENGTH), z.null()]),
    },
    outputSchema: setDeviceMetadataOutputShape,
  },
  connectDevice: {
    name: "connect_device",
    title: "Connect device",
    description:
      "Open a communication session with a known Agent-Q Firmware device. Resolves the target device by deviceId, by purpose, or by the default active device. Sends a connect request that requires physical approval on the device. Writes a status handshake to candidate USB serial ports while locating the device. Connect is not signing approval and does not authorize signing. Session is held in Gateway memory only.",
    inputSchema: {
      deviceId: z.string().min(1).optional(),
      purpose: purposeSchema.optional(),
      gatewayName: z.string().min(1).max(64).optional(),
      approvalTimeoutMs: z.number().int().positive().max(MAX_APPROVAL_TIMEOUT_MS).optional(),
      timeoutMs: z.number().int().positive().max(MAX_SCAN_TIMEOUT_MS).optional(),
    },
    outputSchema: connectDeviceOutputShape,
  },
  disconnectDevice: {
    name: "disconnect_device",
    title: "Disconnect device",
    description:
      "End a previously approved Agent-Q Firmware session. Resolves the target device by deviceId, by purpose, or by the default active device. Returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. Writes a status handshake to candidate USB serial ports when locating the device. Disconnect does not require physical approval.",
    inputSchema: {
      deviceId: z.string().min(1).optional(),
      purpose: purposeSchema.optional(),
      timeoutMs: z.number().int().positive().max(MAX_SCAN_TIMEOUT_MS).optional(),
    },
    outputSchema: disconnectDeviceOutputShape,
  },
} as const;

export function createGatewayMcpServer(core = createDefaultGatewayCore()): McpServer {
  const server = new McpServer({
    name: "agent-q-gateway",
    version: "0.0.0",
  });

  const run = async <T extends object>(work: () => Promise<T>) => {
    try {
      return withStructuredContent(await work());
    } catch (error) {
      return withStructuredContent(toErrorToolResult(toGatewayError(error)), true);
    }
  };

  server.registerTool(
    gatewayToolDefinitions.scanDevices.name,
    {
      title: gatewayToolDefinitions.scanDevices.title,
      description: gatewayToolDefinitions.scanDevices.description,
      inputSchema: gatewayToolDefinitions.scanDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.scanDevices.outputSchema,
    },
    async ({ timeoutMs }) => run(() => core.scanDevices({ timeoutMs })),
  );

  server.registerTool(
    gatewayToolDefinitions.identifyDevices.name,
    {
      title: gatewayToolDefinitions.identifyDevices.title,
      description: gatewayToolDefinitions.identifyDevices.description,
      inputSchema: gatewayToolDefinitions.identifyDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.identifyDevices.outputSchema,
    },
    async ({ timeoutMs, durationMs }) => run(() => core.identifyDevices({ timeoutMs, durationMs })),
  );

  server.registerTool(
    gatewayToolDefinitions.selectDevice.name,
    {
      title: gatewayToolDefinitions.selectDevice.title,
      description: gatewayToolDefinitions.selectDevice.description,
      inputSchema: gatewayToolDefinitions.selectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.selectDevice.outputSchema,
    },
    async ({ deviceId, purpose }) => run(() => core.selectDevice({ deviceId, purpose })),
  );

  server.registerTool(
    gatewayToolDefinitions.getDeviceStatus.name,
    {
      title: gatewayToolDefinitions.getDeviceStatus.title,
      description: gatewayToolDefinitions.getDeviceStatus.description,
      inputSchema: gatewayToolDefinitions.getDeviceStatus.inputSchema,
      outputSchema: gatewayToolDefinitions.getDeviceStatus.outputSchema,
    },
    async ({ deviceId, purpose, timeoutMs }) => run(() => core.getDeviceStatus({ deviceId, purpose, timeoutMs })),
  );

  server.registerTool(
    gatewayToolDefinitions.listDevices.name,
    {
      title: gatewayToolDefinitions.listDevices.title,
      description: gatewayToolDefinitions.listDevices.description,
      inputSchema: gatewayToolDefinitions.listDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.listDevices.outputSchema,
    },
    async () => run(() => core.listDevices()),
  );

  server.registerTool(
    gatewayToolDefinitions.setDeviceMetadata.name,
    {
      title: gatewayToolDefinitions.setDeviceMetadata.title,
      description: gatewayToolDefinitions.setDeviceMetadata.description,
      inputSchema: gatewayToolDefinitions.setDeviceMetadata.inputSchema,
      outputSchema: gatewayToolDefinitions.setDeviceMetadata.outputSchema,
    },
    async ({ deviceId, label }) => run(() => core.setDeviceMetadata({ deviceId, label })),
  );

  server.registerTool(
    gatewayToolDefinitions.connectDevice.name,
    {
      title: gatewayToolDefinitions.connectDevice.title,
      description: gatewayToolDefinitions.connectDevice.description,
      inputSchema: gatewayToolDefinitions.connectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.connectDevice.outputSchema,
    },
    async ({ deviceId, purpose, gatewayName, approvalTimeoutMs, timeoutMs }) =>
      run(() => core.connectDevice({ deviceId, purpose, gatewayName, approvalTimeoutMs, timeoutMs })),
  );

  server.registerTool(
    gatewayToolDefinitions.disconnectDevice.name,
    {
      title: gatewayToolDefinitions.disconnectDevice.title,
      description: gatewayToolDefinitions.disconnectDevice.description,
      inputSchema: gatewayToolDefinitions.disconnectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.disconnectDevice.outputSchema,
    },
    async ({ deviceId, purpose, timeoutMs }) => run(() => core.disconnectDevice({ deviceId, purpose, timeoutMs })),
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

type StructuredToolResult =
  | DeviceStatusToolResult
  | DeviceListResult
  | SetDeviceMetadataResult
  | ConnectDeviceResult
  | DisconnectDeviceResult;

function withStructuredContent(structuredContent: StructuredToolResult | object, isError = false) {
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
