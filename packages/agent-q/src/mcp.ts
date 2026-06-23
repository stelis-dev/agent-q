import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";
import { createDefaultAgentQCore } from "@stelis/agent-q-core";
import {
  type ConnectDeviceResult,
  type DeviceListResult,
  type DeviceStatusToolResult,
  type DisconnectDeviceResult,
  type GetAccountsResult,
  type GetApprovalHistoryResult,
  type GetCapabilitiesResult,
  type PolicyGetResult,
  type SetDeviceMetadataResult,
  type SignPersonalMessageResult,
  type SignTransactionResult,
} from "@stelis/agent-q-core";
import {
  DEVICE_ID_PATTERN,
  CLIENT_NAME_PATTERN,
  AgentQError,
  MAX_LABEL_LENGTH,
  PUBLIC_ERROR_MESSAGES,
  PURPOSE_PATTERN,
  connectDeviceSuccessOutputShape,
  connectDeviceToolOutputShape,
  disconnectDeviceSuccessOutputShape,
  disconnectDeviceToolOutputShape,
  errorToolResultShape,
  getAccountsSuccessOutputShape,
  getAccountsToolOutputShape,
  getApprovalHistorySuccessOutputShape,
  getApprovalHistoryToolOutputShape,
  mcpGetCapabilitiesSuccessOutputShape,
  mcpGetCapabilitiesToolOutputShape,
  getDeviceStatusSuccessOutputShape,
  getDeviceStatusToolOutputShape,
  policyGetSuccessOutputShape,
  policyGetToolOutputShape,
  identifyDevicesSuccessOutputShape,
  identifyDevicesToolOutputShape,
  listDevicesSuccessOutputShape,
  listDevicesToolOutputShape,
  policyProposeSuccessOutputShape,
  policyProposeToolOutputShape,
  scanDevicesSuccessOutputShape,
  scanDevicesToolOutputShape,
  selectDeviceSuccessOutputShape,
  selectDeviceToolOutputShape,
  setDeviceMetadataSuccessOutputShape,
  setDeviceMetadataToolOutputShape,
  signPersonalMessageSuccessOutputShape,
  signPersonalMessageToolOutputShape,
  signTransactionSuccessOutputShape,
  signTransactionToolOutputShape,
  isValidLabel,
  isValidPurpose,
  normalizeErrorCode,
  toAgentQError,
  toPublicError,
} from "@stelis/agent-q-core/adapter-internal";
import {
  MAX_APPROVAL_HISTORY_RECORDS,
  SIGN_CHAIN_PATTERN,
  SIGN_METHOD_PATTERN,
  UINT_DECIMAL_STRING_PATTERN,
  isUint64DecimalString,
} from "@stelis/agent-q-core/protocol";

// Input purpose uses the same SoT predicate as egress, so reserved ("default")
// and prototype-sensitive ("__proto__"/"prototype"/"constructor") names are
// rejected at the request boundary as well as in storage and output.
const purposeSchema = z.string().regex(PURPOSE_PATTERN).refine((value) => isValidPurpose(value), {
  message: "purpose must be 1-32 characters of [A-Za-z0-9_.-] and not a reserved or prototype-sensitive name.",
});
const signNetworkSchema = z.string().describe(
  "Network identifier for the selected chain and method. Current executable Sui signing accepts mainnet, testnet, devnet, or localnet; Client Core and Firmware validate the value.",
);

const requirePackageJson = createRequire(import.meta.url);

function readAgentQMcpServerVersion(): string {
  const packageJson = requirePackageJson("../package.json") as { version?: unknown };
  if (typeof packageJson.version !== "string" || packageJson.version.length === 0) {
    throw new Error("@stelis/agent-q package.json must define a non-empty version");
  }
  return packageJson.version;
}

const AGENT_Q_MCP_SERVER_VERSION = readAgentQMcpServerVersion();

function strictInputSchema<Shape extends z.ZodRawShape>(shape: Shape) {
  return z.object(shape).strict();
}

export const hostToolDefinitions = {
  scanDevices: {
    name: "scan_devices",
    title: "Scan devices",
    description:
      "Find USB-connected Agent-Q Firmware devices by writing a status handshake to candidate USB serial ports, and report sanitized candidate failure reasons.",
    inputSchema: strictInputSchema({}),
    outputSchema: scanDevicesToolOutputShape,
    successOutputSchema: scanDevicesSuccessOutputShape,
  },
  identifyDevices: {
    name: "identify_devices",
    title: "Identify devices",
    description:
      "Ask discovered Agent-Q Firmware devices to display short identification codes. Writes a status handshake to candidate USB serial ports before sending the identify request.",
    inputSchema: strictInputSchema({}),
    outputSchema: identifyDevicesToolOutputShape,
    successOutputSchema: identifyDevicesSuccessOutputShape,
  },
  selectDevice: {
    name: "select_device",
    title: "Select device",
    description:
      "Set a previously discovered Agent-Q Firmware device as the default active device, or as the active device for a named routing purpose. 'purpose' is local Agent-Q process routing metadata, not security policy. Updates local Agent-Q process state only; does not contact Firmware.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN),
      purpose: purposeSchema.optional(),
    }),
    outputSchema: selectDeviceToolOutputShape,
    successOutputSchema: selectDeviceSuccessOutputShape,
  },
  getDeviceStatus: {
    name: "get_device_status",
    title: "Get device status",
    description:
      "Read live or cached status for a known Agent-Q Firmware device by writing a status handshake to candidate USB serial ports. Resolves the device by deviceId, by purpose, or by the default active device.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
    }),
    // outputSchema (full union) is for host-side tests only; it is not
    // registered with the SDK. successOutputSchema (live | cached) is the
    // runtime sanitize boundary used by run().
    outputSchema: getDeviceStatusToolOutputShape,
    successOutputSchema: getDeviceStatusSuccessOutputShape,
  },
  listDevices: {
    name: "list_devices",
    title: "List devices",
    description:
      "List Agent-Q Firmware devices known to Agent-Q, including local label, purpose routing assignments, and any in-memory connection session metadata. Reads from local Agent-Q process state only; does not contact Firmware.",
    inputSchema: strictInputSchema({}),
    outputSchema: listDevicesToolOutputShape,
    successOutputSchema: listDevicesSuccessOutputShape,
  },
  setDeviceMetadata: {
    name: "set_device_metadata",
    title: "Set device metadata",
    description:
      "Set local metadata for a known Agent-Q Firmware device. 'label' is human-readable local metadata, not a security boundary and not device authority. Pass null to clear the label. Updates local Agent-Q process state only; does not contact Firmware.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN),
      label: z.union([z.string().max(MAX_LABEL_LENGTH).refine((value) => isValidLabel(value)), z.null()]),
    }),
    outputSchema: setDeviceMetadataToolOutputShape,
    successOutputSchema: setDeviceMetadataSuccessOutputShape,
  },
  connectDevice: {
    name: "connect_device",
    title: "Connect device",
    description:
      "Open a communication session with a known Agent-Q Firmware device. Resolves the target device by deviceId, by purpose, or by the default active device. Sends a connect request that requires Firmware-owned device-local approval. Writes a status handshake to candidate USB serial ports while locating the device. Connect is not signing approval and does not authorize signing. Session is held in Agent-Q process memory only.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      clientName: z.string().regex(CLIENT_NAME_PATTERN).optional(),
    }),
    outputSchema: connectDeviceToolOutputShape,
    successOutputSchema: connectDeviceSuccessOutputShape,
  },
  disconnectDevice: {
    name: "disconnect_device",
    title: "Disconnect device",
    description:
      "End a previously approved Agent-Q Firmware session. Resolves the target device by deviceId, by purpose, or by the default active device. Returns 'not_connected' without contacting Firmware when there is no Agent-Q runtime session. Writes a status handshake to candidate USB serial ports when locating the device. Disconnect does not require physical approval.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
    }),
    outputSchema: disconnectDeviceToolOutputShape,
    successOutputSchema: disconnectDeviceSuccessOutputShape,
  },
  getCapabilities: {
    name: "get_capabilities",
    title: "Get capabilities",
    description:
      "Read Firmware-authored supported chains, public account schemes, and supported signing methods over an approved session. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Agent-Q runtime session. signing.authorization is Firmware-authored read-only state and is not a request option.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
    }),
    outputSchema: mcpGetCapabilitiesToolOutputShape,
    successOutputSchema: mcpGetCapabilitiesSuccessOutputShape,
  },
  getAccounts: {
    name: "get_accounts",
    title: "Get accounts",
    description:
      "List the public accounts (chain, address, public key) held by a provisioned Agent-Q Firmware device over an approved session. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Agent-Q runtime session. Read-only: no signing, no private material, and no session id is ever returned.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
    }),
    outputSchema: getAccountsToolOutputShape,
    successOutputSchema: getAccountsSuccessOutputShape,
  },
  policyGet: {
    name: "policy_get",
    title: "Get policy",
    description:
      "Read the Firmware-owned active policy document over an approved session. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Agent-Q runtime session. Read-only: no policy update, no signing, no private material, and no session id is ever returned.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
    }),
    outputSchema: policyGetToolOutputShape,
    successOutputSchema: policyGetSuccessOutputShape,
  },
  getApprovalHistory: {
    name: "get_approval_history",
    title: "Get approval history",
    description:
      "Read a bounded page of Firmware-owned approval history over an approved session. This is not on-chain history and is read-only: no raw requests, session ids, private material, PINs, client names, or full policy documents are returned.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      limit: z.number().int().positive().max(MAX_APPROVAL_HISTORY_RECORDS).optional(),
      beforeSeq: z.string().regex(UINT_DECIMAL_STRING_PATTERN).refine((value) => isUint64DecimalString(value)).optional(),
    }),
    outputSchema: getApprovalHistoryToolOutputShape,
    successOutputSchema: getApprovalHistorySuccessOutputShape,
  },
  signTransaction: {
    name: "sign_transaction",
    title: "Sign transaction",
    description:
      "Request a Firmware-owned transaction signature over an approved session. Agent-Q and MCP do not store keys, choose authorization, or make signing decisions; Firmware uses its local signing authorization mode to select policy authorization or user confirmation and returns sign_result.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      chain: z.string().regex(SIGN_CHAIN_PATTERN),
      method: z.string().regex(SIGN_METHOD_PATTERN),
      network: signNetworkSchema,
      txBytes: z.string(),
    }),
    outputSchema: signTransactionToolOutputShape,
    successOutputSchema: signTransactionSuccessOutputShape,
  },
  signPersonalMessage: {
    name: "sign_personal_message",
    title: "Sign personal message",
    description:
      "Request a Firmware-owned Sui personal-message signature over an approved session. Agent-Q and MCP do not store keys, choose authorization, or make signing decisions. The current Firmware implementation signs this method only in user-confirmed authorization mode; policy authorization mode fails closed.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      chain: z.string().regex(SIGN_CHAIN_PATTERN),
      method: z.string().regex(SIGN_METHOD_PATTERN),
      network: signNetworkSchema,
      message: z.string(),
    }),
    outputSchema: signPersonalMessageToolOutputShape,
    successOutputSchema: signPersonalMessageSuccessOutputShape,
  },
  policyPropose: {
    name: "policy_propose",
    title: "Propose policy update",
    description:
      "Submit a bounded current-schema active-policy proposal to Agent-Q Firmware. Firmware validates the proposal, shows a device-local policy summary review, starts local PIN approval only after device-local Continue, and returns the terminal policy_propose_result. This is a request path only: Agent-Q and MCP do not store, apply, or decide policy.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      policy: z.object({}).passthrough(),
    }),
    outputSchema: policyProposeToolOutputShape,
    successOutputSchema: policyProposeSuccessOutputShape,
  },
} as const;

export function createAgentQMcpServer(core = createDefaultAgentQCore()): McpServer {
  const server = new McpServer({
    name: "agent-q",
    version: AGENT_Q_MCP_SERVER_VERSION,
  });

  // run() is the single MCP output boundary. It sanitizes every result so that
  // structuredContent and the text mirror only ever carry schema-approved
  // fields, and so that error output never echoes a raw (possibly
  // device/OS-originated) message back to the untrusted client.
  //
  //   work succeeds       -> successSchema.parse() accepts the exact success shape
  //   work throws         -> canonical public error keyed by error code
  //   sanitize fails      -> fixed internal_output_error (never the raw ZodError)
  const run = async (
    successSchema: { parse: (raw: unknown) => object },
    work: () => Promise<unknown>,
  ) => {
    let raw: unknown;
    try {
      raw = await work();
    } catch (error) {
      const agentQError = toAgentQError(error);
      logToolDiagnostic("agent_q_tool_error", agentQError.code, agentQError.retryable);
      return withStructuredContent(toPublicErrorToolResult(agentQError), true);
    }

    let sanitized: object;
    try {
      sanitized = successSchema.parse(raw);
    } catch {
      // An unsanitizable success is an internal contract bug. Surface a fixed
      // generic error instead of the raw value or the ZodError details.
      logToolDiagnostic("agent_q_output_sanitize_failed", "internal_output_error", false);
      return withStructuredContent(
        toPublicErrorToolResult(new AgentQError("internal_output_error", "", false)),
        true,
      );
    }
    return withStructuredContent(sanitized);
  };

  // For the tools below the registered SDK outputSchema is the success-only
  // object shape. Error results carry `isError: true`, for which the SDK skips
  // output validation, so the error variant is absent there.
  server.registerTool(
    hostToolDefinitions.scanDevices.name,
    {
      title: hostToolDefinitions.scanDevices.title,
      description: hostToolDefinitions.scanDevices.description,
      inputSchema: hostToolDefinitions.scanDevices.inputSchema,
      outputSchema: hostToolDefinitions.scanDevices.successOutputSchema,
    },
    async () =>
      run(hostToolDefinitions.scanDevices.successOutputSchema, () => core.scanDevices()),
  );

  server.registerTool(
    hostToolDefinitions.identifyDevices.name,
    {
      title: hostToolDefinitions.identifyDevices.title,
      description: hostToolDefinitions.identifyDevices.description,
      inputSchema: hostToolDefinitions.identifyDevices.inputSchema,
      outputSchema: hostToolDefinitions.identifyDevices.successOutputSchema,
    },
    async () =>
      run({ parse: sanitizeIdentifyDevicesResult }, () => core.identifyDevices()),
  );

  server.registerTool(
    hostToolDefinitions.selectDevice.name,
    {
      title: hostToolDefinitions.selectDevice.title,
      description: hostToolDefinitions.selectDevice.description,
      inputSchema: hostToolDefinitions.selectDevice.inputSchema,
      outputSchema: hostToolDefinitions.selectDevice.successOutputSchema,
    },
    async ({ deviceId, purpose }) =>
      run(hostToolDefinitions.selectDevice.successOutputSchema, () => core.selectDevice({ deviceId, purpose })),
  );

  // get_device_status is the one tool without a registered SDK outputSchema
  // (success is a live | cached union). It is still sanitized at run() using
  // its success-only union, so an error-shaped result cannot leak as a success.
  server.registerTool(
    hostToolDefinitions.getDeviceStatus.name,
    {
      title: hostToolDefinitions.getDeviceStatus.title,
      description: hostToolDefinitions.getDeviceStatus.description,
      inputSchema: hostToolDefinitions.getDeviceStatus.inputSchema,
    },
    async ({ deviceId, purpose }) =>
      run({ parse: sanitizeGetDeviceStatusResult }, () =>
        core.getDeviceStatus({ deviceId, purpose }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.listDevices.name,
    {
      title: hostToolDefinitions.listDevices.title,
      description: hostToolDefinitions.listDevices.description,
      inputSchema: hostToolDefinitions.listDevices.inputSchema,
      outputSchema: hostToolDefinitions.listDevices.successOutputSchema,
    },
    async () => run(hostToolDefinitions.listDevices.successOutputSchema, () => core.listDevices()),
  );

  server.registerTool(
    hostToolDefinitions.setDeviceMetadata.name,
    {
      title: hostToolDefinitions.setDeviceMetadata.title,
      description: hostToolDefinitions.setDeviceMetadata.description,
      inputSchema: hostToolDefinitions.setDeviceMetadata.inputSchema,
      outputSchema: hostToolDefinitions.setDeviceMetadata.successOutputSchema,
    },
    async ({ deviceId, label }) =>
      run(hostToolDefinitions.setDeviceMetadata.successOutputSchema, () =>
        core.setDeviceMetadata({ deviceId, label }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.connectDevice.name,
    {
      title: hostToolDefinitions.connectDevice.title,
      description: hostToolDefinitions.connectDevice.description,
      inputSchema: hostToolDefinitions.connectDevice.inputSchema,
      outputSchema: hostToolDefinitions.connectDevice.successOutputSchema,
    },
    async ({ deviceId, purpose, clientName }) =>
      run(hostToolDefinitions.connectDevice.successOutputSchema, () =>
        core.connectDevice({ deviceId, purpose, clientName }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.disconnectDevice.name,
    {
      title: hostToolDefinitions.disconnectDevice.title,
      description: hostToolDefinitions.disconnectDevice.description,
      inputSchema: hostToolDefinitions.disconnectDevice.inputSchema,
      outputSchema: hostToolDefinitions.disconnectDevice.successOutputSchema,
    },
    async ({ deviceId, purpose }) =>
      run(hostToolDefinitions.disconnectDevice.successOutputSchema, () =>
        core.disconnectDevice({ deviceId, purpose }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.getCapabilities.name,
    {
      title: hostToolDefinitions.getCapabilities.title,
      description: hostToolDefinitions.getCapabilities.description,
      inputSchema: hostToolDefinitions.getCapabilities.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose }) =>
      run({ parse: sanitizeMcpGetCapabilitiesResult }, () =>
        core.getCapabilities({ deviceId, purpose }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.getAccounts.name,
    {
      title: hostToolDefinitions.getAccounts.title,
      description: hostToolDefinitions.getAccounts.description,
      inputSchema: hostToolDefinitions.getAccounts.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose }) =>
      run(hostToolDefinitions.getAccounts.successOutputSchema, () =>
        core.getAccounts({ deviceId, purpose }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.policyGet.name,
    {
      title: hostToolDefinitions.policyGet.title,
      description: hostToolDefinitions.policyGet.description,
      inputSchema: hostToolDefinitions.policyGet.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose }) =>
      run(hostToolDefinitions.policyGet.successOutputSchema, () =>
        core.policyGet({ deviceId, purpose }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.getApprovalHistory.name,
    {
      title: hostToolDefinitions.getApprovalHistory.title,
      description: hostToolDefinitions.getApprovalHistory.description,
      inputSchema: hostToolDefinitions.getApprovalHistory.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, limit, beforeSeq }) =>
      run(hostToolDefinitions.getApprovalHistory.successOutputSchema, () =>
        core.getApprovalHistory({ deviceId, purpose, limit, beforeSeq }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.signTransaction.name,
    {
      title: hostToolDefinitions.signTransaction.title,
      description: hostToolDefinitions.signTransaction.description,
      inputSchema: hostToolDefinitions.signTransaction.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, chain, method, network, txBytes }) =>
      run(hostToolDefinitions.signTransaction.successOutputSchema, () =>
        core.signTransaction({
          deviceId,
          purpose,
          chain,
          method,
          network,
          txBytes,
        }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.signPersonalMessage.name,
    {
      title: hostToolDefinitions.signPersonalMessage.title,
      description: hostToolDefinitions.signPersonalMessage.description,
      inputSchema: hostToolDefinitions.signPersonalMessage.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, chain, method, network, message }) =>
      run(hostToolDefinitions.signPersonalMessage.successOutputSchema, () =>
        core.signPersonalMessage({
          deviceId,
          purpose,
          chain,
          method,
          network,
          message,
        }),
      ),
  );

  server.registerTool(
    hostToolDefinitions.policyPropose.name,
    {
      title: hostToolDefinitions.policyPropose.title,
      description: hostToolDefinitions.policyPropose.description,
      inputSchema: hostToolDefinitions.policyPropose.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, policy }) =>
      run(hostToolDefinitions.policyPropose.successOutputSchema, () =>
        core.policyPropose({ deviceId, purpose, policy }),
      ),
  );

  return server;
}

export async function startStdioMcpServer(
  core = createDefaultAgentQCore(),
  options: { onClose?: () => void } = {},
): Promise<void> {
  const server = createAgentQMcpServer(core);
  const transport = new StdioServerTransport();
  if (options.onClose !== undefined) {
    transport.onclose = options.onClose;
  }
  await server.connect(transport);
}

// Operator-facing diagnostic on stderr (never stdout, which is the MCP JSON-RPC
// channel). Carries only allowlisted, Agent-Q-authored fields: the normalized
// code, its canonical public message, and retryability. A raw device/OS/Firmware
// string is never logged — not even sanitized, because stripping control bytes is
// not redaction — so the string hazards closed at the MCP output boundary cannot
// reopen in host logs.
function logToolDiagnostic(event: string, rawCode: string, retryable: boolean): void {
  const code = normalizeErrorCode(rawCode);
  console.error(JSON.stringify({ event, code, retryable, message: PUBLIC_ERROR_MESSAGES[code] }));
}

/**
 * Build a client-safe top-level error result. Neither the code nor the message
 * can carry attacker- or device-controlled text to the MCP client.
 */
function toPublicErrorToolResult(error: AgentQError) {
  return errorToolResultShape.parse({
    source: "error",
    connected: false,
    error: toPublicError(error.code, error.retryable),
  });
}

// identify_devices reports per-device failures nested inside an otherwise
// successful result. Canonicalize each nested error with the same allowlist as
// the top-level path so Firmware/serial/OS raw text never reaches the client.
function sanitizeIdentifyDevicesResult(raw: unknown): object {
  // Canonicalize each nested per-device error BEFORE schema validation, so a raw
  // Firmware/serial/OS message becomes a public error rather than failing the
  // publicErrorShape-constrained schema. The real core already canonicalizes at
  // the source; this also covers a leaky adapter/mock input.
  let candidate = raw;
  if (typeof raw === "object" && raw !== null && Array.isArray((raw as { devices?: unknown }).devices)) {
    const record = raw as Record<string, unknown> & { devices: unknown[] };
    candidate = {
      ...record,
      devices: record.devices.map((device) => {
        if (typeof device === "object" && device !== null) {
          const entry = device as Record<string, unknown>;
          const error = entry.error as Record<string, unknown> | undefined;
          if (entry.source === "error" && error && typeof error.code === "string") {
            return { ...entry, error: toPublicError(error.code, error.retryable === true) };
          }
        }
        return device;
      }),
    };
  }
  return identifyDevicesSuccessOutputShape.parse(candidate);
}

// get_device_status cached results carry a Firmware-supplied diagnostic code.
// It is a code, not a message: normalize unknown codes to `agent_q_error` and
// attach no message (unlike an error object).
function sanitizeGetDeviceStatusResult(raw: unknown): object {
  // Normalize the Firmware diagnostic code BEFORE schema validation so an unknown
  // or raw code becomes agent_q_error rather than failing the now allowlist-
  // constrained firmwareErrorCode. It is a code, not a message: no message is
  // attached (unlike an error object).
  let candidate = raw;
  if (typeof raw === "object" && raw !== null) {
    const record = raw as Record<string, unknown>;
    if (record.source === "cached" && typeof record.firmwareErrorCode === "string") {
      candidate = { ...record, firmwareErrorCode: normalizeErrorCode(record.firmwareErrorCode) };
    }
  }
  return getDeviceStatusSuccessOutputShape.parse(candidate);
}

function sanitizeMcpGetCapabilitiesResult(raw: unknown): object {
  return mcpGetCapabilitiesSuccessOutputShape.parse(raw);
}

type StructuredToolResult =
  | DeviceStatusToolResult
  | DeviceListResult
  | SetDeviceMetadataResult
  | ConnectDeviceResult
  | SignTransactionResult
  | SignPersonalMessageResult
  | DisconnectDeviceResult
  | GetAccountsResult
  | GetApprovalHistoryResult
  | GetCapabilitiesResult
  | PolicyGetResult;

// Must only ever receive an already-sanitized success result or a public error
// result. Both structuredContent and the text mirror are derived from the same
// object, so sanitizing before this call closes the text path too.
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
