import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";
import { createDefaultGatewayCore } from "@stelis/agent-q-client/admin";
import {
  GatewayCore,
  type ConnectDeviceResult,
  type DeviceListResult,
  type DeviceStatusToolResult,
  type DisconnectDeviceResult,
  type GetAccountsResult,
  type GetApprovalHistoryResult,
  type GetCapabilitiesResult,
  type PolicyGetResult,
  type PolicyProposeResult,
  type SetDeviceMetadataResult,
  type SignPersonalMessageResult,
  type SignTransactionResult,
} from "@stelis/agent-q-client/admin";
import {
  DEVICE_ID_PATTERN,
  GATEWAY_NAME_PATTERN,
  GatewayError,
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
  toGatewayError,
  toPublicError,
} from "@stelis/agent-q-client/adapter-internal";
import {
  MAX_APPROVAL_HISTORY_RECORDS,
  UINT_DECIMAL_STRING_PATTERN,
  isUint64DecimalString,
} from "@stelis/agent-q-client/protocol";

// Input purpose uses the same SoT predicate as egress, so reserved ("default")
// and prototype-sensitive ("__proto__"/"prototype"/"constructor") names are
// rejected at the request boundary as well as in storage and output.
const purposeSchema = z.string().regex(PURPOSE_PATTERN).refine((value) => isValidPurpose(value), {
  message: "purpose must be 1-32 characters of [A-Za-z0-9_.-] and not a reserved or prototype-sensitive name.",
});

function strictInputSchema<Shape extends z.ZodRawShape>(shape: Shape) {
  return z.object(shape).strict();
}

export const gatewayToolDefinitions = {
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
      "Set a previously discovered Agent-Q Firmware device as the default active device, or as the active device for a named routing purpose. 'purpose' is local Gateway routing metadata, not security policy. Updates local Gateway state only; does not contact Firmware.",
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
    // outputSchema (full union) is for Gateway-side tests only; it is not
    // registered with the SDK. successOutputSchema (live | cached) is the
    // runtime sanitize boundary used by run().
    outputSchema: getDeviceStatusToolOutputShape,
    successOutputSchema: getDeviceStatusSuccessOutputShape,
  },
  listDevices: {
    name: "list_devices",
    title: "List devices",
    description:
      "List Agent-Q Firmware devices known to Gateway, including Gateway-local label, purpose routing assignments, and any in-memory connection session metadata. Reads from local Gateway state only; does not contact Firmware.",
    inputSchema: strictInputSchema({}),
    outputSchema: listDevicesToolOutputShape,
    successOutputSchema: listDevicesSuccessOutputShape,
  },
  setDeviceMetadata: {
    name: "set_device_metadata",
    title: "Set device metadata",
    description:
      "Set Gateway-local metadata for a known Agent-Q Firmware device. 'label' is human-readable Gateway-local metadata, not a security boundary and not device authority. Pass null to clear the label. Updates local Gateway state only; does not contact Firmware.",
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
      "Open a communication session with a known Agent-Q Firmware device. Resolves the target device by deviceId, by purpose, or by the default active device. Sends a connect request that requires Firmware-owned device-local approval. Writes a status handshake to candidate USB serial ports while locating the device. Connect is not signing approval and does not authorize signing. Session is held in Gateway memory only.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      gatewayName: z.string().regex(GATEWAY_NAME_PATTERN).optional(),
    }),
    outputSchema: connectDeviceToolOutputShape,
    successOutputSchema: connectDeviceSuccessOutputShape,
  },
  disconnectDevice: {
    name: "disconnect_device",
    title: "Disconnect device",
    description:
      "End a previously approved Agent-Q Firmware session. Resolves the target device by deviceId, by purpose, or by the default active device. Returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. Writes a status handshake to candidate USB serial ports when locating the device. Disconnect does not require physical approval.",
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
      "Read Firmware-authored supported chains, public account schemes, and supported signing methods over an approved session. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. signing.authorization is Firmware-authored read-only state and is not a request option.",
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
      "List the public accounts (chain, address, public key) held by a provisioned Agent-Q Firmware device over an approved session. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. Read-only: no signing, no private material, and no session id is ever returned.",
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
      "Read the Firmware-owned active policy summary over an approved session. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. Read-only: no policy update, no signing, no private material, and no session id is ever returned.",
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
      "Read a bounded page of Firmware-owned approval history over an approved session. This is not on-chain history and is read-only: no raw requests, session ids, private material, PINs, gateway names, or full policy documents are returned.",
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
      "Request a Firmware-owned transaction signature over an approved session. Gateway and MCP do not store keys, choose authorization, or make signing decisions; Firmware uses its local signing authorization mode to select policy authorization or user confirmation and returns sign_result.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      chain: z.literal("sui"),
      method: z.literal("sign_transaction"),
      network: z.enum(["mainnet", "testnet", "devnet", "localnet"]),
      txBytes: z.string(),
    }),
    outputSchema: signTransactionToolOutputShape,
    successOutputSchema: signTransactionSuccessOutputShape,
  },
  signPersonalMessage: {
    name: "sign_personal_message",
    title: "Sign personal message",
    description:
      "Request a Firmware-owned Sui personal-message signature over an approved session. Gateway and MCP do not store keys, choose authorization, or make signing decisions. The current Firmware implementation signs this method only in user-confirmed authorization mode; policy authorization mode fails closed.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      chain: z.literal("sui"),
      method: z.literal("sign_personal_message"),
      network: z.enum(["mainnet", "testnet", "devnet", "localnet"]),
      message: z.string(),
    }),
    outputSchema: signPersonalMessageToolOutputShape,
    successOutputSchema: signPersonalMessageSuccessOutputShape,
  },
  policyPropose: {
    name: "policy_propose",
    title: "Propose policy update",
    description:
      "Submit a bounded active-policy proposal to Agent-Q Firmware for device-local PIN approval. This is a request path only: Gateway and MCP do not store, apply, or decide policy, and Firmware returns the terminal policy_propose_result.",
    inputSchema: strictInputSchema({
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      policy: z.object({}).passthrough(),
    }),
    outputSchema: policyProposeToolOutputShape,
    successOutputSchema: policyProposeSuccessOutputShape,
  },
} as const;

export function createGatewayMcpServer(core = createDefaultGatewayCore()): McpServer {
  const server = new McpServer({
    name: "agent-q-gateway",
    version: "0.0.0",
  });

  // run() is the single MCP output boundary. It sanitizes every result so that
  // structuredContent and the text mirror only ever carry schema-approved
  // fields, and so that error output never echoes a raw (possibly
  // device/OS-originated) message back to the untrusted client.
  //
  //   work succeeds       -> successSchema.parse() strips unknown fields
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
      const gatewayError = toGatewayError(error);
      logToolDiagnostic("gateway_tool_error", gatewayError.code, gatewayError.retryable);
      return withStructuredContent(toPublicErrorToolResult(gatewayError), true);
    }

    let sanitized: object;
    try {
      sanitized = successSchema.parse(raw);
    } catch {
      // An unsanitizable success is an internal contract bug. Surface a fixed
      // generic error instead of the raw value or the ZodError details.
      logToolDiagnostic("gateway_output_sanitize_failed", "internal_output_error", false);
      return withStructuredContent(
        toPublicErrorToolResult(new GatewayError("internal_output_error", "", false)),
        true,
      );
    }
    return withStructuredContent(sanitized);
  };

  // For the tools below the registered SDK outputSchema is the success-only
  // object shape. Error results carry `isError: true`, for which the SDK skips
  // output validation, so the error variant is intentionally absent there.
  server.registerTool(
    gatewayToolDefinitions.scanDevices.name,
    {
      title: gatewayToolDefinitions.scanDevices.title,
      description: gatewayToolDefinitions.scanDevices.description,
      inputSchema: gatewayToolDefinitions.scanDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.scanDevices.successOutputSchema,
    },
    async () =>
      run(gatewayToolDefinitions.scanDevices.successOutputSchema, () => core.scanDevices()),
  );

  server.registerTool(
    gatewayToolDefinitions.identifyDevices.name,
    {
      title: gatewayToolDefinitions.identifyDevices.title,
      description: gatewayToolDefinitions.identifyDevices.description,
      inputSchema: gatewayToolDefinitions.identifyDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.identifyDevices.successOutputSchema,
    },
    async () =>
      run({ parse: sanitizeIdentifyDevicesResult }, () => core.identifyDevices()),
  );

  server.registerTool(
    gatewayToolDefinitions.selectDevice.name,
    {
      title: gatewayToolDefinitions.selectDevice.title,
      description: gatewayToolDefinitions.selectDevice.description,
      inputSchema: gatewayToolDefinitions.selectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.selectDevice.successOutputSchema,
    },
    async ({ deviceId, purpose }) =>
      run(gatewayToolDefinitions.selectDevice.successOutputSchema, () => core.selectDevice({ deviceId, purpose })),
  );

  // get_device_status is the one tool without a registered SDK outputSchema
  // (success is a live | cached union). It is still sanitized at run() using
  // its success-only union, so an error-shaped result cannot leak as a success.
  server.registerTool(
    gatewayToolDefinitions.getDeviceStatus.name,
    {
      title: gatewayToolDefinitions.getDeviceStatus.title,
      description: gatewayToolDefinitions.getDeviceStatus.description,
      inputSchema: gatewayToolDefinitions.getDeviceStatus.inputSchema,
    },
    async ({ deviceId, purpose }) =>
      run({ parse: sanitizeGetDeviceStatusResult }, () =>
        core.getDeviceStatus({ deviceId, purpose }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.listDevices.name,
    {
      title: gatewayToolDefinitions.listDevices.title,
      description: gatewayToolDefinitions.listDevices.description,
      inputSchema: gatewayToolDefinitions.listDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.listDevices.successOutputSchema,
    },
    async () => run(gatewayToolDefinitions.listDevices.successOutputSchema, () => core.listDevices()),
  );

  server.registerTool(
    gatewayToolDefinitions.setDeviceMetadata.name,
    {
      title: gatewayToolDefinitions.setDeviceMetadata.title,
      description: gatewayToolDefinitions.setDeviceMetadata.description,
      inputSchema: gatewayToolDefinitions.setDeviceMetadata.inputSchema,
      outputSchema: gatewayToolDefinitions.setDeviceMetadata.successOutputSchema,
    },
    async ({ deviceId, label }) =>
      run(gatewayToolDefinitions.setDeviceMetadata.successOutputSchema, () =>
        core.setDeviceMetadata({ deviceId, label }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.connectDevice.name,
    {
      title: gatewayToolDefinitions.connectDevice.title,
      description: gatewayToolDefinitions.connectDevice.description,
      inputSchema: gatewayToolDefinitions.connectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.connectDevice.successOutputSchema,
    },
    async ({ deviceId, purpose, gatewayName }) =>
      run(gatewayToolDefinitions.connectDevice.successOutputSchema, () =>
        core.connectDevice({ deviceId, purpose, gatewayName }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.disconnectDevice.name,
    {
      title: gatewayToolDefinitions.disconnectDevice.title,
      description: gatewayToolDefinitions.disconnectDevice.description,
      inputSchema: gatewayToolDefinitions.disconnectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.disconnectDevice.successOutputSchema,
    },
    async ({ deviceId, purpose }) =>
      run(gatewayToolDefinitions.disconnectDevice.successOutputSchema, () =>
        core.disconnectDevice({ deviceId, purpose }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.getCapabilities.name,
    {
      title: gatewayToolDefinitions.getCapabilities.title,
      description: gatewayToolDefinitions.getCapabilities.description,
      inputSchema: gatewayToolDefinitions.getCapabilities.inputSchema,
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
    gatewayToolDefinitions.getAccounts.name,
    {
      title: gatewayToolDefinitions.getAccounts.title,
      description: gatewayToolDefinitions.getAccounts.description,
      inputSchema: gatewayToolDefinitions.getAccounts.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose }) =>
      run(gatewayToolDefinitions.getAccounts.successOutputSchema, () =>
        core.getAccounts({ deviceId, purpose }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.policyGet.name,
    {
      title: gatewayToolDefinitions.policyGet.title,
      description: gatewayToolDefinitions.policyGet.description,
      inputSchema: gatewayToolDefinitions.policyGet.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose }) =>
      run(gatewayToolDefinitions.policyGet.successOutputSchema, () =>
        core.policyGet({ deviceId, purpose }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.getApprovalHistory.name,
    {
      title: gatewayToolDefinitions.getApprovalHistory.title,
      description: gatewayToolDefinitions.getApprovalHistory.description,
      inputSchema: gatewayToolDefinitions.getApprovalHistory.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, limit, beforeSeq }) =>
      run(gatewayToolDefinitions.getApprovalHistory.successOutputSchema, () =>
        core.getApprovalHistory({ deviceId, purpose, limit, beforeSeq }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.signTransaction.name,
    {
      title: gatewayToolDefinitions.signTransaction.title,
      description: gatewayToolDefinitions.signTransaction.description,
      inputSchema: gatewayToolDefinitions.signTransaction.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, chain, method, network, txBytes }) =>
      run(gatewayToolDefinitions.signTransaction.successOutputSchema, () =>
        core.signTransaction({ deviceId, purpose, chain: chain as "sui", method: method as "sign_transaction", network, txBytes }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.signPersonalMessage.name,
    {
      title: gatewayToolDefinitions.signPersonalMessage.title,
      description: gatewayToolDefinitions.signPersonalMessage.description,
      inputSchema: gatewayToolDefinitions.signPersonalMessage.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, chain, method, network, message }) =>
      run(gatewayToolDefinitions.signPersonalMessage.successOutputSchema, () =>
        core.signPersonalMessage({
          deviceId,
          purpose,
          chain: chain as "sui",
          method: method as "sign_personal_message",
          network,
          message,
        }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.policyPropose.name,
    {
      title: gatewayToolDefinitions.policyPropose.title,
      description: gatewayToolDefinitions.policyPropose.description,
      inputSchema: gatewayToolDefinitions.policyPropose.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, policy }) =>
      run(gatewayToolDefinitions.policyPropose.successOutputSchema, () =>
        core.policyPropose({ deviceId, purpose, policy }),
      ),
  );

  return server;
}

export async function startStdioGateway(
  core = createDefaultGatewayCore(),
  options: { onClose?: () => void } = {},
): Promise<void> {
  const server = createGatewayMcpServer(core);
  const transport = new StdioServerTransport();
  if (options.onClose !== undefined) {
    transport.onclose = options.onClose;
  }
  await server.connect(transport);
}

// Operator-facing diagnostic on stderr (never stdout, which is the MCP JSON-RPC
// channel). Carries only allowlisted, Gateway-authored fields: the normalized
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
function toPublicErrorToolResult(error: GatewayError) {
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
// It is a code, not a message: normalize unknown codes to `gateway_error` and
// attach no message (unlike an error object).
function sanitizeGetDeviceStatusResult(raw: unknown): object {
  // Normalize the Firmware diagnostic code BEFORE schema validation so an unknown
  // or raw code becomes gateway_error rather than failing the now allowlist-
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
