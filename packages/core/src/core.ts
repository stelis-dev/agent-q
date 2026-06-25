import {
  ConfigError,
  ConfigStore,
  RESERVED_PURPOSES,
  isValidPurpose,
  type DeviceListing,
  type DeviceRecord,
} from "./config.js";
import { AgentQError, toAgentQError } from "./errors.js";
import { isClientName, isSafeDeviceId, sanitizePortHint } from "./safe-text.js";
import { normalizeErrorCode, toPublicError } from "./public-error.js";
import {
  identifySignRoute,
  validateSignPersonalMessageParams,
  validateSignTransactionParams,
} from "./provider-protocol.js";
import {
  INTERNAL_CONNECT_DEADLINE_MS,
  INTERNAL_DISCONNECT_DEADLINE_MS,
  INTERNAL_POLICY_UPDATE_DEADLINE_MS,
  INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS,
  INTERNAL_SIGN_TRANSACTION_DEADLINE_MS,
} from "./transport-invariants.js";
import { SerialPortUsbDriver } from "./usb.js";
export { SerialPortUsbDriver } from "./usb.js";
import {
  createIdentificationCode,
  type Account,
  type ApprovalHistoryRecord,
  type CapabilityChain,
  type ConnectResult,
  type CredentialCapability,
  type CredentialPreparationResponse,
  type CredentialProposalOutcomeResponse,
  type DeviceStatusSnapshot,
  type IdentifyDeviceResponse,
  type PolicyDocument,
  type PolicyProposalOutcomeResponse,
  ProtocolError,
  type SignPersonalMessageParams,
  type SigningOutcome,
  type SignTransactionParams,
  type SupportedSignRoute,
  type SigningCapabilities,
  type StatusResponse,
  validateApprovalHistoryInput,
  validateCredentialPrepareInput,
  validateCredentialPrepareRequestInput,
  validateCredentialProposeInput,
  validateCredentialProposeRequestInput,
  validatePolicyProposeInput,
  validatePolicyProposeRequestInput,
} from "./protocol.js";
import {
  consumeFirmwareSessionInvalidated,
  INTERNAL_USB_DEADLINE_MS,
  deadlineEnforcingDriver,
  mapErrorToUnavailableReason,
  scanUsbDeviceStatuses,
  scanUsbDevices,
  type UnavailableReason,
  type UsbSerialDriver,
  type UsbStatusFailure,
  type UsbStatusResult,
} from "./usb.js";

export interface LiveDeviceStatus {
  source: "live";
  connected: true;
  portPath: string;
  status: StatusResponse;
}

export interface CachedDeviceStatus {
  source: "cached";
  connected: false;
  statusObservedAt: string;
  unavailableReason: UnavailableReason;
  firmwareErrorCode?: string;
  cachedStatus: DeviceStatusSnapshot;
}

export type DeviceStatusResult = LiveDeviceStatus | CachedDeviceStatus;
// getDeviceStatus only ever returns a live or cached result, or throws; it never
// returns an error-shaped value. The error surfaces as a thrown AgentQError that
// the adapter boundary (run()) projects through public-error.ts.
export type DeviceStatusToolResult = DeviceStatusResult;

export interface ScanDevicesResult {
  source: "live";
  devices: LiveDeviceStatus[];
  failures: ScanDeviceFailure[];
  activeDeviceId: string | null;
}

export interface ScanDeviceFailure {
  source: "error";
  connected: false;
  portPath: string;
  unavailableReason: UnavailableReason;
  firmwareErrorCode?: string;
}

export interface IdentifiedDevice {
  source: "live";
  connected: true;
  portPath: string;
  code: string;
  device: IdentifyDeviceResponse["device"];
}

export interface IdentifyDeviceFailure {
  source: "error";
  connected: false;
  portPath: string;
  deviceId: string;
  status: "error";
  error: {
    code: string;
    message: string;
    retryable: boolean;
  };
}

export interface IdentifyDevicesResult {
  source: "live";
  devices: Array<IdentifiedDevice | IdentifyDeviceFailure>;
  activeDeviceId: string | null;
}

export interface SelectDeviceResult {
  source: "selected";
  activeDeviceId: string;
  purpose: string | null;
  device: StatusResponse["device"];
}

interface RuntimeSession {
  deviceId: string;
  sessionId: string;
  sessionTtlMs: number;
  connectedAt: string;
}

export interface RuntimeSessionView {
  sessionTtlMs: number;
  connectedAt: string;
}

export interface DeviceListEntry extends DeviceListing {
  runtimeSession: RuntimeSessionView | null;
}

export interface DeviceListResult {
  source: "list";
  devices: DeviceListEntry[];
  activeDeviceId: string | null;
  activeDeviceIdsByPurpose: Record<string, string>;
}

export interface SetDeviceMetadataResult {
  source: "metadata";
  deviceId: string;
  label: string | null;
}

export interface ConnectDeviceResult {
  source: "connected";
  deviceId: string;
  sessionTtlMs: number;
  connectedAt: string;
  device: StatusResponse["device"];
}

// Why a disconnect ended (or did not establish) Agent-Q's local session view.
// Single-sourced so the MCP output schema enumerates exactly these values and a
// different output adapter cannot invent its own.
export const DISCONNECT_REASONS = [
  "firmware_confirmed",
  "invalid_session",
  "transport_unavailable",
  "timeout",
  "not_connected",
] as const;
export type DisconnectReason = (typeof DISCONNECT_REASONS)[number];

export const DISCONNECT_ENDED_REASONS = [
  "firmware_confirmed",
  "invalid_session",
  "transport_unavailable",
  "timeout",
] as const;
export type DisconnectEndedReason = (typeof DISCONNECT_ENDED_REASONS)[number];

export const GET_ACCOUNTS_SESSION_ENDED_REASONS = [
  "invalid_session",
  "transport_unavailable",
  "timeout",
] as const;
export type GetAccountsSessionEndedReason = (typeof GET_ACCOUNTS_SESSION_ENDED_REASONS)[number];

export const GET_CAPABILITIES_SESSION_ENDED_REASONS = GET_ACCOUNTS_SESSION_ENDED_REASONS;
export type GetCapabilitiesSessionEndedReason = GetAccountsSessionEndedReason;
export const POLICY_GET_SESSION_ENDED_REASONS = GET_ACCOUNTS_SESSION_ENDED_REASONS;
export type PolicyGetSessionEndedReason = GetAccountsSessionEndedReason;
export const GET_APPROVAL_HISTORY_SESSION_ENDED_REASONS = GET_ACCOUNTS_SESSION_ENDED_REASONS;
export type GetApprovalHistorySessionEndedReason = GetAccountsSessionEndedReason;
export const POLICY_PROPOSE_SESSION_ENDED_REASONS = GET_ACCOUNTS_SESSION_ENDED_REASONS;
export type PolicyProposeSessionEndedReason = GetAccountsSessionEndedReason;
export const SIGN_TRANSACTION_SESSION_ENDED_REASONS = GET_ACCOUNTS_SESSION_ENDED_REASONS;
export type SignTransactionSessionEndedReason = GetAccountsSessionEndedReason;
export const SIGN_PERSONAL_MESSAGE_SESSION_ENDED_REASONS = GET_ACCOUNTS_SESSION_ENDED_REASONS;
export type SignPersonalMessageSessionEndedReason = GetAccountsSessionEndedReason;
type RuntimeSessionMirrorEndReason = GetAccountsSessionEndedReason;

export type DisconnectDeviceResult =
  | { source: "disconnected"; deviceId: string; reason: DisconnectEndedReason }
  | { source: "not_connected"; deviceId: string; reason: "not_connected" };

// get_capabilities is read-only and session-scoped. The returned capability set
// is Firmware-authored; Agent-Q only transports and validates it.
export type GetCapabilitiesResult =
  | {
      source: "live";
      deviceId: string;
      capabilities: CapabilityChain[];
      signing?: SigningCapabilities;
      credentials?: CredentialCapability[];
    }
  | { source: "not_connected"; deviceId: string; reason: "not_connected" }
  | { source: "session_ended"; deviceId: string; reason: GetCapabilitiesSessionEndedReason };

// get_accounts is read-only and session-scoped. "live" carries the public
// accounts; "not_connected"/"session_ended" carry only a reason (no accounts),
// mirroring disconnect's session-lifecycle reporting. No session id or private
// material is ever included.
export type GetAccountsResult =
  | { source: "live"; deviceId: string; accounts: Account[] }
  | { source: "not_connected"; deviceId: string; reason: "not_connected" }
  | { source: "session_ended"; deviceId: string; reason: GetAccountsSessionEndedReason };

// policy_get is read-only and session-scoped. The policy document is
// Firmware-authored active-policy readback, not an editor surface.
export type PolicyGetResult =
  | { source: "live"; deviceId: string; policy: PolicyDocument }
  | { source: "not_connected"; deviceId: string; reason: "not_connected" }
  | { source: "session_ended"; deviceId: string; reason: PolicyGetSessionEndedReason };

// get_approval_history is read-only and session-scoped. Firmware owns the
// stored decision records; Agent-Q validates and transports only bounded pages.
export type GetApprovalHistoryResult =
  | { source: "live"; deviceId: string; records: ApprovalHistoryRecord[]; hasMore: boolean }
  | { source: "not_connected"; deviceId: string; reason: "not_connected" }
  | { source: "session_ended"; deviceId: string; reason: GetApprovalHistorySessionEndedReason };

export type PolicyProposalOutcome =
  | {
      source: "live";
      deviceId: string;
      status: PolicyProposalOutcomeResponse["status"];
      reasonCode: PolicyProposalOutcomeResponse["reasonCode"];
      policy?: PolicyProposalOutcomeResponse["policy"];
    }
  | { source: "not_connected"; deviceId: string; reason: "not_connected" }
  | { source: "session_ended"; deviceId: string; reason: PolicyProposeSessionEndedReason };

export type CredentialPreparation =
  | {
      source: "live";
      deviceId: string;
      chain: CredentialPreparationResponse["chain"];
      credential: CredentialPreparationResponse["credential"];
      preparation: CredentialPreparationResponse["preparation"];
    }
  | { source: "not_connected"; deviceId: string; reason: "not_connected" }
  | { source: "session_ended"; deviceId: string; reason: GetAccountsSessionEndedReason };

export type CredentialProposalOutcome =
  | {
      source: "live";
      deviceId: string;
      status: CredentialProposalOutcomeResponse["status"];
      reasonCode: CredentialProposalOutcomeResponse["reasonCode"];
      sessionEnded: CredentialProposalOutcomeResponse["sessionEnded"];
    }
  | { source: "not_connected"; deviceId: string; reason: "not_connected" }
  | { source: "session_ended"; deviceId: string; reason: GetAccountsSessionEndedReason };

type SignTerminalResponse = Extract<
  SigningOutcome,
  { status: "user_rejected" | "user_timed_out" | "policy_rejected" | "signing_failed" }
>;

type LiveSignedResult = {
  source: "live";
  deviceId: string;
  status: "signed";
  authorization: Extract<SigningOutcome, { status: "signed" }>["authorization"];
  chain: Extract<SigningOutcome, { status: "signed" }>["chain"];
  method: Extract<SigningOutcome, { status: "signed" }>["method"];
  signature: string;
  messageBytes?: string;
};

type LiveTerminalSigningOutcome =
  | {
      source: "live";
      deviceId: string;
      status: Exclude<SignTerminalResponse["status"], "policy_rejected">;
      authorization: SignTerminalResponse["authorization"];
      error: Extract<SignTerminalResponse, { status: Exclude<SignTerminalResponse["status"], "policy_rejected"> }>["error"];
    }
  | {
      source: "live";
      deviceId: string;
      status: "policy_rejected";
      authorization: "policy";
      policyHash: string;
      ruleRef: string;
      error: Extract<SignTerminalResponse, { status: "policy_rejected" }>["error"];
    };

export type SignTransactionResult =
  | LiveSignedResult
  | LiveTerminalSigningOutcome
  | { source: "not_connected"; deviceId: string; reason: "not_connected" }
  | { source: "session_ended"; deviceId: string; reason: SignTransactionSessionEndedReason };

export type SignPersonalMessageResult =
  | LiveSignedResult
  | LiveTerminalSigningOutcome
  | { source: "not_connected"; deviceId: string; reason: "not_connected" }
  | { source: "session_ended"; deviceId: string; reason: SignPersonalMessageSessionEndedReason };

export const DEFAULT_CLIENT_NAME = "Agent-Q";

export class AgentQCore {
  private readonly runtimeSessions = new Map<string, RuntimeSession>();
  private readonly usbDriver: UsbSerialDriver;

  constructor(
    private readonly configStore: ConfigStore,
    usbDriver: UsbSerialDriver,
    private readonly clock: () => Date = () => new Date(),
  ) {
    // Wrap the driver once so every deadline-bearing transport call is bounded by
    // its internal deadline at a single boundary, regardless of whether the
    // injected driver honors it.
    this.usbDriver = deadlineEnforcingDriver(usbDriver);
  }

  async scanDevices(input: Record<string, never> = {}): Promise<ScanDevicesResult> {
    rejectUnsupportedInputFields(input, NO_INPUT_KEYS, "scanDevices");
    const scanResult = await scanUsbDeviceStatuses(this.usbDriver, INTERNAL_USB_DEADLINE_MS);
    const devices: LiveDeviceStatus[] = [];

    for (const liveDevice of scanResult.devices) {
      await this.configStore.rememberUsbStatus(liveDevice.status, liveDevice.portPath, {
        setActive: false,
      });
      devices.push(toLiveStatus(liveDevice));
    }
    this.clearRuntimeSessionsAbsentFromLiveUsbScan(
      new Set(scanResult.devices.map((liveDevice) => liveDevice.status.device.deviceId)),
    );

    const config = await this.configStore.load();
    return {
      source: "live",
      devices,
      failures: scanResult.failures.map(toScanFailure),
      activeDeviceId: config.activeDeviceId,
    };
  }

  async identifyDevices(input: Record<string, never> = {}): Promise<IdentifyDevicesResult> {
    rejectUnsupportedInputFields(input, NO_INPUT_KEYS, "identifyDevices");
    const deadlineMs = INTERNAL_USB_DEADLINE_MS;
    // deadlineMs is the total internal transport budget for the whole call
    // (discovery plus every identify handshake), not a per-device limit.
    const deadline = this.clock().getTime() + deadlineMs;
    const liveDevices = await scanUsbDevices(this.usbDriver, deadlineMs);
    const devices: Array<IdentifiedDevice | IdentifyDeviceFailure> = [];
    const usedCodes = new Set<string>();

    for (const liveDevice of liveDevices) {
      const remainingMs = deadline - this.clock().getTime();
      if (remainingMs <= 0) {
        // Transport budget exhausted before this device was reached. The nested
        // error is already public (canonical code + message) at the source.
        devices.push({
          source: "error",
          connected: false,
          portPath: sanitizePortHint(liveDevice.portPath),
          deviceId: liveDevice.status.device.deviceId,
          status: "error",
          error: toPublicError("timeout", true),
        });
        continue;
      }
      const code = createUniqueIdentificationCode(usedCodes);
      try {
        const response = await this.usbDriver.identifyDevice(
          liveDevice.portPath,
          code,
          remainingMs,
        );
        if (response.device.deviceId !== liveDevice.status.device.deviceId) {
          throw new AgentQError(
            "handshake_failed",
            `Identify response device id did not match status response. Expected ${liveDevice.status.device.deviceId}, got ${response.device.deviceId}.`,
            true,
          );
        }
        if (response.code !== code) {
          throw new AgentQError("handshake_failed", "Identify response code did not match request.", true);
        }

        await this.configStore.rememberUsbStatus(
          { device: response.device, provisioning: liveDevice.status.provisioning },
          liveDevice.portPath,
        );
        devices.push({
          source: "live",
          connected: true,
          portPath: sanitizePortHint(liveDevice.portPath),
          code,
          device: response.device,
        });
      } catch (error) {
        const agentQError = toAgentQError(error);
        // Canonicalize the nested error at the source so the returned data is
        // public-safe for ANY adapter, not only after MCP re-sanitizes it.
        devices.push({
          source: "error",
          connected: false,
          portPath: sanitizePortHint(liveDevice.portPath),
          deviceId: liveDevice.status.device.deviceId,
          status: "error",
          error: toPublicError(agentQError.code, agentQError.retryable),
        });
      }
    }

    const config = await this.configStore.load();
    return {
      source: "live",
      devices,
      activeDeviceId: config.activeDeviceId,
    };
  }

  async selectDevice(input: { deviceId: string; purpose?: string }): Promise<SelectDeviceResult> {
    rejectUnsupportedInputFields(input, DEVICE_SCOPED_INPUT_KEYS, "selectDevice");
    if (!isSafeDeviceId(input.deviceId)) {
      throw new AgentQError("invalid_device_id", "deviceId is not a valid device identifier.", false);
    }

    let record: DeviceRecord;
    try {
      record = await this.configStore.setActiveDevice(input.deviceId, input.purpose);
    } catch (error) {
      throw mapConfigError(error);
    }

    return {
      source: "selected",
      activeDeviceId: record.deviceId,
      purpose: input.purpose ?? null,
      device: record.lastStatus.device,
    };
  }

  async listDevices(): Promise<DeviceListResult> {
    const config = await this.configStore.load();
    const listings = await this.configStore.listDevices();
    const devices: DeviceListEntry[] = listings.map((listing) => ({
      ...listing,
      runtimeSession: toRuntimeSessionView(this.peekRuntimeSession(listing.deviceId)),
    }));
    return {
      source: "list",
      devices,
      activeDeviceId: config.activeDeviceId,
      activeDeviceIdsByPurpose: { ...config.activeDeviceIdsByPurpose },
    };
  }

  async setDeviceMetadata(input: {
    deviceId: string;
    label?: string | null;
  }): Promise<SetDeviceMetadataResult> {
    rejectUnsupportedInputFields(input, SET_DEVICE_METADATA_INPUT_KEYS, "setDeviceMetadata");
    if (!isSafeDeviceId(input.deviceId)) {
      throw new AgentQError("invalid_device_id", "deviceId is not a valid device identifier.", false);
    }

    let record: DeviceRecord;
    try {
      record = await this.configStore.setDeviceMetadata({
        deviceId: input.deviceId,
        label: input.label,
      });
    } catch (error) {
      throw mapConfigError(error);
    }
    return {
      source: "metadata",
      deviceId: record.deviceId,
      label: record.label,
    };
  }

  async connectDevice(input: {
    deviceId?: string;
    purpose?: string;
    clientName?: string;
  } = {}): Promise<ConnectDeviceResult> {
    rejectUnsupportedInputFields(input, CONNECT_DEVICE_INPUT_KEYS, "connectDevice");
    const clientName = validateClientName(input.clientName);
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_USB_DEADLINE_MS;

    let matchingPort: UsbStatusResult;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      throw error;
    }
    // Record the live device before sending connect so a rejected or timed-out
    // attempt still refreshes lastSeenAt and the cached status for this device.
    await this.configStore.rememberUsbStatus(
      matchingPort.status,
      matchingPort.portPath,
      { observedAt: this.clock() },
    );

    const existingSession = this.peekRuntimeSession(target.deviceId);
    if (existingSession !== null) {
      try {
        await this.usbDriver.getCapabilities(
          matchingPort.portPath,
          existingSession.sessionId,
          scanDeadlineMs,
        );
        return {
          source: "connected",
          deviceId: target.deviceId,
          sessionTtlMs: existingSession.sessionTtlMs,
          connectedAt: existingSession.connectedAt,
          device: matchingPort.status.device,
        };
      } catch (error) {
        const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
        if (reason !== "invalid_session") {
          throw error;
        }
      }
    }

    let response: ConnectResult;
    try {
      response = await this.usbDriver.connectDevice(
        matchingPort.portPath,
        clientName,
        INTERNAL_CONNECT_DEADLINE_MS,
      );
    } catch (error) {
      this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      throw error;
    }

    if (response.device.deviceId !== target.deviceId) {
      throw new AgentQError(
        "handshake_failed",
        `Connect response device id did not match. Expected ${target.deviceId}, got ${response.device.deviceId}.`,
        true,
      );
    }

    const session = this.recordSession(
      target.deviceId,
      response.sessionId,
      response.sessionTtlMs,
    );
    return {
      source: "connected",
      deviceId: target.deviceId,
      sessionTtlMs: session.sessionTtlMs,
      connectedAt: session.connectedAt,
      device: response.device,
    };
  }

  async disconnectDevice(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<DisconnectDeviceResult> {
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }
    rejectUnsupportedInputFields(input, DEVICE_SCOPED_INPUT_KEYS, "disconnectDevice");

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      // The device could not be located. clearRuntimeSessionMirrorIfEnded owns the policy
      // for which disconnect failures end Agent-Q's local session view; clearing
      // it here prevents reusing a session Agent-Q cannot confirm.
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "disconnected", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      await this.usbDriver.disconnectDevice(matchingPort.portPath, session.sessionId, scanDeadlineMs);
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "disconnected", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    this.clearRuntimeSessionMirror(target.deviceId);
    return { source: "disconnected", deviceId: target.deviceId, reason: "firmware_confirmed" };
  }

  async getCapabilities(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<GetCapabilitiesResult> {
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }
    rejectUnsupportedInputFields(input, DEVICE_SCOPED_INPUT_KEYS, "getCapabilities");

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      const response = await this.usbDriver.getCapabilities(
        matchingPort.portPath,
        session.sessionId,
        scanDeadlineMs,
      );
      return {
        source: "live",
        deviceId: target.deviceId,
        capabilities: response.chains,
        ...(response.signing === undefined ? {} : { signing: response.signing }),
        ...(response.credentials === undefined ? {} : { credentials: response.credentials }),
      };
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }
  }

  async getAccounts(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<GetAccountsResult> {
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }
    rejectUnsupportedInputFields(input, DEVICE_SCOPED_INPUT_KEYS, "getAccounts");

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      // A transport/session failure while locating the device may end Agent-Q's
      // local session view; clearRuntimeSessionMirrorIfEnded owns that policy. get_accounts
      // is read-only, so a recognized clearing reason is reported as session_ended
      // (the firmware session is presumed gone) rather than throwing.
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      const response = await this.usbDriver.getAccounts(
        matchingPort.portPath,
        session.sessionId,
        scanDeadlineMs,
      );
      // Read-only: the session is retained on success.
      return { source: "live", deviceId: target.deviceId, accounts: response.accounts };
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }
  }

  async policyGet(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<PolicyGetResult> {
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }
    rejectUnsupportedInputFields(input, DEVICE_SCOPED_INPUT_KEYS, "policyGet");

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      const response = await this.usbDriver.policyGet(
        matchingPort.portPath,
        session.sessionId,
        scanDeadlineMs,
      );
      return { source: "live", deviceId: target.deviceId, policy: response.policy };
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }
  }

  async getApprovalHistory(input: {
    deviceId?: string;
    purpose?: string;
    limit?: number;
    beforeSeq?: string;
  } = {}): Promise<GetApprovalHistoryResult> {
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }
    rejectUnsupportedInputFields(input, GET_APPROVAL_HISTORY_INPUT_KEYS, "getApprovalHistory");
    const params = validateApprovalHistoryInput({
      limit: input.limit,
      beforeSeq: input.beforeSeq,
    });

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      const response = await this.usbDriver.getApprovalHistory(
        matchingPort.portPath,
        session.sessionId,
        params,
        scanDeadlineMs,
      );
      return {
        source: "live",
        deviceId: target.deviceId,
        records: response.records,
        hasMore: response.hasMore,
      };
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }
  }

  async policyPropose(input: {
    deviceId?: string;
    purpose?: string;
    policy: Record<string, unknown>;
  }): Promise<PolicyProposalOutcome> {
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;
    const policyUpdateDeadlineMs = INTERNAL_POLICY_UPDATE_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }

    rejectUnsupportedInputFields(input, POLICY_PROPOSE_INPUT_KEYS, "policyPropose");
    validatePolicyProposeInput(input.policy);
    validatePolicyProposeRequestInput(session.sessionId, input.policy);

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      const response = await this.usbDriver.policyPropose(
        matchingPort.portPath,
        session.sessionId,
        input.policy,
        policyUpdateDeadlineMs,
      );
      if (response.status === "consistency_error") {
        this.clearRuntimeSessionMirror(target.deviceId);
      }
      return {
        source: "live",
        deviceId: target.deviceId,
        status: response.status,
        reasonCode: response.reasonCode,
        ...(response.policy === undefined ? {} : { policy: response.policy }),
      };
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }
  }

  async credentialPrepare(input: {
    deviceId?: string;
    purpose?: string;
    chain: string;
    credential: string;
  }): Promise<CredentialPreparation> {
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }

    rejectUnsupportedInputFields(input, CREDENTIAL_PREPARE_INPUT_KEYS, "credentialPrepare");
    const params = validateCredentialPrepareInput({
      chain: input.chain,
      credential: input.credential,
    });
    validateCredentialPrepareRequestInput(session.sessionId, params);

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      const response = await this.usbDriver.credentialPrepare(
        matchingPort.portPath,
        session.sessionId,
        scanDeadlineMs,
      );
      return {
        source: "live",
        deviceId: target.deviceId,
        chain: response.chain,
        credential: response.credential,
        preparation: response.preparation,
      };
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }
  }

  async credentialPropose(input: {
    deviceId?: string;
    purpose?: string;
    chain: string;
    credential: string;
    network: unknown;
    address: string;
    publicKey: string;
    maxEpoch: string;
    inputs: unknown;
  }): Promise<CredentialProposalOutcome> {
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;
    const deadlineMs = INTERNAL_POLICY_UPDATE_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }

    rejectUnsupportedInputFields(input, CREDENTIAL_PROPOSE_INPUT_KEYS, "credentialPropose");
    const params = validateCredentialProposeInput({
      chain: input.chain,
      credential: input.credential,
      network: input.network,
      address: input.address,
      publicKey: input.publicKey,
      maxEpoch: input.maxEpoch,
      inputs: input.inputs,
    });
    validateCredentialProposeRequestInput(session.sessionId, params);

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      const response = await this.usbDriver.credentialPropose(
        matchingPort.portPath,
        session.sessionId,
        params,
        deadlineMs,
      );
      if (response.sessionEnded) {
        this.clearRuntimeSessionMirror(target.deviceId);
      }
      return {
        source: "live",
        deviceId: target.deviceId,
        status: response.status,
        reasonCode: response.reasonCode,
        sessionEnded: response.sessionEnded,
      };
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }
  }

  async signTransaction(input: {
    deviceId?: string;
    purpose?: string;
    chain: string;
    method: string;
    network: unknown;
    txBytes: string;
  }): Promise<SignTransactionResult> {
    const route = identifySignHostRoute("sign_transaction", input.chain, input.method);
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;
    const deadlineMs = INTERNAL_SIGN_TRANSACTION_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }

    rejectUnsupportedInputFields(input, SIGN_TRANSACTION_INPUT_KEYS, "signTransaction");
    const params = validateSignHostInput({
      requestType: "sign_transaction",
      network: input.network,
      txBytes: input.txBytes,
    });

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      const response = await this.usbDriver.signTransaction(
        matchingPort.portPath,
        session.sessionId,
        route,
        params,
        deadlineMs,
      );
      const firmwareInvalidatedSession = consumeFirmwareSessionInvalidated(response);
      const result = toLiveSigningOutcome(target.deviceId, response);
      if (firmwareInvalidatedSession) {
        this.clearRuntimeSessionMirror(target.deviceId);
      }
      return result;
    } catch (error) {
      this.clearRuntimeSessionMirrorIfFirmwareInvalidatedSideEffect(target.deviceId, error);
      const reason = this.clearRuntimeSessionMirrorIfFirmwareInvalidated(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }
  }

  async signPersonalMessage(input: {
    deviceId?: string;
    purpose?: string;
    chain: string;
    method: string;
    network: unknown;
    message: string;
  }): Promise<SignPersonalMessageResult> {
    const route = identifySignHostRoute("sign_personal_message", input.chain, input.method);
    const target = await this.resolveTargetDevice(input);
    const scanDeadlineMs = INTERNAL_DISCONNECT_DEADLINE_MS;
    const deadlineMs = INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS;

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return { source: "not_connected", deviceId: target.deviceId, reason: "not_connected" };
    }

    rejectUnsupportedInputFields(input, SIGN_PERSONAL_MESSAGE_INPUT_KEYS, "signPersonalMessage");
    const params = validateSignPersonalMessageHostInput({
      requestType: "sign_personal_message",
      network: input.network,
      message: input.message,
    });

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanDeadlineMs);
    } catch (error) {
      const reason = this.clearRuntimeSessionMirrorIfEnded(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }

    try {
      const response = await this.usbDriver.signPersonalMessage(
        matchingPort.portPath,
        session.sessionId,
        route,
        params,
        deadlineMs,
      );
      const firmwareInvalidatedSession = consumeFirmwareSessionInvalidated(response);
      const result = toLiveSigningOutcome(target.deviceId, response);
      if (firmwareInvalidatedSession) {
        this.clearRuntimeSessionMirror(target.deviceId);
      }
      return result;
    } catch (error) {
      this.clearRuntimeSessionMirrorIfFirmwareInvalidatedSideEffect(target.deviceId, error);
      const reason = this.clearRuntimeSessionMirrorIfFirmwareInvalidated(target.deviceId, error);
      if (reason !== null) {
        return { source: "session_ended", deviceId: target.deviceId, reason };
      }
      throw error;
    }
  }

  private peekRuntimeSession(deviceId: string): RuntimeSession | null {
    const session = this.runtimeSessions.get(deviceId);
    if (session === undefined) {
      return null;
    }
    return session;
  }

  private recordSession(deviceId: string, sessionId: string, sessionTtlMs: number): RuntimeSession {
    const connectedAt = this.clock();
    const session: RuntimeSession = {
      deviceId,
      sessionId,
      sessionTtlMs,
      connectedAt: connectedAt.toISOString(),
    };
    this.runtimeSessions.set(deviceId, session);
    return session;
  }

  private clearRuntimeSessionsAbsentFromLiveUsbScan(liveDeviceIds: ReadonlySet<string>): void {
    for (const deviceId of this.runtimeSessions.keys()) {
      if (!liveDeviceIds.has(deviceId)) {
        this.clearRuntimeSessionMirror(deviceId);
      }
    }
  }

  private clearRuntimeSessionMirror(deviceId: string): void {
    this.runtimeSessions.delete(deviceId);
  }

  private clearRuntimeSessionMirrorIfEnded(
    deviceId: string,
    error: unknown,
  ): RuntimeSessionMirrorEndReason | null {
    const reason = runtimeSessionMirrorEndReason(error);
    if (reason !== null) {
      this.clearRuntimeSessionMirror(deviceId);
    }
    return reason;
  }

  private clearRuntimeSessionMirrorIfFirmwareInvalidated(
    deviceId: string,
    error: unknown,
  ): RuntimeSessionMirrorEndReason | null {
    if (!(error instanceof AgentQError) || error.code !== "invalid_session") {
      return null;
    }
    this.clearRuntimeSessionMirror(deviceId);
    return "invalid_session";
  }

  private clearRuntimeSessionMirrorIfFirmwareInvalidatedSideEffect(
    deviceId: string,
    error: unknown,
  ): boolean {
    if (!consumeFirmwareSessionInvalidated(error)) {
      return false;
    }
    this.clearRuntimeSessionMirror(deviceId);
    return true;
  }

  private async resolveTargetDevice(input: {
    deviceId?: string;
    purpose?: string;
  }): Promise<{ deviceId: string; record: DeviceRecord }> {
    if (input.purpose !== undefined && RESERVED_PURPOSES.has(input.purpose)) {
      throw new AgentQError(
        "invalid_params",
        `purpose '${input.purpose}' is reserved. Omit purpose to use the default device.`,
        false,
      );
    }
    if (input.purpose !== undefined && !isValidPurpose(input.purpose)) {
      throw new AgentQError(
        "invalid_params",
        "purpose must be 1-32 characters of [A-Za-z0-9_.-].",
        false,
      );
    }

    const config = await this.configStore.load();
    let deviceId: string | undefined;
    if (input.deviceId !== undefined && input.deviceId.length > 0) {
      deviceId = input.deviceId;
    } else if (input.purpose !== undefined) {
      // Own-property lookup: an inherited name must not resolve to a prototype value.
      deviceId = Object.prototype.hasOwnProperty.call(config.activeDeviceIdsByPurpose, input.purpose)
        ? config.activeDeviceIdsByPurpose[input.purpose]
        : undefined;
    } else if (config.activeDeviceId !== null) {
      deviceId = config.activeDeviceId;
    }

    if (deviceId === undefined || deviceId.length === 0) {
      throw new AgentQError("no_active_device", "No active device is configured.", false);
    }

    const record = config.devices.find((candidate) => candidate.deviceId === deviceId);
    if (record === undefined) {
      throw new AgentQError("device_not_found", "Device is not known to Agent-Q.", true);
    }
    return { deviceId, record };
  }

  private async findLivePortForDevice(
    record: DeviceRecord,
    deadlineMs: number,
  ): Promise<UsbStatusResult> {
    const scanResult = await scanUsbDeviceStatuses(this.usbDriver, deadlineMs);
    const matching = scanResult.devices.find(
      (candidate) => candidate.status.device.deviceId === record.deviceId,
    );
    if (matching !== undefined) {
      return matching;
    }

    const knownPortFailure = scanResult.failures.find((failure) => failure.portPath === record.lastPortHint);
    if (knownPortFailure !== undefined) {
      throw new AgentQError(
        knownPortFailure.unavailableReason,
        `Device ${record.deviceId} is not reachable on the last known port.`,
        true,
      );
    }
    const knownPortExists = scanResult.ports.some((port) => port.path === record.lastPortHint);
    if (!knownPortExists) {
      throw new AgentQError(
        "port_not_found",
        `Device ${record.deviceId} is not connected.`,
        true,
      );
    }
    throw new AgentQError(
      "handshake_failed",
      `Device ${record.deviceId} did not respond to a status handshake.`,
      true,
    );
  }

  async getDeviceStatus(
    input: { deviceId?: string; purpose?: string } = {},
  ): Promise<DeviceStatusResult> {
    rejectUnsupportedInputFields(input, DEVICE_SCOPED_INPUT_KEYS, "getDeviceStatus");
    const deadlineMs = INTERNAL_USB_DEADLINE_MS;
    const { record } = await this.resolveTargetDevice(input);

    try {
      const scanResult = await scanUsbDeviceStatuses(this.usbDriver, deadlineMs);
      const matchingDevice = scanResult.devices.find(
        (candidate) => candidate.status.device.deviceId === record.deviceId,
      );

      if (matchingDevice !== undefined) {
        await this.configStore.rememberUsbStatus(
          matchingDevice.status,
          matchingDevice.portPath,
        );
        return toLiveStatus(matchingDevice);
      }

      const knownPortFailure = scanResult.failures.find((failure) => failure.portPath === record.lastPortHint);
      if (knownPortFailure !== undefined) {
        return toCachedStatus(record, knownPortFailure.unavailableReason, knownPortFailure.firmwareErrorCode);
      }

      const knownPortExists = scanResult.ports.some((port) => port.path === record.lastPortHint);
      if (!knownPortExists) {
        return toCachedStatus(record, "port_not_found");
      }

      return toCachedStatus(record, "handshake_failed");
    } catch (scanError) {
      return toCachedStatus(record, mapErrorToUnavailableReason(scanError));
    }
  }
}

function toLiveStatus(liveDevice: UsbStatusResult): LiveDeviceStatus {
  return {
    source: "live",
    connected: true,
    // portPath is an OS-supplied string; sanitize the copy that reaches MCP
    // output. The raw path is still used for I/O elsewhere via UsbStatusResult.
    portPath: sanitizePortHint(liveDevice.portPath),
    status: liveDevice.status,
  };
}

function toCachedStatus(
  record: DeviceRecord,
  unavailableReason: UnavailableReason,
  firmwareErrorCode?: string,
): CachedDeviceStatus {
  return {
    source: "cached",
    connected: false,
    statusObservedAt: record.lastSeenAt,
    unavailableReason,
    // Normalize the Firmware diagnostic code to an allowlisted public code at the
    // source, so the cached result is public-safe for any adapter.
    ...(firmwareErrorCode === undefined ? {} : { firmwareErrorCode: normalizeErrorCode(firmwareErrorCode) }),
    cachedStatus: record.lastStatus,
  };
}

function toScanFailure(failure: UsbStatusFailure): ScanDeviceFailure {
  return {
    source: "error",
    connected: false,
    portPath: sanitizePortHint(failure.portPath),
    unavailableReason: failure.unavailableReason,
    ...(failure.firmwareErrorCode === undefined
      ? {}
      : { firmwareErrorCode: normalizeErrorCode(failure.firmwareErrorCode) }),
  };
}

function validateClientName(value: unknown): string {
  if (value === undefined) {
    return DEFAULT_CLIENT_NAME;
  }
  if (!isClientName(value)) {
    throw new AgentQError(
      "invalid_params",
      "clientName must be 1-64 printable ASCII characters.",
      false,
    );
  }
  return value;
}

function validateSignHostInput(input: {
  requestType: "sign_transaction";
  network: unknown;
  txBytes: unknown;
}): SignTransactionParams {
  try {
    return validateSignTransactionParams(
      {
        network: input.network,
        txBytes: input.txBytes,
      },
      input.requestType,
    );
  } catch (error) {
    if (error instanceof ProtocolError) {
      throw new AgentQError(error.code, error.message, false);
    }
    throw error;
  }
}

function validateSignPersonalMessageHostInput(input: {
  requestType: "sign_personal_message";
  network: unknown;
  message: unknown;
}): SignPersonalMessageParams {
  try {
    return validateSignPersonalMessageParams(
      {
        network: input.network,
        message: input.message,
      },
      input.requestType,
    );
  } catch (error) {
    if (error instanceof ProtocolError) {
      throw new AgentQError(error.code, error.message, false);
    }
    throw error;
  }
}

function identifySignHostRoute(
  operation: "sign_transaction",
  chain: unknown,
  method: unknown,
): Extract<SupportedSignRoute, { operation: "sign_transaction" }>;
function identifySignHostRoute(
  operation: "sign_personal_message",
  chain: unknown,
  method: unknown,
): Extract<SupportedSignRoute, { operation: "sign_personal_message" }>;
function identifySignHostRoute(
  operation: "sign_transaction" | "sign_personal_message",
  chain: unknown,
  method: unknown,
): SupportedSignRoute {
  try {
    return identifySignRoute(operation, chain, method);
  } catch (error) {
    if (error instanceof ProtocolError) {
      throw new AgentQError(error.code, error.message, false);
    }
    throw error;
  }
}

function toLiveSigningOutcome(deviceId: string, response: SigningOutcome): LiveSignedResult | LiveTerminalSigningOutcome {
  if (response.status === "signed") {
    return {
      source: "live",
      deviceId,
      status: "signed",
      authorization: response.authorization,
      chain: response.chain,
      method: response.method,
      signature: response.signature,
      ...(response.method === "sign_personal_message" ? { messageBytes: response.messageBytes } : {}),
    };
  }
  if (response.status === "policy_rejected") {
    return {
      source: "live",
      deviceId,
      status: "policy_rejected",
      authorization: "policy",
      policyHash: response.policyHash,
      ruleRef: response.ruleRef,
      error: response.error,
    };
  }
  return {
    source: "live",
    deviceId,
    status: response.status,
    authorization: response.authorization,
    error: response.error,
  };
}

const NO_INPUT_KEYS = new Set<string>();
const DEVICE_SCOPED_INPUT_KEYS = new Set(["deviceId", "purpose"]);
const CONNECT_DEVICE_INPUT_KEYS = new Set(["deviceId", "purpose", "clientName"]);
const SET_DEVICE_METADATA_INPUT_KEYS = new Set(["deviceId", "label"]);
const GET_APPROVAL_HISTORY_INPUT_KEYS = new Set(["deviceId", "purpose", "limit", "beforeSeq"]);
const POLICY_PROPOSE_INPUT_KEYS = new Set(["deviceId", "purpose", "policy"]);
const CREDENTIAL_PREPARE_INPUT_KEYS = new Set(["deviceId", "purpose", "chain", "credential"]);
const CREDENTIAL_PROPOSE_INPUT_KEYS = new Set([
  "deviceId",
  "purpose",
  "chain",
  "credential",
  "network",
  "address",
  "publicKey",
  "maxEpoch",
  "inputs",
]);
const SIGN_TRANSACTION_INPUT_KEYS = new Set(["deviceId", "purpose", "chain", "method", "network", "txBytes"]);
const SIGN_PERSONAL_MESSAGE_INPUT_KEYS = new Set(["deviceId", "purpose", "chain", "method", "network", "message"]);

function rejectUnsupportedInputFields(
  input: unknown,
  allowedKeys: ReadonlySet<string>,
  inputName: string,
): void {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return;
  }
  for (const key of Object.keys(input)) {
    if (!allowedKeys.has(key)) {
      throw new AgentQError("invalid_params", `${inputName} input contains unsupported fields.`, false);
    }
  }
}

function mapConfigError(error: unknown): AgentQError {
  if (error instanceof ConfigError) {
    return new AgentQError(error.code, error.message, error.code === "device_not_found");
  }
  return toAgentQError(error);
}

function toRuntimeSessionView(session: RuntimeSession | null): RuntimeSessionView | null {
  if (session === null) {
    return null;
  }
  return {
    sessionTtlMs: session.sessionTtlMs,
    connectedAt: session.connectedAt,
  };
}

// Single owner of the session-clearing transport policy (see specs/PROTOCOL.md):
// these failures mean Agent-Q cannot confirm the session, so it clears its
// local view to avoid reusing a session Firmware may have already dropped. The
// returned reason explains why; an unrecognized error returns null, so the caller
// rethrows and keeps the session.
function runtimeSessionMirrorEndReason(
  error: unknown,
): RuntimeSessionMirrorEndReason | null {
  if (!(error instanceof AgentQError)) {
    return null;
  }
  switch (error.code) {
    case "invalid_session":
      return "invalid_session";
    case "timeout":
      return "timeout";
    case "port_not_found":
    case "transport_closed":
    case "port_in_use":
    case "port_permission_denied":
      return "transport_unavailable";
    default:
      return null;
  }
}

function createUniqueIdentificationCode(usedCodes: Set<string>): string {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const code = createIdentificationCode();
    if (!usedCodes.has(code)) {
      usedCodes.add(code);
      return code;
    }
  }

  for (let value = 0; value <= 9999; value += 1) {
    const code = value.toString().padStart(4, "0");
    if (!usedCodes.has(code)) {
      usedCodes.add(code);
      return code;
    }
  }

  throw new AgentQError("identification_code_exhausted", "Could not create a unique identification code.", true);
}

export function createDefaultAgentQCore(): AgentQCore {
  return new AgentQCore(new ConfigStore(), new SerialPortUsbDriver());
}
