import {
  ConfigError,
  ConfigStore,
  RESERVED_PURPOSES,
  isValidPurpose,
  type DeviceListing,
  type DeviceRecord,
} from "./config.js";
import { GatewayError, toGatewayError } from "./errors.js";
import {
  createIdentificationCode,
  DEFAULT_APPROVAL_TIMEOUT_MS,
  MAX_APPROVAL_TIMEOUT_MS,
  type IdentifyDeviceResponse,
  type StatusResponse,
} from "./protocol.js";
import {
  DEFAULT_SCAN_TIMEOUT_MS,
  mapErrorToUnavailableReason,
  scanUsbDeviceStatuses,
  scanUsbDevices,
  validateTimeoutMs,
  type UnavailableReason,
  type UsbSerialDriver,
  type UsbStatusResult,
} from "./usb.js";

export interface LiveDeviceStatus {
  source: "live";
  connected: true;
  portPath: string;
  protocolResponse: StatusResponse;
}

export interface CachedDeviceStatus {
  source: "cached";
  connected: false;
  statusObservedAt: string;
  unavailableReason: UnavailableReason;
  firmwareErrorCode?: string;
  cachedStatus: {
    device: StatusResponse["device"];
  };
}

export interface ErrorDeviceStatus {
  source: "error";
  connected: false;
  error: {
    code: string;
    message: string;
    retryable: boolean;
  };
}

export type DeviceStatusResult = LiveDeviceStatus | CachedDeviceStatus;
export type DeviceStatusToolResult = DeviceStatusResult | ErrorDeviceStatus;

export interface ScanDevicesResult {
  source: "live";
  devices: LiveDeviceStatus[];
  activeDeviceId: string | null;
}

export interface IdentifiedDevice {
  source: "live";
  connected: true;
  portPath: string;
  status: "displayed";
  code: string;
  protocolResponse: IdentifyDeviceResponse;
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
  expiresAt: string;
}

export interface RuntimeSessionView {
  sessionTtlMs: number;
  connectedAt: string;
  expiresAt: string;
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
  reused: boolean;
  sessionTtlMs: number;
  connectedAt: string;
  expiresAt: string;
  device: StatusResponse["device"];
}

export interface DisconnectDeviceResult {
  source: "disconnected" | "not_connected";
  deviceId: string;
}

export const DEFAULT_IDENTIFY_DURATION_MS = 10000;
export const MAX_IDENTIFY_DURATION_MS = 30000;
export const DEFAULT_GATEWAY_NAME = "Agent-Q Gateway";
// Firmware owns the approval-window timeout. Gateway waits that long plus a
// transport margin so the final approve/reject response (sent right at the
// Firmware deadline) still arrives over the wire. Observed USB JTAG round trips
// are well under 100ms; 1000ms is a generous margin.
export const CONNECT_TRANSPORT_MARGIN_MS = 1000;
export const DEFAULT_DISCONNECT_TIMEOUT_MS = DEFAULT_SCAN_TIMEOUT_MS;

export class GatewayCore {
  private readonly runtimeSessions = new Map<string, RuntimeSession>();

  constructor(
    private readonly configStore: ConfigStore,
    private readonly usbDriver: UsbSerialDriver,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async scanDevices(input: { timeoutMs?: number } = {}): Promise<ScanDevicesResult> {
    const timeoutMs = validateTimeoutMs(input.timeoutMs);
    const liveDevices = await scanUsbDevices(this.usbDriver, timeoutMs);
    const devices: LiveDeviceStatus[] = [];

    for (const liveDevice of liveDevices) {
      await this.configStore.rememberUsbStatus(liveDevice.protocolResponse.device, liveDevice.portPath, {
        setActive: false,
      });
      devices.push(toLiveStatus(liveDevice));
    }

    const config = await this.configStore.load();
    return {
      source: "live",
      devices,
      activeDeviceId: config.activeDeviceId,
    };
  }

  async identifyDevices(input: { timeoutMs?: number; durationMs?: number } = {}): Promise<IdentifyDevicesResult> {
    const timeoutMs = validateTimeoutMs(input.timeoutMs);
    const durationMs = validateIdentifyDurationMs(input.durationMs);
    const liveDevices = await scanUsbDevices(this.usbDriver, timeoutMs);
    const devices: Array<IdentifiedDevice | IdentifyDeviceFailure> = [];
    const usedCodes = new Set<string>();

    for (const liveDevice of liveDevices) {
      const code = createUniqueIdentificationCode(usedCodes);
      try {
        const response = await this.usbDriver.identifyDevice(
          liveDevice.portPath,
          code,
          timeoutMs,
          durationMs,
        );
        if (response.device.deviceId !== liveDevice.protocolResponse.device.deviceId) {
          throw new GatewayError(
            "handshake_failed",
            `Identify response device id did not match status response. Expected ${liveDevice.protocolResponse.device.deviceId}, got ${response.device.deviceId}.`,
            true,
          );
        }
        if (response.code !== code) {
          throw new GatewayError("handshake_failed", "Identify response code did not match request.", true);
        }

        await this.configStore.rememberUsbStatus(response.device, liveDevice.portPath);
        devices.push({
          source: "live",
          connected: true,
          portPath: liveDevice.portPath,
          status: "displayed",
          code,
          protocolResponse: response,
        });
      } catch (error) {
        const gatewayError = toGatewayError(error);
        devices.push({
          source: "error",
          connected: false,
          portPath: liveDevice.portPath,
          deviceId: liveDevice.protocolResponse.device.deviceId,
          status: "error",
          error: {
            code: gatewayError.code,
            message: gatewayError.message,
            retryable: gatewayError.retryable,
          },
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
    if (input.deviceId.length === 0) {
      throw new GatewayError("invalid_device_id", "deviceId must not be empty.", false);
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
    if (input.deviceId.length === 0) {
      throw new GatewayError("invalid_device_id", "deviceId must not be empty.", false);
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
    gatewayName?: string;
    approvalTimeoutMs?: number;
    timeoutMs?: number;
  } = {}): Promise<ConnectDeviceResult> {
    const approvalTimeoutMs = validateApprovalTimeoutMs(input.approvalTimeoutMs);
    const gatewayName = validateGatewayName(input.gatewayName);
    const target = await this.resolveTargetDevice(input);
    const scanTimeoutMs = validateTimeoutMs(input.timeoutMs);

    const existingSession = this.peekRuntimeSession(target.deviceId);
    if (existingSession !== null) {
      // A non-expired runtime session is reused from local memory without
      // contacting Firmware and without re-approval: the session was already
      // physically approved when it was established. This reflects Gateway's
      // local view only. If Firmware has dropped the session (for example after
      // a reboot), Gateway does not detect it here; the loss surfaces as
      // invalid_session on the next disconnect or session-scoped request.
      return {
        source: "connected",
        deviceId: target.deviceId,
        reused: true,
        sessionTtlMs: existingSession.sessionTtlMs,
        connectedAt: existingSession.connectedAt,
        expiresAt: existingSession.expiresAt,
        device: target.record.lastStatus.device,
      };
    }

    const matchingPort = await this.findLivePortForDevice(target.record, scanTimeoutMs);
    // Record the live device before sending connect so a rejected or timed-out
    // attempt still refreshes lastSeenAt and the cached status for this device.
    await this.configStore.rememberUsbStatus(
      matchingPort.protocolResponse.device,
      matchingPort.portPath,
      { observedAt: this.clock() },
    );

    const transportTimeoutMs = approvalTimeoutMs + CONNECT_TRANSPORT_MARGIN_MS;
    const response = await this.usbDriver.connectDevice(
      matchingPort.portPath,
      gatewayName,
      transportTimeoutMs,
      approvalTimeoutMs,
    );

    if (response.status === "rejected") {
      throw new GatewayError(
        response.error.code,
        response.error.message,
        response.error.code === "timeout",
      );
    }

    if (response.device.deviceId !== target.deviceId) {
      throw new GatewayError(
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
      reused: false,
      sessionTtlMs: session.sessionTtlMs,
      connectedAt: session.connectedAt,
      expiresAt: session.expiresAt,
      device: response.device,
    };
  }

  async disconnectDevice(input: {
    deviceId?: string;
    purpose?: string;
    timeoutMs?: number;
  } = {}): Promise<DisconnectDeviceResult> {
    const target = await this.resolveTargetDevice(input);
    const scanTimeoutMs = validateTimeoutMs(input.timeoutMs ?? DEFAULT_DISCONNECT_TIMEOUT_MS);

    const session = this.peekRuntimeSession(target.deviceId);
    if (session === null) {
      return {
        source: "not_connected",
        deviceId: target.deviceId,
      };
    }

    let matchingPort: UsbStatusResult | undefined;
    try {
      matchingPort = await this.findLivePortForDevice(target.record, scanTimeoutMs);
    } catch (error) {
      // Transport is gone but Gateway still owns its local view of the session.
      if (isTransportUnavailable(error)) {
        this.runtimeSessions.delete(target.deviceId);
        return {
          source: "disconnected",
          deviceId: target.deviceId,
        };
      }
      throw error;
    }

    try {
      await this.usbDriver.disconnectDevice(matchingPort.portPath, session.sessionId, scanTimeoutMs);
    } catch (error) {
      if (error instanceof GatewayError && error.code === "invalid_session") {
        this.runtimeSessions.delete(target.deviceId);
        return {
          source: "disconnected",
          deviceId: target.deviceId,
        };
      }
      if (isTransportUnavailable(error)) {
        this.runtimeSessions.delete(target.deviceId);
        return {
          source: "disconnected",
          deviceId: target.deviceId,
        };
      }
      throw error;
    }

    this.runtimeSessions.delete(target.deviceId);
    return {
      source: "disconnected",
      deviceId: target.deviceId,
    };
  }

  private peekRuntimeSession(deviceId: string): RuntimeSession | null {
    const session = this.runtimeSessions.get(deviceId);
    if (session === undefined) {
      return null;
    }
    if (this.clock().getTime() >= Date.parse(session.expiresAt)) {
      this.runtimeSessions.delete(deviceId);
      return null;
    }
    return session;
  }

  private recordSession(deviceId: string, sessionId: string, sessionTtlMs: number): RuntimeSession {
    const connectedAt = this.clock();
    const expiresAt = new Date(connectedAt.getTime() + sessionTtlMs);
    const session: RuntimeSession = {
      deviceId,
      sessionId,
      sessionTtlMs,
      connectedAt: connectedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
    this.runtimeSessions.set(deviceId, session);
    return session;
  }

  private async resolveTargetDevice(input: {
    deviceId?: string;
    purpose?: string;
  }): Promise<{ deviceId: string; record: DeviceRecord }> {
    if (input.purpose !== undefined && RESERVED_PURPOSES.has(input.purpose)) {
      throw new GatewayError(
        "reserved_purpose",
        `purpose '${input.purpose}' is reserved. Omit purpose to use the default device.`,
        false,
      );
    }
    if (input.purpose !== undefined && !isValidPurpose(input.purpose)) {
      throw new GatewayError(
        "invalid_purpose",
        "purpose must be 1-32 characters of [A-Za-z0-9_.-].",
        false,
      );
    }

    const config = await this.configStore.load();
    let deviceId: string | undefined;
    if (input.deviceId !== undefined && input.deviceId.length > 0) {
      deviceId = input.deviceId;
    } else if (input.purpose !== undefined) {
      deviceId = config.activeDeviceIdsByPurpose[input.purpose];
    } else if (config.activeDeviceId !== null) {
      deviceId = config.activeDeviceId;
    }

    if (deviceId === undefined || deviceId.length === 0) {
      throw new GatewayError("no_active_device", "No active device is configured.", false);
    }

    const record = config.devices.find((candidate) => candidate.deviceId === deviceId);
    if (record === undefined) {
      throw new GatewayError("device_not_found", "Device is not known to Gateway.", true);
    }
    return { deviceId, record };
  }

  private async findLivePortForDevice(
    record: DeviceRecord,
    timeoutMs: number,
  ): Promise<UsbStatusResult> {
    const scanResult = await scanUsbDeviceStatuses(this.usbDriver, timeoutMs);
    const matching = scanResult.devices.find(
      (candidate) => candidate.protocolResponse.device.deviceId === record.deviceId,
    );
    if (matching !== undefined) {
      return matching;
    }

    const knownPortFailure = scanResult.failures.find((failure) => failure.portPath === record.lastPortHint);
    if (knownPortFailure !== undefined) {
      throw new GatewayError(
        knownPortFailure.unavailableReason,
        `Device ${record.deviceId} is not reachable on the last known port.`,
        true,
      );
    }
    const knownPortExists = scanResult.ports.some((port) => port.path === record.lastPortHint);
    if (!knownPortExists) {
      throw new GatewayError(
        "port_not_found",
        `Device ${record.deviceId} is not connected.`,
        true,
      );
    }
    throw new GatewayError(
      "handshake_failed",
      `Device ${record.deviceId} did not respond to a status handshake.`,
      true,
    );
  }

  async getDeviceStatus(
    input: { deviceId?: string; purpose?: string; timeoutMs?: number } = {},
  ): Promise<DeviceStatusResult> {
    const timeoutMs = validateTimeoutMs(input.timeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS);
    const { record } = await this.resolveTargetDevice(input);

    try {
      const scanResult = await scanUsbDeviceStatuses(this.usbDriver, timeoutMs);
      const matchingDevice = scanResult.devices.find(
        (candidate) => candidate.protocolResponse.device.deviceId === record.deviceId,
      );

      if (matchingDevice !== undefined) {
        await this.configStore.rememberUsbStatus(
          matchingDevice.protocolResponse.device,
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

export function toErrorToolResult(error: GatewayError): ErrorDeviceStatus {
  return {
    source: "error",
    connected: false,
    error: {
      code: error.code,
      message: error.message,
      retryable: error.retryable,
    },
  };
}

function toLiveStatus(liveDevice: UsbStatusResult): LiveDeviceStatus {
  return {
    source: "live",
    connected: true,
    portPath: liveDevice.portPath,
    protocolResponse: liveDevice.protocolResponse,
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
    ...(firmwareErrorCode === undefined ? {} : { firmwareErrorCode }),
    cachedStatus: record.lastStatus,
  };
}

function validateIdentifyDurationMs(value: unknown): number {
  if (value === undefined) {
    return DEFAULT_IDENTIFY_DURATION_MS;
  }
  if (!Number.isInteger(value) || typeof value !== "number" || value <= 0) {
    throw new GatewayError("invalid_duration", "durationMs must be a positive integer.", false);
  }
  if (value > MAX_IDENTIFY_DURATION_MS) {
    throw new GatewayError("invalid_duration", `durationMs must be <= ${MAX_IDENTIFY_DURATION_MS}.`, false);
  }
  return value;
}

function validateApprovalTimeoutMs(value: unknown): number {
  if (value === undefined) {
    return DEFAULT_APPROVAL_TIMEOUT_MS;
  }
  if (!Number.isInteger(value) || typeof value !== "number" || value <= 0) {
    throw new GatewayError(
      "invalid_approval_timeout",
      "approvalTimeoutMs must be a positive integer.",
      false,
    );
  }
  if (value > MAX_APPROVAL_TIMEOUT_MS) {
    throw new GatewayError(
      "invalid_approval_timeout",
      `approvalTimeoutMs must be <= ${MAX_APPROVAL_TIMEOUT_MS}.`,
      false,
    );
  }
  return value;
}

function validateGatewayName(value: unknown): string {
  if (value === undefined) {
    return DEFAULT_GATEWAY_NAME;
  }
  if (typeof value !== "string" || value.length === 0 || value.length > 64 || !/^[\x20-\x7E]+$/.test(value)) {
    throw new GatewayError(
      "invalid_gateway_name",
      "gatewayName must be 1-64 printable ASCII characters.",
      false,
    );
  }
  return value;
}

function mapConfigError(error: unknown): GatewayError {
  if (error instanceof ConfigError) {
    return new GatewayError(error.code, error.message, error.code === "device_not_found");
  }
  return toGatewayError(error);
}

function toRuntimeSessionView(session: RuntimeSession | null): RuntimeSessionView | null {
  if (session === null) {
    return null;
  }
  return {
    sessionTtlMs: session.sessionTtlMs,
    connectedAt: session.connectedAt,
    expiresAt: session.expiresAt,
  };
}

function isTransportUnavailable(error: unknown): boolean {
  if (!(error instanceof GatewayError)) {
    return false;
  }
  return (
    error.code === "port_not_found" ||
    error.code === "transport_closed" ||
    error.code === "port_in_use"
  );
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

  throw new GatewayError("identification_code_exhausted", "Could not create a unique identification code.", true);
}
