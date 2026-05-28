import { ConfigStore, type DeviceRecord } from "./config.js";
import { GatewayError, toGatewayError } from "./errors.js";
import {
  createIdentificationCode,
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
  device: StatusResponse["device"];
}

export const DEFAULT_IDENTIFY_DURATION_MS = 10000;
export const MAX_IDENTIFY_DURATION_MS = 30000;

export class GatewayCore {
  constructor(
    private readonly configStore: ConfigStore,
    private readonly usbDriver: UsbSerialDriver,
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

  async selectDevice(input: { deviceId: string }): Promise<SelectDeviceResult> {
    if (input.deviceId.length === 0) {
      throw new GatewayError("invalid_device_id", "deviceId must not be empty.", false);
    }

    const record = await this.configStore.setActiveDevice(input.deviceId);
    if (record === undefined) {
      throw new GatewayError("device_not_found", "Device is not known to Gateway.", true);
    }

    return {
      source: "selected",
      activeDeviceId: record.deviceId,
      device: record.lastStatus.device,
    };
  }

  async getDeviceStatus(input: { deviceId?: string; timeoutMs?: number } = {}): Promise<DeviceStatusResult> {
    const timeoutMs = validateTimeoutMs(input.timeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS);
    const config = await this.configStore.load();
    const deviceId = input.deviceId ?? config.activeDeviceId;

    if (deviceId === null || deviceId === undefined || deviceId.length === 0) {
      throw new GatewayError("no_active_device", "No active device is configured.", false);
    }

    const record = config.devices.find((candidate) => candidate.deviceId === deviceId);
    if (record === undefined) {
      throw new GatewayError("device_not_found", "Device is not known to Gateway.", true);
    }

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
