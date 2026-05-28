import { ConfigStore, type DeviceRecord } from "./config.js";
import { GatewayError } from "./errors.js";
import {
  createIdentificationCode,
  type IdentifyDeviceResponse,
  type StatusResponse,
} from "./protocol.js";
import {
  DEFAULT_SCAN_TIMEOUT_MS,
  mapErrorToUnavailableReason,
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
  code: string;
  protocolResponse: IdentifyDeviceResponse;
}

export interface IdentifyDevicesResult {
  source: "live";
  devices: IdentifiedDevice[];
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
    const devices: IdentifiedDevice[] = [];
    const usedCodes = new Set<string>();

    for (const liveDevice of liveDevices) {
      const code = createUniqueIdentificationCode(usedCodes);
      const response = await this.usbDriver.identifyDevice(
        liveDevice.portPath,
        code,
        timeoutMs,
        durationMs,
      );
      if (response.device.deviceId !== liveDevice.protocolResponse.device.deviceId) {
        throw new GatewayError("handshake_failed", "Identify response device id did not match status response.", true);
      }
      if (response.code !== code) {
        throw new GatewayError("handshake_failed", "Identify response code did not match request.", true);
      }

      await this.configStore.rememberUsbStatus(response.device, liveDevice.portPath);
      devices.push({
        source: "live",
        connected: true,
        portPath: liveDevice.portPath,
        code,
        protocolResponse: response,
      });
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
      const protocolResponse = await this.usbDriver.requestStatus(record.lastPortHint, timeoutMs);
      if (protocolResponse.device.deviceId !== record.deviceId) {
        throw new GatewayError("handshake_failed", "Device id did not match cached record.", true);
      }
      await this.configStore.rememberUsbStatus(protocolResponse.device, record.lastPortHint);
      return {
        source: "live",
        connected: true,
        portPath: record.lastPortHint,
        protocolResponse,
      };
    } catch (directError) {
      try {
        const liveDevices = await scanUsbDevices(this.usbDriver, timeoutMs);
        const matchingDevice = liveDevices.find(
          (candidate) => candidate.protocolResponse.device.deviceId === record.deviceId,
        );

        if (matchingDevice !== undefined) {
          await this.configStore.rememberUsbStatus(
            matchingDevice.protocolResponse.device,
            matchingDevice.portPath,
          );
          return toLiveStatus(matchingDevice);
        }
      } catch (scanError) {
        return toCachedStatus(record, mapErrorToUnavailableReason(scanError));
      }

      return toCachedStatus(record, mapErrorToUnavailableReason(directError));
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

function toCachedStatus(record: DeviceRecord, unavailableReason: UnavailableReason): CachedDeviceStatus {
  return {
    source: "cached",
    connected: false,
    statusObservedAt: record.lastSeenAt,
    unavailableReason,
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
  throw new GatewayError("identification_code_exhausted", "Could not create a unique identification code.", true);
}
