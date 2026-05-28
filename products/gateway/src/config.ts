import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import type { DeviceStatus } from "./protocol.js";

export const CONFIG_SCHEMA_VERSION = 1;

export interface DeviceRecord {
  deviceId: string;
  transport: "usb";
  lastPortHint: string;
  lastSeenAt: string;
  lastStatus: {
    device: DeviceStatus;
  };
}

export interface GatewayConfig {
  schemaVersion: typeof CONFIG_SCHEMA_VERSION;
  activeDeviceId: string | null;
  devices: DeviceRecord[];
}

export interface ConfigPathOptions {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
}

export interface RememberUsbStatusOptions {
  observedAt?: Date;
  setActive?: boolean;
}

export function defaultGatewayConfig(): GatewayConfig {
  return {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    activeDeviceId: null,
    devices: [],
  };
}

export function getConfigPath(options: ConfigPathOptions = {}): string {
  const env = options.env ?? process.env;
  const base = env.XDG_CONFIG_HOME && env.XDG_CONFIG_HOME.length > 0
    ? env.XDG_CONFIG_HOME
    : join(options.homeDir ?? homedir(), ".config");
  return join(base, "agent-q-gateway", "config.json");
}

export class ConfigStore {
  readonly path: string;

  constructor(path = getConfigPath()) {
    this.path = path;
  }

  async load(): Promise<GatewayConfig> {
    try {
      const raw = await readFile(this.path, "utf8");
      const parsed = JSON.parse(raw);
      if (isGatewayConfig(parsed)) {
        return parsed;
      }
      return defaultGatewayConfig();
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return defaultGatewayConfig();
      }
      throw error;
    }
  }

  async save(config: GatewayConfig): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    await writeFile(this.path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  }

  async rememberUsbStatus(
    device: DeviceStatus,
    portPath: string,
    options: RememberUsbStatusOptions = {},
  ): Promise<GatewayConfig> {
    const config = await this.load();
    const record: DeviceRecord = {
      deviceId: device.deviceId,
      transport: "usb",
      lastPortHint: portPath,
      lastSeenAt: (options.observedAt ?? new Date()).toISOString(),
      lastStatus: {
        device,
      },
    };

    const index = config.devices.findIndex((candidate) => candidate.deviceId === device.deviceId);
    if (index >= 0) {
      config.devices[index] = record;
    } else {
      config.devices.push(record);
    }

    if (options.setActive === true) {
      config.activeDeviceId = device.deviceId;
    }

    await this.save(config);
    return config;
  }

  async setActiveDevice(deviceId: string): Promise<DeviceRecord | undefined> {
    const config = await this.load();
    const record = config.devices.find((candidate) => candidate.deviceId === deviceId);
    if (record === undefined) {
      return undefined;
    }

    config.activeDeviceId = deviceId;
    await this.save(config);
    return record;
  }
}

function isGatewayConfig(value: unknown): value is GatewayConfig {
  if (!isRecord(value) || value.schemaVersion !== CONFIG_SCHEMA_VERSION) {
    return false;
  }
  if (!(typeof value.activeDeviceId === "string" || value.activeDeviceId === null)) {
    return false;
  }
  return Array.isArray(value.devices) && value.devices.every(isDeviceRecord);
}

function isDeviceRecord(value: unknown): value is DeviceRecord {
  if (!isRecord(value)) {
    return false;
  }
  return (
    typeof value.deviceId === "string" &&
    value.transport === "usb" &&
    typeof value.lastPortHint === "string" &&
    typeof value.lastSeenAt === "string" &&
    isRecord(value.lastStatus) &&
    isDeviceStatus(value.lastStatus.device)
  );
}

function isDeviceStatus(value: unknown): value is DeviceStatus {
  if (!isRecord(value)) {
    return false;
  }
  return (
    typeof value.deviceId === "string" &&
    typeof value.state === "string" &&
    typeof value.firmwareName === "string" &&
    typeof value.hardware === "string" &&
    typeof value.firmwareVersion === "string"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
