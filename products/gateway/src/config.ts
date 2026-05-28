import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import type { DeviceStatus } from "./protocol.js";

export const CONFIG_SCHEMA_VERSION = 2;
export const MAX_LABEL_LENGTH = 64;
export const PURPOSE_PATTERN = /^[A-Za-z0-9_.-]{1,32}$/;
export const RESERVED_PURPOSES: ReadonlySet<string> = new Set(["default"]);

export interface DeviceRecord {
  deviceId: string;
  transport: "usb";
  lastPortHint: string;
  lastSeenAt: string;
  label: string | null;
  lastStatus: {
    device: DeviceStatus;
  };
}

export interface GatewayConfig {
  schemaVersion: typeof CONFIG_SCHEMA_VERSION;
  activeDeviceId: string | null;
  activeDeviceIdsByPurpose: Record<string, string>;
  devices: DeviceRecord[];
}

export interface DeviceListing {
  deviceId: string;
  transport: "usb";
  lastPortHint: string;
  lastSeenAt: string;
  label: string | null;
  lastStatus: {
    device: DeviceStatus;
  };
  assignedPurposes: string[];
  isDefaultActive: boolean;
}

export interface ConfigPathOptions {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
}

export interface RememberUsbStatusOptions {
  observedAt?: Date;
  setActive?: boolean;
}

export interface SetDeviceMetadataInput {
  deviceId: string;
  label?: string | null;
}

export interface ConfigValidationError {
  code: string;
  message: string;
}

export class ConfigError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ConfigError";
    this.code = code;
  }
}

export function defaultGatewayConfig(): GatewayConfig {
  return {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    activeDeviceId: null,
    activeDeviceIdsByPurpose: {},
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

export function isValidLabel(value: unknown): value is string | null {
  if (value === null) {
    return true;
  }
  return typeof value === "string" && value.length > 0 && value.length <= MAX_LABEL_LENGTH;
}

export function isValidPurpose(value: unknown): value is string {
  if (typeof value !== "string" || !PURPOSE_PATTERN.test(value)) {
    return false;
  }
  return !RESERVED_PURPOSES.has(value);
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
      const migrated = migrateConfig(parsed);
      if (migrated !== undefined) {
        return normalizeReferences(migrated);
      }
      // Structurally invalid but valid JSON: do not silently overwrite without
      // surfacing it. stderr is safe here; stdout is the MCP JSON-RPC channel.
      console.warn(
        `agent-q-gateway: config at ${this.path} is not a recognized schema; using defaults.`,
      );
      return defaultGatewayConfig();
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return defaultGatewayConfig();
      }
      if (error instanceof SyntaxError) {
        console.warn(
          `agent-q-gateway: config at ${this.path} is not valid JSON; using defaults.`,
        );
        return defaultGatewayConfig();
      }
      throw error;
    }
  }

  async save(config: GatewayConfig): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    await writeFile(this.path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  }

  async listDevices(): Promise<DeviceListing[]> {
    const config = await this.load();
    return config.devices.map((record) => toDeviceListing(record, config));
  }

  async rememberUsbStatus(
    device: DeviceStatus,
    portPath: string,
    options: RememberUsbStatusOptions = {},
  ): Promise<GatewayConfig> {
    const config = await this.load();
    const lastSeenAt = (options.observedAt ?? new Date()).toISOString();
    const index = config.devices.findIndex((candidate) => candidate.deviceId === device.deviceId);

    if (index >= 0) {
      // Status refresh must not wipe Gateway-local metadata such as label.
      const existing = config.devices[index];
      config.devices[index] = {
        ...existing,
        transport: "usb",
        lastPortHint: portPath,
        lastSeenAt,
        lastStatus: {
          device,
        },
      };
    } else {
      config.devices.push({
        deviceId: device.deviceId,
        transport: "usb",
        lastPortHint: portPath,
        lastSeenAt,
        label: null,
        lastStatus: {
          device,
        },
      });
    }

    if (options.setActive === true) {
      config.activeDeviceId = device.deviceId;
    }

    await this.save(config);
    return config;
  }

  async setDeviceMetadata(input: SetDeviceMetadataInput): Promise<DeviceRecord> {
    if (input.deviceId.length === 0) {
      throw new ConfigError("invalid_device_id", "deviceId must not be empty.");
    }
    if (!Object.prototype.hasOwnProperty.call(input, "label")) {
      throw new ConfigError("invalid_metadata", "set_device_metadata requires at least one metadata field.");
    }
    if (!isValidLabel(input.label)) {
      throw new ConfigError(
        "invalid_label",
        `label must be null or a 1-${MAX_LABEL_LENGTH} character string.`,
      );
    }

    const config = await this.load();
    const index = config.devices.findIndex((candidate) => candidate.deviceId === input.deviceId);
    if (index < 0) {
      throw new ConfigError("device_not_found", "Device is not known to Gateway.");
    }

    const record: DeviceRecord = {
      ...config.devices[index],
      label: input.label ?? null,
    };
    config.devices[index] = record;
    await this.save(config);
    return record;
  }

  async setActiveDevice(deviceId: string, purpose?: string): Promise<DeviceRecord> {
    if (deviceId.length === 0) {
      throw new ConfigError("invalid_device_id", "deviceId must not be empty.");
    }
    if (purpose !== undefined) {
      if (RESERVED_PURPOSES.has(purpose)) {
        throw new ConfigError(
          "reserved_purpose",
          `purpose '${purpose}' is reserved. Omit purpose to set the default device.`,
        );
      }
      if (!isValidPurpose(purpose)) {
        throw new ConfigError(
          "invalid_purpose",
          "purpose must be 1-32 characters of [A-Za-z0-9_.-].",
        );
      }
    }

    const config = await this.load();
    const record = config.devices.find((candidate) => candidate.deviceId === deviceId);
    if (record === undefined) {
      throw new ConfigError("device_not_found", "Device is not known to Gateway.");
    }

    if (purpose === undefined) {
      config.activeDeviceId = deviceId;
    } else {
      config.activeDeviceIdsByPurpose[purpose] = deviceId;
    }
    await this.save(config);
    return record;
  }

  async getActiveDevice(purpose?: string): Promise<DeviceRecord | undefined> {
    if (purpose !== undefined && RESERVED_PURPOSES.has(purpose)) {
      throw new ConfigError(
        "reserved_purpose",
        `purpose '${purpose}' is reserved. Omit purpose to read the default device.`,
      );
    }
    if (purpose !== undefined && !isValidPurpose(purpose)) {
      throw new ConfigError(
        "invalid_purpose",
        "purpose must be 1-32 characters of [A-Za-z0-9_.-].",
      );
    }

    const config = await this.load();
    const deviceId =
      purpose === undefined ? config.activeDeviceId : config.activeDeviceIdsByPurpose[purpose];
    if (deviceId === null || deviceId === undefined || deviceId.length === 0) {
      return undefined;
    }
    return config.devices.find((candidate) => candidate.deviceId === deviceId);
  }
}

function toDeviceListing(record: DeviceRecord, config: GatewayConfig): DeviceListing {
  const assignedPurposes = Object.entries(config.activeDeviceIdsByPurpose)
    .filter(([, deviceId]) => deviceId === record.deviceId)
    .map(([purpose]) => purpose)
    .sort();
  return {
    deviceId: record.deviceId,
    transport: record.transport,
    lastPortHint: record.lastPortHint,
    lastSeenAt: record.lastSeenAt,
    label: record.label,
    lastStatus: record.lastStatus,
    assignedPurposes,
    isDefaultActive: config.activeDeviceId === record.deviceId,
  };
}

/**
 * Drop routing selections that point at devices not present in `devices`.
 * Writes always validate references, so dangling entries only arise from a
 * hand-edited config. Pruning keeps `list_devices` and purpose routing
 * self-consistent instead of failing later with `device_not_found`.
 */
export function normalizeReferences(config: GatewayConfig): GatewayConfig {
  const knownDeviceIds = new Set(config.devices.map((device) => device.deviceId));

  const activeDeviceId =
    config.activeDeviceId !== null && knownDeviceIds.has(config.activeDeviceId)
      ? config.activeDeviceId
      : null;

  const activeDeviceIdsByPurpose: Record<string, string> = {};
  for (const [purpose, deviceId] of Object.entries(config.activeDeviceIdsByPurpose)) {
    if (knownDeviceIds.has(deviceId)) {
      activeDeviceIdsByPurpose[purpose] = deviceId;
    }
  }

  if (
    activeDeviceId === config.activeDeviceId &&
    Object.keys(activeDeviceIdsByPurpose).length === Object.keys(config.activeDeviceIdsByPurpose).length
  ) {
    return config;
  }
  return { ...config, activeDeviceId, activeDeviceIdsByPurpose };
}

function migrateConfig(value: unknown): GatewayConfig | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  if (value.schemaVersion === CONFIG_SCHEMA_VERSION) {
    return isGatewayConfigV2(value) ? value : undefined;
  }

  if (value.schemaVersion === 1) {
    return migrateFromV1(value);
  }

  return undefined;
}

function migrateFromV1(value: Record<string, unknown>): GatewayConfig | undefined {
  if (!(typeof value.activeDeviceId === "string" || value.activeDeviceId === null)) {
    return undefined;
  }
  if (!Array.isArray(value.devices)) {
    return undefined;
  }

  const migratedDevices: DeviceRecord[] = [];
  for (const device of value.devices) {
    if (!isV1DeviceRecord(device)) {
      return undefined;
    }
    migratedDevices.push({
      deviceId: device.deviceId,
      transport: device.transport,
      lastPortHint: device.lastPortHint,
      lastSeenAt: device.lastSeenAt,
      label: null,
      lastStatus: device.lastStatus,
    });
  }

  return {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    activeDeviceId: value.activeDeviceId,
    activeDeviceIdsByPurpose: {},
    devices: migratedDevices,
  };
}

function isGatewayConfigV2(value: unknown): value is GatewayConfig {
  if (!isRecord(value) || value.schemaVersion !== CONFIG_SCHEMA_VERSION) {
    return false;
  }
  if (!(typeof value.activeDeviceId === "string" || value.activeDeviceId === null)) {
    return false;
  }
  if (!isRecord(value.activeDeviceIdsByPurpose)) {
    return false;
  }
  for (const [purpose, deviceId] of Object.entries(value.activeDeviceIdsByPurpose)) {
    if (RESERVED_PURPOSES.has(purpose)) {
      return false;
    }
    if (!isValidPurpose(purpose) || typeof deviceId !== "string" || deviceId.length === 0) {
      return false;
    }
  }
  return Array.isArray(value.devices) && value.devices.every(isDeviceRecord);
}

function isV1DeviceRecord(value: unknown): value is {
  deviceId: string;
  transport: "usb";
  lastPortHint: string;
  lastSeenAt: string;
  lastStatus: { device: DeviceStatus };
} {
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

function isDeviceRecord(value: unknown): value is DeviceRecord {
  if (!isRecord(value)) {
    return false;
  }
  if (!(value.label === null || (typeof value.label === "string" && value.label.length > 0 && value.label.length <= MAX_LABEL_LENGTH))) {
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
