import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import {
  sanitizeDeviceStatusSnapshot,
  type DeviceStatus,
  type DeviceStatusSnapshot,
} from "./protocol.js";
import {
  MAX_LABEL_LENGTH,
  PURPOSE_PATTERN,
  RESERVED_PURPOSES,
  isIsoTimestamp,
  isSafeDeviceId,
  isValidLabel,
  isValidPurpose,
  sanitizePortHint,
} from "./safe-text.js";

export const CONFIG_SCHEMA_VERSION = 0;

// The label/purpose policy is defined once in safe-text.ts (the single source of
// truth) and re-exported here so existing importers and tests continue to
// resolve these symbols through config.ts.
export { MAX_LABEL_LENGTH, PURPOSE_PATTERN, RESERVED_PURPOSES, isValidLabel, isValidPurpose };

// Unknown-timestamp sentinel. A stored lastSeenAt that is missing or malformed is
// coerced to the Unix epoch so the field always reaches MCP output as a valid ISO
// instant. The epoch is the stable "unknown / not recently observed" marker:
// Agent-Q does not invent a plausible current time (a false observation), and it
// does not drop the device for a bad display-only timestamp.
const EPOCH_ISO = "1970-01-01T00:00:00.000Z";

export interface DeviceRecord {
  deviceId: string;
  transport: "usb";
  lastPortHint: string;
  lastSeenAt: string;
  label: string | null;
  lastStatus: DeviceStatusSnapshot;
}

export interface DeviceConfig {
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
  lastStatus: DeviceStatusSnapshot;
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

export function defaultDeviceConfig(): DeviceConfig {
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
  return join(base, "firmware-device", "config.json");
}

export class ConfigStore {
  readonly path: string;

  constructor(path = getConfigPath()) {
    this.path = path;
  }

  // Raw content last warned about, so repeated loads of the same unchanged
  // (hand-edited) config do not re-emit the normalization warning.
  private lastWarnedRaw: string | null = null;

  async load(): Promise<DeviceConfig> {
    try {
      const raw = await readFile(this.path, "utf8");
      const parsed = JSON.parse(raw);
      const normalized = normalizeDeviceConfig(parsed);
      if (normalized !== undefined) {
        // One pipeline produces the config AND the report; every transformation it
        // performs increments the report (guarded by the per-field tests and the
        // fixpoint test), so the warning reflects what was actually changed.
        this.maybeWarnNormalized(raw, normalized.report);
        return normalized.config;
      }
      // Structurally invalid but valid JSON: do not silently overwrite without
      // surfacing it. stderr is safe here; stdout is the MCP JSON-RPC channel.
      // The interpolated path is operator-controlled local config (from
      // getConfigPath or the embedding caller), not untrusted request/device
      // text, so unlike a device/Firmware string it is logged as-is to stay
      // useful for debugging.
      console.warn(
        `device-config: config at ${this.path} is not a recognized schema; using defaults.`,
      );
      return defaultDeviceConfig();
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return defaultDeviceConfig();
      }
      if (error instanceof SyntaxError) {
        console.warn(
          `device-config: config at ${this.path} is not valid JSON; using defaults.`,
        );
        return defaultDeviceConfig();
      }
      throw error;
    }
  }

  // The single disk-write boundary. It re-runs the same normalization pipeline
  // used on load, so the file on disk can never hold an unsafe record or a
  // dangling route regardless of how the caller built the in-memory config — the
  // boundary enforces the SoT itself rather than trusting callers. Private:
  // callers mutate config only through the methods above.
  private async writeConfig(config: DeviceConfig): Promise<void> {
    const normalized = normalizeDeviceConfig(config);
    if (normalized === undefined) {
      // Unreachable: writeConfig only ever receives a current-schema config built by
      // this store. Fail loudly rather than silently writing defaults (which
      // would drop data) if that assumption ever breaks.
      throw new ConfigError("internal_output_error", "Refusing to write an unrecognized config shape.");
    }
    await mkdir(dirname(this.path), { recursive: true });
    await writeFile(this.path, `${JSON.stringify(normalized.config, null, 2)}\n`, "utf8");
  }

  // One aggregated stderr warning when stored config was normalized, deduped by
  // raw content so a persistent hand-edited file does not warn on every load.
  // Only counts are logged, never a raw (possibly unsafe) value.
  private maybeWarnNormalized(rawContent: string, report: NormalizationReport): void {
    if (reportTotal(report) === 0 || rawContent === this.lastWarnedRaw) {
      return;
    }
    this.lastWarnedRaw = rawContent;
    console.warn(
      `device-config: normalized stored config (droppedRecords=${report.droppedRecords}, ` +
        `droppedRoutes=${report.droppedRoutes}, clearedActiveDeviceId=${report.clearedActiveDeviceId}, ` +
        `coercedLabels=${report.coercedLabels}, coercedTimestamps=${report.coercedTimestamps}, ` +
        `sanitizedDeviceDisplayText=${report.sanitizedDeviceDisplayText}, ` +
        `sanitizedPortHints=${report.sanitizedPortHints}).`,
    );
  }

  async listDevices(): Promise<DeviceListing[]> {
    const config = await this.load();
    return config.devices.map((record) => toDeviceListing(record, config));
  }

  async rememberUsbStatus(
    status: DeviceStatusSnapshot,
    portPath: string,
    options: RememberUsbStatusOptions = {},
  ): Promise<DeviceConfig> {
    const config = await this.load();
    const lastSeenAt = (options.observedAt ?? new Date()).toISOString();
    // portPath is an OS-supplied diagnostic string; sanitize it before it is
    // stored and returned as lastPortHint in MCP output.
    const lastPortHint = sanitizePortHint(portPath);
    // Defensive: callers pass a wire-parsed (already sanitized) status, but the
    // write boundary re-applies the same policy so the stored registry can never
    // hold an unsafe identity, invalid provisioning state, or unsanitized display
    // string.
    const safeStatus = sanitizeDeviceStatusSnapshot(status);
    if (safeStatus === null) {
      throw new ConfigError("invalid_device", "Refusing to store a device with an unsafe identity.");
    }
    const safeDevice = safeStatus.device;
    const index = config.devices.findIndex((candidate) => candidate.deviceId === safeDevice.deviceId);

    if (index >= 0) {
      // Status refresh must not wipe local metadata such as label.
      const existing = config.devices[index];
      config.devices[index] = {
        ...existing,
        transport: "usb",
        lastPortHint,
        lastSeenAt,
        lastStatus: safeStatus,
      };
    } else {
      config.devices.push({
        deviceId: safeDevice.deviceId,
        transport: "usb",
        lastPortHint,
        lastSeenAt,
        label: null,
        lastStatus: safeStatus,
      });
    }

    if (options.setActive === true) {
      config.activeDeviceId = safeDevice.deviceId;
    }

    await this.writeConfig(config);
    return config;
  }

  async setDeviceMetadata(input: SetDeviceMetadataInput): Promise<DeviceRecord> {
    if (!isSafeDeviceId(input.deviceId)) {
      throw new ConfigError("invalid_device_id", "deviceId is not a valid device identifier.");
    }
    if (!Object.prototype.hasOwnProperty.call(input, "label")) {
      throw new ConfigError("invalid_params", "set_device_metadata requires at least one metadata field.");
    }
    if (!isValidLabel(input.label)) {
      throw new ConfigError(
        "invalid_params",
        `label must be null or a 1-${MAX_LABEL_LENGTH} character string.`,
      );
    }

    const config = await this.load();
    const index = config.devices.findIndex((candidate) => candidate.deviceId === input.deviceId);
    if (index < 0) {
      throw new ConfigError("device_not_found", "Device is not known to Agent-Q.");
    }

    const record: DeviceRecord = {
      ...config.devices[index],
      label: input.label ?? null,
    };
    config.devices[index] = record;
    await this.writeConfig(config);
    return record;
  }

  async setActiveDevice(deviceId: string, purpose?: string): Promise<DeviceRecord> {
    if (!isSafeDeviceId(deviceId)) {
      throw new ConfigError("invalid_device_id", "deviceId is not a valid device identifier.");
    }
    if (purpose !== undefined) {
      if (RESERVED_PURPOSES.has(purpose)) {
        throw new ConfigError(
          "invalid_params",
          `purpose '${purpose}' is reserved. Omit purpose to set the default device.`,
        );
      }
      if (!isValidPurpose(purpose)) {
        throw new ConfigError(
          "invalid_params",
          "purpose must be 1-32 characters of [A-Za-z0-9_.-].",
        );
      }
    }

    const config = await this.load();
    const record = config.devices.find((candidate) => candidate.deviceId === deviceId);
    if (record === undefined) {
      throw new ConfigError("device_not_found", "Device is not known to Agent-Q.");
    }

    if (purpose === undefined) {
      config.activeDeviceId = deviceId;
    } else {
      config.activeDeviceIdsByPurpose[purpose] = deviceId;
    }
    await this.writeConfig(config);
    return record;
  }

  async getActiveDevice(purpose?: string): Promise<DeviceRecord | undefined> {
    if (purpose !== undefined && RESERVED_PURPOSES.has(purpose)) {
      throw new ConfigError(
        "invalid_params",
        `purpose '${purpose}' is reserved. Omit purpose to read the default device.`,
      );
    }
    if (purpose !== undefined && !isValidPurpose(purpose)) {
      throw new ConfigError(
        "invalid_params",
        "purpose must be 1-32 characters of [A-Za-z0-9_.-].",
      );
    }

    const config = await this.load();
    // Read the purpose map with an own-property lookup so an inherited name (for
    // example "toString" or "hasOwnProperty") can never resolve to a prototype
    // value instead of an actual routing entry.
    const deviceId =
      purpose === undefined
        ? config.activeDeviceId
        : Object.prototype.hasOwnProperty.call(config.activeDeviceIdsByPurpose, purpose)
          ? config.activeDeviceIdsByPurpose[purpose]
          : undefined;
    if (deviceId === null || deviceId === undefined || deviceId.length === 0) {
      return undefined;
    }
    return config.devices.find((candidate) => candidate.deviceId === deviceId);
  }
}

function toDeviceListing(record: DeviceRecord, config: DeviceConfig): DeviceListing {
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
 * self-consistent instead of returning `device_not_found` for a stale route.
 *
 * Stable exported shape. Internally this is the report-free view of the
 * pipeline's reference-pruning pass ({@link pruneReferences}); load and write
 * thread a NormalizationReport through that pass instead.
 */
export function normalizeReferences(config: DeviceConfig): DeviceConfig {
  return pruneReferences(config, emptyReport());
}

// Every transformation Agent-Q applies to a stored (possibly hand-edited) config
// is recorded here, so the operator warning can never under-report. One report is
// threaded through the whole pipeline rather than merged from per-pass objects,
// which removes the merge step where a newly added field could be forgotten.
interface NormalizationReport {
  droppedRecords: number;
  droppedRoutes: number;
  clearedActiveDeviceId: number;
  coercedLabels: number;
  coercedTimestamps: number;
  sanitizedDeviceDisplayText: number;
  sanitizedPortHints: number;
}

function emptyReport(): NormalizationReport {
  return {
    droppedRecords: 0,
    droppedRoutes: 0,
    clearedActiveDeviceId: 0,
    coercedLabels: 0,
    coercedTimestamps: 0,
    sanitizedDeviceDisplayText: 0,
    sanitizedPortHints: 0,
  };
}

function reportTotal(report: NormalizationReport): number {
  return (
    report.droppedRecords +
    report.droppedRoutes +
    report.clearedActiveDeviceId +
    report.coercedLabels +
    report.coercedTimestamps +
    report.sanitizedDeviceDisplayText +
    report.sanitizedPortHints
  );
}

interface RecognizedConfig {
  activeDeviceId: string | null;
  activeDeviceIdsByPurpose: Record<string, unknown>;
  devices: unknown[];
}

// THE single config-normalization pipeline. Both load() (untrusted disk input)
// and writeConfig() (defensive re-normalization of in-memory state) go through
// here, and every drop/reset/sanitize/prune is recorded in one report. An empty
// report therefore means the input was already fully normalized: there is no path
// that changes the config without recording it. Returns undefined only when the
// envelope is not a recognized schema — a wholesale fallback to defaults, not a
// field-level normalization, which the caller surfaces separately.
function normalizeDeviceConfig(
  input: unknown,
): { config: DeviceConfig; report: NormalizationReport } | undefined {
  const recognized = recognizeConfigShape(input);
  if (recognized === undefined) {
    return undefined;
  }
  const report = emptyReport();
  const assembled = assembleConfig(recognized, report);
  const config = pruneReferences(assembled, report);
  return { config, report };
}

// Top-level envelope gate. A config whose envelope is wrong or whose schema
// version is not current is treated as foreign (the caller uses defaults);
// individual current-schema device records and routing entries are normalized
// at the field-entry boundary rather than rejected wholesale, so one bad record
// cannot discard the whole registry.
function recognizeConfigShape(value: unknown): RecognizedConfig | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  if (!(typeof value.activeDeviceId === "string" || value.activeDeviceId === null)) {
    return undefined;
  }
  if (value.schemaVersion === CONFIG_SCHEMA_VERSION) {
    if (!isRecord(value.activeDeviceIdsByPurpose) || !Array.isArray(value.devices)) {
      return undefined;
    }
    return {
      activeDeviceId: value.activeDeviceId,
      activeDeviceIdsByPurpose: value.activeDeviceIdsByPurpose,
      devices: value.devices,
    };
  }
  return undefined;
}

// Build a clean registry from loosely-typed input. The disk-ingress trust
// boundary, mirroring protocol.ts at the wire: records that cannot be made safe
// are dropped, duplicates removed, salvageable records sanitized, malformed
// routes discarded. Every change is recorded in `report`.
function assembleConfig(recognized: RecognizedConfig, report: NormalizationReport): DeviceConfig {
  const normalizedDevices: DeviceRecord[] = [];
  const seenDeviceIds = new Set<string>();
  for (const device of recognized.devices) {
    const record = normalizeDeviceRecord(device, report);
    if (record === null) {
      continue;
    }
    if (seenDeviceIds.has(record.deviceId)) {
      // Duplicate deviceId from a hand-edited config: keep the first, drop the rest.
      report.droppedRecords += 1;
      continue;
    }
    seenDeviceIds.add(record.deviceId);
    normalizedDevices.push(record);
  }

  // Purpose names are validated before being used as map keys (isValidPurpose
  // rejects prototype-sensitive names); reads elsewhere use own-property lookups.
  const normalizedPurposes: Record<string, string> = {};
  for (const [purpose, deviceId] of Object.entries(recognized.activeDeviceIdsByPurpose)) {
    if (isValidPurpose(purpose) && isSafeDeviceId(deviceId)) {
      normalizedPurposes[purpose] = deviceId;
    } else {
      report.droppedRoutes += 1;
    }
  }

  // A malformed (non-safe) activeDeviceId is reset to null and counted; a
  // well-formed but dangling one is handled by pruneReferences.
  let activeDeviceId: string | null = null;
  if (isSafeDeviceId(recognized.activeDeviceId)) {
    activeDeviceId = recognized.activeDeviceId;
  } else if (recognized.activeDeviceId !== null) {
    report.clearedActiveDeviceId += 1;
  }

  return {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    activeDeviceId,
    activeDeviceIdsByPurpose: normalizedPurposes,
    devices: normalizedDevices,
  };
}

// Drop routing selections (and a dangling default active id) that point at
// devices not present in `devices`, recording each removal in `report`.
function pruneReferences(config: DeviceConfig, report: NormalizationReport): DeviceConfig {
  const knownDeviceIds = new Set(config.devices.map((device) => device.deviceId));

  let activeDeviceId = config.activeDeviceId;
  if (activeDeviceId !== null && !knownDeviceIds.has(activeDeviceId)) {
    // Well-formed id that names no known device: a dangling active selection.
    activeDeviceId = null;
    report.clearedActiveDeviceId += 1;
  }

  const activeDeviceIdsByPurpose: Record<string, string> = {};
  for (const [purpose, deviceId] of Object.entries(config.activeDeviceIdsByPurpose)) {
    if (knownDeviceIds.has(deviceId)) {
      activeDeviceIdsByPurpose[purpose] = deviceId;
    } else {
      report.droppedRoutes += 1;
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

// Normalize one stored device record to a safe DeviceRecord, or null when its
// identity cannot be trusted. deviceId, transport, and the cached device's
// identity are REJECTED when malformed (the record is dropped); display text,
// label, port hint, and timestamp are sanitized or reset to a safe value. Every
// such change is recorded in `report`, so a silently-altered field cannot escape
// the operator warning.
function normalizeDeviceRecord(value: unknown, report: NormalizationReport): DeviceRecord | null {
  if (!isRecord(value) || !isSafeDeviceId(value.deviceId) || value.transport !== "usb") {
    report.droppedRecords += 1;
    return null;
  }
  if (!isRecord(value.lastStatus)) {
    report.droppedRecords += 1;
    return null;
  }
  const rawStatus = value.lastStatus;
  const status = sanitizeDeviceStatusSnapshot(rawStatus);
  if (status === null) {
    report.droppedRecords += 1;
    return null;
  }
  const rawDevice = rawStatus.device;
  const device = status.device;
  // Identity invariant: the record id and the cached device id must name the same
  // device. A hand-edited config that splits them would route/select one id while
  // exposing cached status for another, so the record is dropped.
  if (device.deviceId !== value.deviceId) {
    report.droppedRecords += 1;
    return null;
  }
  // Stripping control bytes from (or truncating) firmwareName, hardware, or
  // firmwareVersion is a normalization too; count each present-but-rewritten
  // field so the warning reports it (a missing field defaulting to "" is not
  // counted, matching the label/timestamp rule).
  report.sanitizedDeviceDisplayText += countSanitizedDisplayFields(rawDevice, device);

  const rawLabel = value.label;
  let label: string | null;
  if (isValidLabel(rawLabel)) {
    label = rawLabel;
  } else {
    label = null;
    // A present-but-invalid label was reset; a missing label (null/undefined) is
    // normal and not counted.
    if (rawLabel !== undefined && rawLabel !== null) {
      report.coercedLabels += 1;
    }
  }

  let lastSeenAt: string;
  if (isIsoTimestamp(value.lastSeenAt)) {
    lastSeenAt = value.lastSeenAt;
  } else {
    lastSeenAt = EPOCH_ISO;
    if (value.lastSeenAt !== undefined) {
      report.coercedTimestamps += 1;
    }
  }

  const lastPortHint = sanitizePortHint(value.lastPortHint);
  // A present-but-rewritten port hint is a sanitization; a missing one is not.
  if (value.lastPortHint !== undefined && lastPortHint !== value.lastPortHint) {
    report.sanitizedPortHints += 1;
  }

  return {
    deviceId: value.deviceId,
    transport: "usb",
    lastPortHint,
    lastSeenAt,
    label,
    lastStatus: status,
  };
}

// Number of device display-text fields that sanitization changed. Only a field
// that was PRESENT on disk and differs from its sanitized form counts, so a clean
// value adds nothing and a missing field (defaulted to "") is not counted —
// consistent with how labels and timestamps treat a missing value.
function countSanitizedDisplayFields(rawDevice: unknown, sanitized: DeviceStatus): number {
  if (!isRecord(rawDevice)) {
    return 0;
  }
  const fields: Array<"firmwareName" | "hardware" | "firmwareVersion"> = [
    "firmwareName",
    "hardware",
    "firmwareVersion",
  ];
  let count = 0;
  for (const field of fields) {
    if (rawDevice[field] !== undefined && rawDevice[field] !== sanitized[field]) {
      count += 1;
    }
  }
  return count;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
