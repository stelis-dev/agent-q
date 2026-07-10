import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { DeviceRequestError } from "./errors.js";
import { ProtocolError } from "./protocol-error.js";
import {
  LOCAL_TRANSPORT_FRAME_HEADER_BYTES as FRAME_HEADER_BYTES,
  LOCAL_TRANSPORT_CARRIER_CLEANUP_TIMEOUT_MS,
  LOCAL_TRANSPORT_HANDSHAKE_TIMEOUT_MS,
  LOCAL_TRANSPORT_MIN_ENCRYPTED_FRAME_PAYLOAD_BYTES,
  LOCAL_TRANSPORT_PAIRING_EXPIRY_SECONDS as PAIRING_EXPIRY_SECONDS,
  LOCAL_TRANSPORT_RESPONSE_TIMEOUT_MS,
  LOCAL_TRANSPORT_TAG_BYTES as TAG_BYTES,
  openLocalTransportProtocolSessionWithRandomSource,
  parseLocalTransportOpticalPayload,
  runLocalTransportOperation,
  type LocalTransportOpticalPayload,
  type LocalTransportProtocolSessionLike,
} from "./local-transport-protocol.js";

export { parseLocalTransportOpticalPayload } from "./local-transport-protocol.js";
export type { LocalTransportOpticalPayload } from "./local-transport-protocol.js";

const REQUEST_LINE_CAP = 4096;
const RESPONSE_LINE_CAP = 16 * 1024;
const DEFAULT_SCAN_TIMEOUT_MS = PAIRING_EXPIRY_SECONDS * 1_000;
const DEFAULT_ADAPTER_POWER_TIMEOUT_MS = 10_000;
const ATT_HEADER_BYTES = 3;
const MIN_BLE_ATT_MTU_BYTES =
  ATT_HEADER_BYTES + FRAME_HEADER_BYTES + TAG_BYTES +
  LOCAL_TRANSPORT_MIN_ENCRYPTED_FRAME_PAYLOAD_BYTES;
const DEFAULT_BLE_ATT_MTU_BYTES = 509;
const require = createRequire(import.meta.url);

/** @internal */
export interface LocalTransportBleGatewayOptions {
  noble?: NobleLike;
  randomBytes?: (length: number) => Uint8Array;
  scanTimeoutMs?: number;
  handshakeTimeoutMs?: number;
  responseTimeoutMs?: number;
  adapterPowerTimeoutMs?: number;
  cleanupTimeoutMs?: number;
}

/** @internal */
export interface LocalTransportBleSession extends LocalTransportProtocolSessionLike {}

/** @internal */
export type NobleLike = {
  readonly state: string;
  on(event: "stateChange", listener: (state: string) => void): void;
  on(event: "discover", listener: (peripheral: NoblePeripheralLike) => void): void;
  off?(event: "stateChange", listener: (state: string) => void): void;
  off?(event: "discover", listener: (peripheral: NoblePeripheralLike) => void): void;
  removeAllListeners?(): void;
  reset?(): void;
  stop?(): void;
  startScanningAsync(serviceUuids: string[], allowDuplicates: boolean): Promise<void>;
  stopScanningAsync(): Promise<void>;
};

/** @internal */
export type NoblePeripheralLike = {
  readonly id?: string;
  readonly mtu?: number | null;
  readonly advertisement: {
    readonly serviceData?: Array<{ uuid: string; data: Buffer }>;
  };
  connectAsync(): Promise<void>;
  disconnectAsync(): Promise<void>;
  once(event: "disconnect", listener: (error?: Error | null) => void): void;
  removeListener?(event: "disconnect", listener: (error?: Error | null) => void): void;
  discoverSomeServicesAndCharacteristicsAsync(
    serviceUuids: string[],
    characteristicUuids: string[],
  ): Promise<{ services: unknown[]; characteristics: NobleCharacteristicLike[] }>;
};

/** @internal */
export type NobleCharacteristicLike = {
  readonly uuid: string;
  readonly properties: string[];
  once(event: "data", listener: (chunk: Uint8Array) => void): void;
  on(event: "data", listener: (chunk: Uint8Array) => void): void;
  removeListener(event: "data", listener: (chunk: Uint8Array) => void): void;
  subscribeAsync(): Promise<void>;
  unsubscribeAsync(): Promise<void>;
  writeAsync(data: Uint8Array, withoutResponse: boolean): Promise<void>;
};

type CharacteristicDataWaiter = {
  promise: Promise<Uint8Array>;
  cancel: (error: DeviceRequestError) => void;
};

type NobleAdapterSession<T> = {
  value: T;
  release: () => Promise<void>;
};

class NobleAdapterCoordinator {
  readonly #factory: () => NobleLike;
  readonly #shutdownWhenIdle: boolean;
  #noble: NobleLike | null = null;
  #connectTail: Promise<void> = Promise.resolve();
  #scheduledConnects = 0;
  #activeSessions = 0;

  constructor(factory: () => NobleLike, shutdownWhenIdle: boolean) {
    this.#factory = factory;
    this.#shutdownWhenIdle = shutdownWhenIdle;
  }

  async establish<T>(operation: (noble: NobleLike) => Promise<T>): Promise<NobleAdapterSession<T>> {
    this.#scheduledConnects += 1;
    const previous = this.#connectTail;
    const run = previous.then(async () => {
      const noble = this.#noble ?? this.#createNoble();
      try {
        const value = await operation(noble);
        this.#activeSessions += 1;
        let released = false;
        return {
          value,
          release: async () => {
            if (released) {
              return;
            }
            released = true;
            this.#activeSessions -= 1;
            await this.#shutdownIfIdle();
          },
        };
      } finally {
        this.#scheduledConnects -= 1;
        await this.#shutdownIfIdle();
      }
    });
    this.#connectTail = run.then(noop, noop);
    return run;
  }

  #createNoble(): NobleLike {
    const noble = this.#factory();
    this.#noble = noble;
    return noble;
  }

  async #shutdownIfIdle(): Promise<void> {
    if (
      !this.#shutdownWhenIdle ||
      this.#scheduledConnects !== 0 ||
      this.#activeSessions !== 0 ||
      this.#noble === null
    ) {
      return;
    }
    const noble = this.#noble;
    this.#noble = null;
    await shutdownNoble(noble);
  }
}

const injectedNobleCoordinators = new WeakMap<object, NobleAdapterCoordinator>();
const defaultNobleCoordinator = new NobleAdapterCoordinator(loadDefaultNoble, true);

function coordinatorForInjectedNoble(noble: NobleLike): NobleAdapterCoordinator {
  const existing = injectedNobleCoordinators.get(noble);
  if (existing !== undefined) {
    return existing;
  }
  const coordinator = new NobleAdapterCoordinator(() => noble, false);
  injectedNobleCoordinators.set(noble, coordinator);
  return coordinator;
}

/** @internal */
export class LocalTransportBleGateway {
  readonly #adapter: NobleAdapterCoordinator;
  #consumed = false;
  readonly #randomBytes: (length: number) => Uint8Array;
  readonly #scanTimeoutMs: number;
  readonly #handshakeTimeoutMs: number;
  readonly #responseTimeoutMs: number;
  readonly #adapterPowerTimeoutMs: number;
  readonly #cleanupTimeoutMs: number;

  constructor(options: LocalTransportBleGatewayOptions) {
    this.#adapter = options.noble === undefined
      ? defaultNobleCoordinator
      : coordinatorForInjectedNoble(options.noble);
    this.#randomBytes = options.randomBytes ?? ((length) => randomBytes(length));
    this.#scanTimeoutMs = options.scanTimeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS;
    this.#handshakeTimeoutMs = options.handshakeTimeoutMs ?? LOCAL_TRANSPORT_HANDSHAKE_TIMEOUT_MS;
    this.#responseTimeoutMs = options.responseTimeoutMs ?? LOCAL_TRANSPORT_RESPONSE_TIMEOUT_MS;
    this.#adapterPowerTimeoutMs = options.adapterPowerTimeoutMs ?? DEFAULT_ADAPTER_POWER_TIMEOUT_MS;
    this.#cleanupTimeoutMs = options.cleanupTimeoutMs ?? LOCAL_TRANSPORT_CARRIER_CLEANUP_TIMEOUT_MS;
  }

  async connect(opticalPayload: string): Promise<LocalTransportBleSession> {
    if (this.#consumed) {
      throw new DeviceRequestError("invalid_state", "Local transport gateway instance was already used.", false);
    }
    this.#consumed = true;
    const payload = parseLocalTransportOpticalPayload(opticalPayload);
    const adapterSession = await this.#adapter.establish(async (noble) => {
      const peripheral = await this.#scanForPayloadTarget(noble, payload);
      try {
        await runLocalTransportOperation(
          "BLE connection",
          this.#handshakeTimeoutMs,
          () => peripheral.connectAsync(),
          () => safeDisconnect(peripheral, this.#cleanupTimeoutMs),
        );
        const { control, data } = await runLocalTransportOperation(
          "BLE service discovery",
          this.#handshakeTimeoutMs,
          () => discoverLocalTransportCharacteristics(peripheral, payload),
          () => safeDisconnect(peripheral, this.#cleanupTimeoutMs),
        );
        await runLocalTransportOperation(
          "control indication subscription",
          this.#handshakeTimeoutMs,
          () => control.subscribeAsync(),
          () => boundedUnsubscribe(control, this.#cleanupTimeoutMs),
        );
        await runLocalTransportOperation(
          "data indication subscription",
          this.#handshakeTimeoutMs,
          () => data.subscribeAsync(),
          () => boundedUnsubscribe(data, this.#cleanupTimeoutMs),
        );
        return { peripheral, control, data };
      } catch (error) {
        await safeDisconnect(peripheral, this.#cleanupTimeoutMs);
        throw mapLocalTransportError(error);
      }
    });
    try {
      const { peripheral, control, data } = adapterSession.value;
      return await openLocalTransportProtocolSessionWithRandomSource({
        opticalPayload: payload,
        handshakeTimeoutMs: this.#handshakeTimeoutMs,
        beginControlWait: (label, timeoutMs) =>
          waitForCharacteristicData(control, timeoutMs, label),
        writeControl: (bytes) => control.writeAsync(bytes, false),
        defaultResponseTimeoutMs: this.#responseTimeoutMs,
        cleanupTimeoutMs: this.#cleanupTimeoutMs,
        encryptedFramePayloadBytes: encryptedFramePayloadBytesForMtu(peripheral.mtu),
        writeData: (bytes) => data.writeAsync(bytes, false),
        addDataListener: (listener) => data.on("data", listener),
        removeDataListener: (listener) => data.removeListener("data", listener),
        onCarrierClosed: (listener) => {
          peripheral.once("disconnect", listener);
          return () => peripheral.removeListener?.("disconnect", listener);
        },
        closeCarrier: async () => {
          await Promise.allSettled([
            boundedUnsubscribe(data, this.#cleanupTimeoutMs),
            boundedUnsubscribe(control, this.#cleanupTimeoutMs),
          ]);
          await safeDisconnect(peripheral, this.#cleanupTimeoutMs);
          await adapterSession.release();
        },
      }, this.#randomBytes);
    } catch (error) {
      const { peripheral, control, data } = adapterSession.value;
      await Promise.allSettled([
        boundedUnsubscribe(data, this.#cleanupTimeoutMs),
        boundedUnsubscribe(control, this.#cleanupTimeoutMs),
      ]);
      await safeDisconnect(peripheral, this.#cleanupTimeoutMs);
      await adapterSession.release();
      throw mapLocalTransportError(error);
    }
  }

  async #scanForPayloadTarget(
    noble: NobleLike,
    payload: LocalTransportOpticalPayload,
  ): Promise<NoblePeripheralLike> {
    await waitForNoblePoweredOn(noble, this.#adapterPowerTimeoutMs);
    const scanTimeoutMs = Math.min(
      this.#scanTimeoutMs,
      payload.expiresInSeconds * 1_000,
    );
    const deadline = Date.now() + scanTimeoutMs;
    let connecting = false;
    return await new Promise<NoblePeripheralLike>((resolve, reject) => {
      const onDiscover = async (peripheral: NoblePeripheralLike): Promise<void> => {
        if (connecting) {
          return;
        }
        const serviceData = (peripheral.advertisement.serviceData ?? []).find(
          (entry) => entry.uuid.toLowerCase() === payload.serviceUuid,
        );
        if (serviceData === undefined || serviceData.data.length !== 8) {
          return;
        }
        if (!serviceData.data.equals(Buffer.from(payload.identityFingerprint))) {
          return;
        }
        connecting = true;
        cleanup();
        try {
          const remainingMs = Math.max(1, deadline - Date.now());
          await runLocalTransportOperation(
            "BLE scan stop",
            remainingMs,
            () => noble.stopScanningAsync(),
          );
          resolve(peripheral);
        } catch (error) {
          reject(error);
        }
      };
      const timer = setInterval(() => {
        if (Date.now() <= deadline) {
          return;
        }
        cleanup();
        void runLocalTransportOperation(
          "expired BLE scan stop",
          this.#cleanupTimeoutMs,
          () => noble.stopScanningAsync(),
        ).catch(noop);
        reject(new DeviceRequestError("timeout", "Timed out scanning for local transport device.", true));
      }, 250);
      const cleanup = (): void => {
        clearInterval(timer);
        removeNobleListener(noble, "discover", onDiscover);
      };
      noble.on("discover", onDiscover);
      runLocalTransportOperation(
        "BLE scan start",
        scanTimeoutMs,
        () => noble.startScanningAsync([payload.serviceUuid], true),
        () => runLocalTransportOperation(
          "late BLE scan stop",
          this.#cleanupTimeoutMs,
          () => noble.stopScanningAsync(),
        ).catch(noop),
      ).catch((error) => {
        cleanup();
        reject(error);
      });
    });
  }
}

function encryptedFramePayloadBytesForMtu(mtu: number | null | undefined): number {
  const effectiveMtu = mtu ?? DEFAULT_BLE_ATT_MTU_BYTES;
  if (!Number.isInteger(effectiveMtu) || effectiveMtu < MIN_BLE_ATT_MTU_BYTES) {
    throw new DeviceRequestError("unsupported_transport", "BLE ATT MTU is too small for local transport frames.", true);
  }
  return effectiveMtu - ATT_HEADER_BYTES - FRAME_HEADER_BYTES - TAG_BYTES;
}

function loadDefaultNoble(): NobleLike {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const module = require("@stoprocent/noble") as {
    withBindings?: () => NobleLike;
  };
  if (typeof module.withBindings !== "function") {
    throw new DeviceRequestError(
      "unsupported_transport",
      "BLE adapter runtime cannot create an isolated binding instance.",
      true,
    );
  }
  return module.withBindings();
}

async function waitForNoblePoweredOn(noble: NobleLike, timeoutMs: number): Promise<void> {
  if (noble.state === "poweredOn") {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const onStateChange = (state: string): void => {
      if (state !== "poweredOn") {
        return;
      }
      cleanup();
      resolve();
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      removeNobleListener(noble, "stateChange", onStateChange);
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new DeviceRequestError("unsupported_transport", `BLE adapter is not powered on (${noble.state}).`, true));
    }, timeoutMs);
    noble.on("stateChange", onStateChange);
  });
}

async function discoverLocalTransportCharacteristics(
  peripheral: NoblePeripheralLike,
  payload: LocalTransportOpticalPayload,
): Promise<{ control: NobleCharacteristicLike; data: NobleCharacteristicLike }> {
  const { characteristics } = await peripheral.discoverSomeServicesAndCharacteristicsAsync(
    [payload.serviceUuid],
    [payload.controlCharacteristicUuid, payload.dataCharacteristicUuid],
  );
  const control = characteristics.find((characteristic) =>
    characteristic.uuid.toLowerCase() === payload.controlCharacteristicUuid);
  const data = characteristics.find((characteristic) =>
    characteristic.uuid.toLowerCase() === payload.dataCharacteristicUuid);
  if (control === undefined || data === undefined) {
    throw new DeviceRequestError("handshake_failed", "Local transport characteristics are unavailable.", true);
  }
  return { control, data };
}

function waitForCharacteristicData(
  characteristic: NobleCharacteristicLike,
  timeoutMs: number,
  label: string,
): CharacteristicDataWaiter {
  let cancel = (_error: DeviceRequestError): void => {};
  const promise = new Promise<Uint8Array>((resolve, reject) => {
    let settled = false;
    const onData = (chunk: Uint8Array): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve(chunk.slice());
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      characteristic.removeListener("data", onData);
    };
    cancel = (error): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(error);
    };
    const timer = setTimeout(() => {
      cancel(new DeviceRequestError("timeout", `Timed out waiting for ${label}.`, true));
    }, timeoutMs);
    characteristic.once("data", onData);
  });
  return { promise, cancel: (error) => cancel(error) };
}

function removeNobleListener(
  noble: NobleLike,
  event: "stateChange" | "discover",
  listener: (value: never) => void,
): void {
  if (event === "stateChange") {
    noble.off?.("stateChange", listener as (state: string) => void);
    return;
  }
  noble.off?.("discover", listener as (peripheral: NoblePeripheralLike) => void);
}

async function boundedUnsubscribe(
  characteristic: NobleCharacteristicLike,
  timeoutMs: number,
): Promise<void> {
  await runLocalTransportOperation(
    "BLE indication unsubscribe",
    timeoutMs,
    () => characteristic.unsubscribeAsync(),
  ).catch(noop);
}

async function safeDisconnect(
  peripheral: NoblePeripheralLike,
  timeoutMs: number,
): Promise<void> {
  await runLocalTransportOperation(
    "BLE disconnect",
    timeoutMs,
    () => peripheral.disconnectAsync(),
  ).catch(noop);
}

async function shutdownNoble(noble: NobleLike): Promise<void> {
  await runLocalTransportOperation(
    "BLE adapter shutdown",
    LOCAL_TRANSPORT_CARRIER_CLEANUP_TIMEOUT_MS,
    () => noble.stopScanningAsync(),
  ).catch(noop);
  noble.removeAllListeners?.();
  noble.reset?.();
  noble.stop?.();
}

function errorCode(error: unknown): string | null {
  return error instanceof DeviceRequestError ? error.code : null;
}

function noop(): void {}

function mapLocalTransportError(error: unknown): DeviceRequestError {
  if (error instanceof DeviceRequestError) {
    return error;
  }
  if (error instanceof ProtocolError) {
    return new DeviceRequestError(error.code, error.message, error.code === "timeout");
  }
  return new DeviceRequestError("transport_error", "Local transport failed before a valid device response.", true);
}
