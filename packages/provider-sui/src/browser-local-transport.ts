import {
  LOCAL_TRANSPORT_CARRIER_CLEANUP_TIMEOUT_MS,
  LOCAL_TRANSPORT_HANDSHAKE_TIMEOUT_MS,
  LOCAL_TRANSPORT_MIN_ENCRYPTED_FRAME_PAYLOAD_BYTES,
  LOCAL_TRANSPORT_RESPONSE_TIMEOUT_MS,
  openLocalTransportProtocolSession,
  parseLocalTransportOpticalPayload,
  runLocalTransportOperation,
  type LocalTransportControlWaiter,
  type LocalTransportProtocolSessionLike,
} from "@stelis/agent-q-core/local-transport-internal";

type BluetoothValueEvent = Event & {
  target: { value?: DataView | null } | null;
};

type BrowserBluetoothCharacteristic = {
  readonly value?: DataView | null;
  startNotifications(): Promise<BrowserBluetoothCharacteristic>;
  stopNotifications(): Promise<BrowserBluetoothCharacteristic>;
  writeValueWithResponse(value: Uint8Array): Promise<void>;
  addEventListener(type: "characteristicvaluechanged", listener: (event: BluetoothValueEvent) => void): void;
  removeEventListener(type: "characteristicvaluechanged", listener: (event: BluetoothValueEvent) => void): void;
};

type BrowserBluetoothService = {
  getCharacteristic(characteristic: string): Promise<BrowserBluetoothCharacteristic>;
};

type BrowserBluetoothServer = {
  readonly connected: boolean;
  connect(): Promise<BrowserBluetoothServer>;
  getPrimaryService(service: string): Promise<BrowserBluetoothService>;
  disconnect(): void;
};

type BrowserBluetoothDevice = {
  readonly gatt?: BrowserBluetoothServer;
  addEventListener(type: "gattserverdisconnected", listener: () => void): void;
  removeEventListener(type: "gattserverdisconnected", listener: () => void): void;
};

type BrowserBluetooth = {
  requestDevice(options: {
    filters: Array<{
      services: string[];
      serviceData: Array<{ service: string; dataPrefix: Uint8Array }>;
    }>;
    optionalServices: string[];
  }): Promise<BrowserBluetoothDevice>;
};

type BrowserLocalTransportOptions = {
  handshakeTimeoutMs?: number;
  cleanupTimeoutMs?: number;
};

export function isBrowserLocalTransportAvailable(): boolean {
  return globalThis.isSecureContext === true &&
    browserBluetooth() !== null &&
    typeof globalThis.crypto?.getRandomValues === "function";
}

export async function openBrowserLocalTransport(
  opticalPayload: string,
  onCarrierClosed?: () => void,
  options: BrowserLocalTransportOptions = {},
): Promise<LocalTransportProtocolSessionLike> {
  if (!isBrowserLocalTransportAvailable()) {
    throw localTransportError(
      "unsupported_transport",
      "Web Bluetooth requires a secure context and a compatible browser.",
    );
  }
  const bluetooth = browserBluetooth();
  if (bluetooth === null) {
    throw localTransportError("unsupported_transport", "Web Bluetooth is unavailable.");
  }
  const payload = parseLocalTransportOpticalPayload(opticalPayload);
  const handshakeTimeoutMs = options.handshakeTimeoutMs ?? LOCAL_TRANSPORT_HANDSHAKE_TIMEOUT_MS;
  const cleanupTimeoutMs = options.cleanupTimeoutMs ?? LOCAL_TRANSPORT_CARRIER_CLEANUP_TIMEOUT_MS;
  const device = await bluetooth.requestDevice({
    filters: [{
      services: [payload.serviceUuid],
      serviceData: [{
        service: payload.serviceUuid,
        dataPrefix: payload.identityFingerprint,
      }],
    }],
    optionalServices: [payload.serviceUuid],
  });
  const server = device.gatt;
  if (server === undefined) {
    throw localTransportError("transport_error", "Selected Bluetooth device has no GATT server.");
  }

  let control: BrowserBluetoothCharacteristic | null = null;
  let data: BrowserBluetoothCharacteristic | null = null;
  try {
    const connectedServer = await runLocalTransportOperation(
      "browser BLE connection",
      handshakeTimeoutMs,
      () => server.connect(),
      () => server.disconnect(),
    );
    const service = await runLocalTransportOperation(
      "browser BLE service discovery",
      handshakeTimeoutMs,
      () => connectedServer.getPrimaryService(payload.serviceUuid),
    );
    control = await runLocalTransportOperation(
      "browser control characteristic discovery",
      handshakeTimeoutMs,
      () => service.getCharacteristic(payload.controlCharacteristicUuid),
    );
    data = await runLocalTransportOperation(
      "browser data characteristic discovery",
      handshakeTimeoutMs,
      () => service.getCharacteristic(payload.dataCharacteristicUuid),
    );
    await runLocalTransportOperation(
      "browser control notification subscription",
      handshakeTimeoutMs,
      () => control!.startNotifications(),
      () => stopNotifications(control, cleanupTimeoutMs),
    );
    await runLocalTransportOperation(
      "browser data notification subscription",
      handshakeTimeoutMs,
      () => data!.startNotifications(),
      () => stopNotifications(data, cleanupTimeoutMs),
    );
    const controlCharacteristic = control;
    const dataCharacteristic = data;
    const dataListeners = new Map<(bytes: Uint8Array) => void, (event: BluetoothValueEvent) => void>();
    let carrierClosed = false;
    return await openLocalTransportProtocolSession({
      opticalPayload: payload,
      handshakeTimeoutMs,
      beginControlWait: (label, timeoutMs) =>
        waitForCharacteristicValue(controlCharacteristic, label, timeoutMs),
      writeControl: (bytes) => controlCharacteristic.writeValueWithResponse(bytes),
      // Web Bluetooth does not expose the negotiated ATT MTU. Use the protocol
      // minimum instead of assuming the 509-byte maximum used by current
      // hardware; the browser/OS still owns the actual ATT write procedure.
      encryptedFramePayloadBytes: LOCAL_TRANSPORT_MIN_ENCRYPTED_FRAME_PAYLOAD_BYTES,
      defaultResponseTimeoutMs: LOCAL_TRANSPORT_RESPONSE_TIMEOUT_MS,
      cleanupTimeoutMs,
      writeData: (bytes) => dataCharacteristic.writeValueWithResponse(bytes),
      addDataListener: (listener) => {
        const eventListener = (event: BluetoothValueEvent): void => {
          const value = event.target?.value ?? dataCharacteristic.value ?? null;
          if (value !== null) {
            listener(new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice());
          }
        };
        dataListeners.set(listener, eventListener);
        dataCharacteristic.addEventListener("characteristicvaluechanged", eventListener);
      },
      removeDataListener: (listener) => {
        const eventListener = dataListeners.get(listener);
        if (eventListener !== undefined) {
          dataCharacteristic.removeEventListener("characteristicvaluechanged", eventListener);
          dataListeners.delete(listener);
        }
      },
      onCarrierClosed: (listener) => {
        const carrierListener = (): void => {
          listener();
          onCarrierClosed?.();
        };
        device.addEventListener("gattserverdisconnected", carrierListener);
        return () => device.removeEventListener("gattserverdisconnected", carrierListener);
      },
      closeCarrier: async () => {
        if (carrierClosed) {
          return;
        }
        carrierClosed = true;
        for (const eventListener of dataListeners.values()) {
          dataCharacteristic.removeEventListener("characteristicvaluechanged", eventListener);
        }
        dataListeners.clear();
        await Promise.allSettled([
          stopNotifications(dataCharacteristic, cleanupTimeoutMs),
          stopNotifications(controlCharacteristic, cleanupTimeoutMs),
        ]);
        if (server.connected) {
          server.disconnect();
        }
      },
    });
  } catch (error) {
    await Promise.allSettled([
      stopNotifications(control, cleanupTimeoutMs),
      stopNotifications(data, cleanupTimeoutMs),
    ]);
    if (server.connected) {
      server.disconnect();
    }
    throw error;
  }
}

function waitForCharacteristicValue(
  characteristic: BrowserBluetoothCharacteristic,
  label: string,
  timeoutMs: number,
): LocalTransportControlWaiter {
  let cancel = (_error: Error): void => {};
  const promise = new Promise<Uint8Array>((resolve, reject) => {
    let settled = false;
    const listener = (event: BluetoothValueEvent): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      const value = event.target?.value ?? characteristic.value ?? null;
      if (value === null) {
        reject(localTransportError("handshake_failed", `${label} is empty.`));
        return;
      }
      resolve(new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice());
    };
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(localTransportError("timeout", `Timed out waiting for ${label}.`));
    }, timeoutMs);
    const cleanup = (): void => {
      clearTimeout(timer);
      characteristic.removeEventListener("characteristicvaluechanged", listener);
    };
    cancel = (error): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(error);
    };
    characteristic.addEventListener("characteristicvaluechanged", listener);
  });
  return { promise, cancel };
}

async function stopNotifications(
  characteristic: BrowserBluetoothCharacteristic | null,
  timeoutMs: number,
): Promise<void> {
  if (characteristic !== null) {
    await runLocalTransportOperation(
      "browser notification cleanup",
      timeoutMs,
      () => characteristic.stopNotifications(),
    ).catch(() => undefined);
  }
}

function browserBluetooth(): BrowserBluetooth | null {
  return (globalThis.navigator as Navigator & { bluetooth?: BrowserBluetooth } | undefined)?.bluetooth ?? null;
}

function localTransportError(code: string, message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code });
}
