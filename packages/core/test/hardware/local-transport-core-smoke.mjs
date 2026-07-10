import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { ConfigStore } from "../../dist/config.js";
import { DeviceCore } from "../../dist/core.js";
import { SerialPortUsbDriver } from "../../dist/usb.js";

const firstOpticalPayload = process.env.LOCAL_TRANSPORT_HW_OPTICAL_PAYLOAD ?? "";
const signingTxBytes = (process.env.LOCAL_TRANSPORT_HW_SIGN_TX_BYTES ?? "").replace(/\s+/g, "");
const signingNetwork = process.env.LOCAL_TRANSPORT_HW_SIGN_NETWORK ?? "";

if (firstOpticalPayload.length === 0) {
  throw new Error("Set LOCAL_TRANSPORT_HW_OPTICAL_PAYLOAD.");
}
if (signingTxBytes.length === 0) {
  throw new Error("Set LOCAL_TRANSPORT_HW_SIGN_TX_BYTES to canonical base64 transaction bytes.");
}
if (signingNetwork.length === 0) {
  throw new Error("Set LOCAL_TRANSPORT_HW_SIGN_NETWORK to the transaction network.");
}

async function readSecondOpticalPayload() {
  const configured = process.env.LOCAL_TRANSPORT_HW_SECOND_OPTICAL_PAYLOAD ?? "";
  if (configured.length > 0) {
    return configured;
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error(
      "Set LOCAL_TRANSPORT_HW_SECOND_OPTICAL_PAYLOAD or run interactively to enter a fresh second QR payload.",
    );
  }
  const input = createInterface({ input: process.stdin, output: process.stdout });
  try {
    console.log("hardware stage: awaiting a fresh second QR payload");
    return (await input.question(
      "Second aqlt payload: ",
    )).trim();
  } finally {
    input.close();
  }
}

const directory = await mkdtemp(join(tmpdir(), "agent-q-local-transport-smoke-"));
let core = null;
let connectedDeviceId = null;
try {
  core = new DeviceCore(
    new ConfigStore(join(directory, "config.json")),
    new SerialPortUsbDriver(),
  );
  console.log("hardware stage: opening first BLE session");
  const connected = await core.connectDevice({ transport: "ble", opticalPayload: firstOpticalPayload });
  assert.equal(connected.source, "connected");
  assert.equal(connected.device.deviceId, connected.deviceId);
  connectedDeviceId = connected.deviceId;
  console.log("hardware stage: first protocol session connected");

  const capabilities = await core.getCapabilities({ deviceId: connected.deviceId });
  assert.equal(capabilities.source, "live", JSON.stringify(capabilities));
  const accounts = await core.getAccounts({ deviceId: connected.deviceId });
  assert.equal(accounts.source, "live", JSON.stringify(accounts));
  console.log("hardware stage: capabilities and accounts received");

  console.log("hardware stage: waiting for transaction signing result");
  const signed = await core.signTransaction({
    deviceId: connected.deviceId,
    chain: "sui",
    method: "sign_transaction",
    network: signingNetwork,
    txBytes: signingTxBytes,
  });
  assert.equal(signed.source, "live", JSON.stringify({
    source: signed.source,
    status: "status" in signed ? signed.status : undefined,
  }));
  assert.equal(signed.status, "signed");
  console.log("hardware stage: transaction signing result received");

  console.log("hardware stage: closing first protocol session");
  const disconnected = await core.disconnectDevice({ deviceId: connected.deviceId });
  assert.equal(disconnected.source, "disconnected");
  assert.equal(disconnected.reason, "firmware_confirmed");
  connectedDeviceId = null;
  console.log("hardware stage: first protocol session closed");

  const secondOpticalPayload = await readSecondOpticalPayload();
  assert.notEqual(secondOpticalPayload, firstOpticalPayload, "the second session requires a fresh QR payload");
  console.log("hardware stage: opening second BLE session");
  const reconnected = await core.connectDevice({
    transport: "ble",
    opticalPayload: secondOpticalPayload,
  });
  assert.equal(reconnected.source, "connected");
  assert.equal(reconnected.deviceId, connected.deviceId);
  connectedDeviceId = reconnected.deviceId;
  console.log("hardware stage: second protocol session connected");
  const reconnectedCapabilities = await core.getCapabilities({ deviceId: reconnected.deviceId });
  assert.equal(reconnectedCapabilities.source, "live", JSON.stringify(reconnectedCapabilities));
  const reconnectedDisconnect = await core.disconnectDevice({ deviceId: reconnected.deviceId });
  assert.equal(reconnectedDisconnect.source, "disconnected");
  assert.equal(reconnectedDisconnect.reason, "firmware_confirmed");
  connectedDeviceId = null;
  console.log("hardware stage: second protocol session closed");

  console.log(JSON.stringify({
    connected: true,
    capabilities: "live",
    accounts: "live",
    signing: "signed",
    disconnected: true,
    reconnected: true,
    reconnectedCapabilities: "live",
    reconnectedDisconnected: true,
  }));
} finally {
  if (core !== null && connectedDeviceId !== null) {
    await core.disconnectDevice({ deviceId: connectedDeviceId }).catch(() => {});
  }
  await rm(directory, { recursive: true, force: true });
}
