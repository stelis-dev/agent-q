import type {
  AgentQCore,
  ScanDevicesResult,
} from "@stelis/agent-q-core";
import { AgentQError, toAgentQError, toPublicError } from "@stelis/agent-q-core/adapter-internal";

export type StartupConnectCore = Pick<
  AgentQCore,
  | "scanDevices"
  | "selectDevice"
  | "connectDevice"
  | "getCapabilities"
  | "getAccounts"
>;

export interface StartupConnectOptions {
  deviceId?: string;
  purpose?: string;
}

export async function requestDeviceConnectionOnStart(
  core: StartupConnectCore,
  options: StartupConnectOptions,
  writeDiagnostic: (line: string) => void = (line) => {
    console.error(line);
  },
): Promise<void> {
  try {
    writeDiagnostic("Agent-Q sending a connection request. Confirm it on the device.");
    const scanResult = await core.scanDevices();
    const deviceId = chooseStartupConnectDeviceId(scanResult, options.deviceId);
    await core.selectDevice({ deviceId, purpose: options.purpose });
    const result = await core.connectDevice({
      deviceId,
      purpose: options.purpose,
      clientName: "Agent-Q",
    });
    writeDiagnostic(`Agent-Q device connection approved: ${result.deviceId}`);
    await writeStartupConnectionSummary(core, { deviceId, purpose: options.purpose }, writeDiagnostic);
  } catch (error) {
    const agentQError = toAgentQError(error);
    const publicError = toPublicError(agentQError.code, agentQError.retryable);
    writeDiagnostic(
      `Agent-Q connection request did not complete: ${publicError.code}. ${publicError.message}`,
    );
  }
}

async function writeStartupConnectionSummary(
  core: StartupConnectCore,
  input: { deviceId: string; purpose?: string },
  writeDiagnostic: (line: string) => void,
): Promise<void> {
  try {
    const [capabilitiesResult, accountsResult] = await Promise.all([
      core.getCapabilities(input),
      core.getAccounts(input),
    ]);
    if (accountsResult.source === "live") {
      const suiAddresses = accountsResult.accounts
        .filter((account) => account.chain === "sui")
        .map((account) => account.address);
      if (suiAddresses.length > 0) {
        writeDiagnostic(`Agent-Q Sui address: ${suiAddresses.join(", ")}`);
      } else {
        writeDiagnostic("Agent-Q Sui address: unavailable");
      }
    } else {
      writeDiagnostic(`Agent-Q accounts unavailable: ${accountsResult.reason}`);
    }

    if (capabilitiesResult.source === "live") {
      if (capabilitiesResult.signing !== undefined) {
        writeDiagnostic(`Agent-Q signing mode: ${capabilitiesResult.signing.authorization}`);
        const methods = capabilitiesResult.signing.methods
          .map((method) => `${method.chain}:${method.method}`)
          .join(", ");
        writeDiagnostic(`Agent-Q signing methods: ${methods}`);
      } else {
        writeDiagnostic("Agent-Q signing mode: unavailable");
      }
    } else {
      writeDiagnostic(`Agent-Q capabilities unavailable: ${capabilitiesResult.reason}`);
    }
  } catch (error) {
    const agentQError = toAgentQError(error);
    const publicError = toPublicError(agentQError.code, agentQError.retryable);
    writeDiagnostic(`Agent-Q connection summary unavailable: ${publicError.code}. ${publicError.message}`);
  }
}

function chooseStartupConnectDeviceId(scanResult: ScanDevicesResult, requestedDeviceId: string | undefined): string {
  if (requestedDeviceId !== undefined && requestedDeviceId.length > 0) {
    return requestedDeviceId;
  }

  const liveDeviceIds = scanResult.devices.map((device) => device.protocolResponse.device.deviceId);
  if (scanResult.activeDeviceId !== null && liveDeviceIds.includes(scanResult.activeDeviceId)) {
    return scanResult.activeDeviceId;
  }
  if (liveDeviceIds.length === 1) {
    return liveDeviceIds[0]!;
  }
  if (liveDeviceIds.length === 0) {
    const firstFailure = scanResult.failures[0];
    if (firstFailure !== undefined) {
      throw new AgentQError(
        firstFailure.unavailableReason,
        `Agent-Q device port is unavailable: ${firstFailure.unavailableReason}.`,
        true,
      );
    }
    throw new AgentQError("port_not_found", "No Agent-Q device is connected.", true);
  }
  throw new AgentQError(
    "invalid_params",
    "Multiple Agent-Q devices are connected; pass --device-id.",
    false,
  );
}
