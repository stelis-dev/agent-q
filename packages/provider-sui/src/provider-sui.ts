import { createDefaultDeviceClientCore } from "@stelis/agent-q-client";
import {
  connectDeviceSuccessOutputShape,
  disconnectDeviceSuccessOutputShape,
  getAccountsSuccessOutputShape,
  identifyDevicesSuccessOutputShape,
  listDevicesSuccessOutputShape,
  providerGetCapabilitiesSuccessOutputShape,
  scanDevicesSuccessOutputShape,
  selectDeviceSuccessOutputShape,
  signByUserSuccessOutputShape,
} from "@stelis/agent-q-client/adapter-internal";
import { FORBIDDEN_SECRET_FIELD_NAMES } from "@stelis/agent-q-client/protocol";
import type {
  ConnectDeviceResult,
  DeviceListResult,
  DisconnectDeviceResult,
  GetAccountsResult,
  GetCapabilitiesResult as CoreGetCapabilitiesResult,
  IdentifiedDevice,
  IdentifyDeviceFailure,
  IdentifyDevicesResult,
  ScanDevicesResult,
  SelectDeviceResult,
  SignByUserResult,
  DeviceClientCore,
} from "@stelis/agent-q-client";

type ProviderSigningCapabilities = {
  user: Array<{ chain: "sui"; method: "sign_transaction" }>;
};

type LiveProviderGetCapabilitiesResult =
  Omit<Extract<CoreGetCapabilitiesResult, { source: "live" }>, "signing"> & {
    signing?: ProviderSigningCapabilities;
  };

export type GetCapabilitiesResult =
  | LiveProviderGetCapabilitiesResult
  | Exclude<CoreGetCapabilitiesResult, { source: "live" }>;

export type AgentQSuiProviderCore = Pick<
  DeviceClientCore,
  | "scanDevices"
  | "identifyDevices"
  | "selectDevice"
  | "listDevices"
  | "connectDevice"
  | "disconnectDevice"
  | "getCapabilities"
  | "getAccounts"
  | "signByUser"
>;

export interface AgentQSuiProviderOptions {
  core?: AgentQSuiProviderCore;
}

const FORBIDDEN_PROVIDER_OUTPUT_FIELDS = new Set(
  [...FORBIDDEN_SECRET_FIELD_NAMES, "sessionId", "session_id"].map((fieldName) => fieldName.toLowerCase()),
);

function assertNoForbiddenProviderOutputFields(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      assertNoForbiddenProviderOutputFields(item);
    }
    return;
  }
  if (typeof value !== "object" || value === null) {
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (FORBIDDEN_PROVIDER_OUTPUT_FIELDS.has(key.toLowerCase())) {
      throw new Error("Provider core returned a forbidden output field.");
    }
    assertNoForbiddenProviderOutputFields(nested);
  }
}

function parseProviderOutput<T>(schema: { parse(value: unknown): T }, value: unknown): T {
  assertNoForbiddenProviderOutputFields(value);
  return schema.parse(value);
}

export type {
  ConnectDeviceResult,
  DeviceListResult,
  DisconnectDeviceResult,
  GetAccountsResult,
  IdentifiedDevice,
  IdentifyDeviceFailure,
  IdentifyDevicesResult,
  ScanDevicesResult,
  SelectDeviceResult,
  SignByUserResult,
};

export class AgentQSuiProvider {
  private readonly core: AgentQSuiProviderCore;

  constructor(options: AgentQSuiProviderOptions = {}) {
    this.core = options.core ?? createDefaultDeviceClientCore();
  }

  async scanDevices(input: Record<string, never> = {}): Promise<ScanDevicesResult> {
    return parseProviderOutput(scanDevicesSuccessOutputShape, await this.core.scanDevices(input)) as ScanDevicesResult;
  }

  async identifyDevices(input: Record<string, never> = {}): Promise<IdentifyDevicesResult> {
    return parseProviderOutput(identifyDevicesSuccessOutputShape, await this.core.identifyDevices(input)) as IdentifyDevicesResult;
  }

  async selectDevice(input: { deviceId: string; purpose?: string }): Promise<SelectDeviceResult> {
    return parseProviderOutput(selectDeviceSuccessOutputShape, await this.core.selectDevice(input)) as SelectDeviceResult;
  }

  async listDevices(): Promise<DeviceListResult> {
    return parseProviderOutput(listDevicesSuccessOutputShape, await this.core.listDevices()) as DeviceListResult;
  }

  async connectDevice(input: {
    deviceId?: string;
    purpose?: string;
    gatewayName?: string;
  } = {}): Promise<ConnectDeviceResult> {
    return parseProviderOutput(connectDeviceSuccessOutputShape, await this.core.connectDevice(input)) as ConnectDeviceResult;
  }

  async disconnectDevice(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<DisconnectDeviceResult> {
    return parseProviderOutput(disconnectDeviceSuccessOutputShape, await this.core.disconnectDevice(input)) as DisconnectDeviceResult;
  }

  async getCapabilities(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<GetCapabilitiesResult> {
    const result = await this.core.getCapabilities(input);
    const projected = result.source === "live" && result.signing !== undefined
      ? { ...result, signing: { user: result.signing.user } }
      : result;
    return parseProviderOutput(providerGetCapabilitiesSuccessOutputShape, projected) as GetCapabilitiesResult;
  }

  async getAccounts(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<GetAccountsResult> {
    return parseProviderOutput(getAccountsSuccessOutputShape, await this.core.getAccounts(input)) as GetAccountsResult;
  }

  async signByUser(input: {
    deviceId?: string;
    purpose?: string;
    chain: "sui";
    method: "sign_transaction";
    network: "mainnet" | "testnet" | "devnet" | "localnet";
    txBytes: string;
  }): Promise<SignByUserResult> {
    return parseProviderOutput(signByUserSuccessOutputShape, await this.core.signByUser(input)) as SignByUserResult;
  }
}

export function createAgentQSuiProvider(options: AgentQSuiProviderOptions = {}): AgentQSuiProvider {
  return new AgentQSuiProvider(options);
}
