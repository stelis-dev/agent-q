import {
  createDefaultAgentQDeviceClient,
  type AgentQDeviceClient,
} from "@stelis/agent-q-core/device";
import {
  connectDeviceSuccessOutputShape,
  disconnectDeviceSuccessOutputShape,
  getAccountsSuccessOutputShape,
  identifyDevicesSuccessOutputShape,
  listDevicesSuccessOutputShape,
  providerGetCapabilitiesSuccessOutputShape,
  scanDevicesSuccessOutputShape,
  selectDeviceSuccessOutputShape,
  signPersonalMessageSuccessOutputShape,
  signTransactionSuccessOutputShape,
} from "@stelis/agent-q-core/adapter-internal";
import { FORBIDDEN_SECRET_FIELD_NAMES } from "@stelis/agent-q-core/protocol";
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
  SignPersonalMessageResult,
  SignTransactionResult,
} from "@stelis/agent-q-core";

export type GetCapabilitiesResult =
  | Extract<CoreGetCapabilitiesResult, { source: "live" }>
  | Exclude<CoreGetCapabilitiesResult, { source: "live" }>;

export type AgentQSuiProviderCore = Pick<
  AgentQDeviceClient,
  | "scanDevices"
  | "identifyDevices"
  | "selectDevice"
  | "listDevices"
  | "connectDevice"
  | "disconnectDevice"
  | "getCapabilities"
  | "getAccounts"
  | "signTransaction"
  | "signPersonalMessage"
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
  SignPersonalMessageResult,
  SignTransactionResult,
};

export class AgentQSuiProvider {
  private readonly core: AgentQSuiProviderCore;

  constructor(options: AgentQSuiProviderOptions = {}) {
    this.core = options.core ?? createDefaultAgentQDeviceClient();
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
    clientName?: string;
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
    return parseProviderOutput(providerGetCapabilitiesSuccessOutputShape, result) as GetCapabilitiesResult;
  }

  async getAccounts(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<GetAccountsResult> {
    return parseProviderOutput(getAccountsSuccessOutputShape, await this.core.getAccounts(input)) as GetAccountsResult;
  }

  async signTransaction(input: {
    deviceId?: string;
    purpose?: string;
    chain: "sui";
    method: "sign_transaction";
    network: "mainnet" | "testnet" | "devnet" | "localnet";
    txBytes: string;
  }): Promise<SignTransactionResult> {
    return parseProviderOutput(signTransactionSuccessOutputShape, await this.core.signTransaction(input)) as SignTransactionResult;
  }

  async signPersonalMessage(input: {
    deviceId?: string;
    purpose?: string;
    chain: "sui";
    method: "sign_personal_message";
    network: "mainnet" | "testnet" | "devnet" | "localnet";
    message: string;
  }): Promise<SignPersonalMessageResult> {
    return parseProviderOutput(signPersonalMessageSuccessOutputShape, await this.core.signPersonalMessage(input)) as SignPersonalMessageResult;
  }
}

export function createAgentQSuiProvider(options: AgentQSuiProviderOptions = {}): AgentQSuiProvider {
  return new AgentQSuiProvider(options);
}
