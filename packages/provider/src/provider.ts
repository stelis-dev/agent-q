import { createDefaultDeviceClientCore } from "@stelis/agent-q-client";
import type {
  ConnectDeviceResult,
  DeviceListResult,
  DisconnectDeviceResult,
  GetAccountsResult,
  GetApprovalHistoryResult,
  GetCapabilitiesResult,
  GetPolicyResult,
  IdentifiedDevice,
  IdentifyDeviceFailure,
  IdentifyDevicesResult,
  RequestSignatureResult,
  ScanDevicesResult,
  SelectDeviceResult,
  DeviceClientCore,
} from "@stelis/agent-q-client";

export type AgentQProviderCore = Pick<
  DeviceClientCore,
  | "scanDevices"
  | "identifyDevices"
  | "selectDevice"
  | "listDevices"
  | "connectDevice"
  | "disconnectDevice"
  | "getCapabilities"
  | "getAccounts"
  | "getPolicy"
  | "getApprovalHistory"
  | "requestSignature"
>;

export interface AgentQProviderOptions {
  core?: AgentQProviderCore;
}

export type {
  ConnectDeviceResult,
  DeviceListResult,
  DisconnectDeviceResult,
  GetAccountsResult,
  GetApprovalHistoryResult,
  GetCapabilitiesResult,
  GetPolicyResult,
  IdentifiedDevice,
  IdentifyDeviceFailure,
  IdentifyDevicesResult,
  RequestSignatureResult,
  ScanDevicesResult,
  SelectDeviceResult,
};

export class AgentQProvider {
  private readonly core: AgentQProviderCore;

  constructor(options: AgentQProviderOptions = {}) {
    this.core = options.core ?? createDefaultDeviceClientCore();
  }

  scanDevices(input: Record<string, never> = {}): Promise<ScanDevicesResult> {
    return this.core.scanDevices(input);
  }

  identifyDevices(input: Record<string, never> = {}): Promise<IdentifyDevicesResult> {
    return this.core.identifyDevices(input);
  }

  selectDevice(input: { deviceId: string; purpose?: string }): Promise<SelectDeviceResult> {
    return this.core.selectDevice(input);
  }

  listDevices(): Promise<DeviceListResult> {
    return this.core.listDevices();
  }

  connectDevice(input: {
    deviceId?: string;
    purpose?: string;
    gatewayName?: string;
  } = {}): Promise<ConnectDeviceResult> {
    return this.core.connectDevice(input);
  }

  disconnectDevice(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<DisconnectDeviceResult> {
    return this.core.disconnectDevice(input);
  }

  getCapabilities(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<GetCapabilitiesResult> {
    return this.core.getCapabilities(input);
  }

  getAccounts(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<GetAccountsResult> {
    return this.core.getAccounts(input);
  }

  getPolicy(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<GetPolicyResult> {
    return this.core.getPolicy(input);
  }

  getApprovalHistory(input: {
    deviceId?: string;
    purpose?: string;
    limit?: number;
    beforeSeq?: string;
  } = {}): Promise<GetApprovalHistoryResult> {
    return this.core.getApprovalHistory(input);
  }

  requestSignature(input: {
    deviceId?: string;
    purpose?: string;
    chain: "sui";
    method: "sign_transaction";
    network: "mainnet" | "testnet" | "devnet" | "localnet";
    txBytes: string;
  }): Promise<RequestSignatureResult> {
    return this.core.requestSignature(input);
  }
}

export function createAgentQProvider(options: AgentQProviderOptions = {}): AgentQProvider {
  return new AgentQProvider(options);
}
