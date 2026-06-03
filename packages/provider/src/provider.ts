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
  ScanDevicesResult,
  SelectDeviceResult,
};

export class AgentQProvider {
  private readonly core: AgentQProviderCore;

  constructor(options: AgentQProviderOptions = {}) {
    this.core = options.core ?? createDefaultDeviceClientCore();
  }

  scanDevices(input: { timeoutMs?: number } = {}): Promise<ScanDevicesResult> {
    return this.core.scanDevices(input);
  }

  identifyDevices(input: { timeoutMs?: number; durationMs?: number } = {}): Promise<IdentifyDevicesResult> {
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
    approvalTimeoutMs?: number;
    timeoutMs?: number;
  } = {}): Promise<ConnectDeviceResult> {
    return this.core.connectDevice(input);
  }

  disconnectDevice(input: {
    deviceId?: string;
    purpose?: string;
    timeoutMs?: number;
  } = {}): Promise<DisconnectDeviceResult> {
    return this.core.disconnectDevice(input);
  }

  getCapabilities(input: {
    deviceId?: string;
    purpose?: string;
    timeoutMs?: number;
  } = {}): Promise<GetCapabilitiesResult> {
    return this.core.getCapabilities(input);
  }

  getAccounts(input: {
    deviceId?: string;
    purpose?: string;
    timeoutMs?: number;
  } = {}): Promise<GetAccountsResult> {
    return this.core.getAccounts(input);
  }

  getPolicy(input: {
    deviceId?: string;
    purpose?: string;
    timeoutMs?: number;
  } = {}): Promise<GetPolicyResult> {
    return this.core.getPolicy(input);
  }

  getApprovalHistory(input: {
    deviceId?: string;
    purpose?: string;
    limit?: number;
    beforeSeq?: string;
    timeoutMs?: number;
  } = {}): Promise<GetApprovalHistoryResult> {
    return this.core.getApprovalHistory(input);
  }
}

export function createAgentQProvider(options: AgentQProviderOptions = {}): AgentQProvider {
  return new AgentQProvider(options);
}
