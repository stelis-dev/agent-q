import { ConfigStore } from "./config.js";
import { AgentQCore } from "./core.js";
import { SerialPortUsbDriver } from "./usb.js";
import type {
  ConnectDeviceResult,
  DeviceListResult,
  DisconnectDeviceResult,
  GetAccountsResult,
  GetApprovalHistoryResult,
  GetCapabilitiesResult,
  PolicyGetResult,
  IdentifiedDevice,
  IdentifyDeviceFailure,
  IdentifyDevicesResult,
  SignPersonalMessageResult,
  SignTransactionResult,
  ScanDevicesResult,
  SelectDeviceResult,
} from "./core.js";

export type {
  ConnectDeviceResult,
  DeviceListResult,
  DisconnectDeviceResult,
  GetAccountsResult,
  GetApprovalHistoryResult,
  GetCapabilitiesResult,
  PolicyGetResult,
  IdentifiedDevice,
  IdentifyDeviceFailure,
  IdentifyDevicesResult,
  SignPersonalMessageResult,
  SignTransactionResult,
  ScanDevicesResult,
  SelectDeviceResult,
} from "./core.js";

export interface AgentQDeviceClient {
  scanDevices(input?: Record<string, never>): Promise<ScanDevicesResult>;
  identifyDevices(input?: Record<string, never>): Promise<IdentifyDevicesResult>;
  selectDevice(input: { deviceId: string; purpose?: string }): Promise<SelectDeviceResult>;
  listDevices(): Promise<DeviceListResult>;
  connectDevice(input?: {
    deviceId?: string;
    purpose?: string;
    clientName?: string;
  }): Promise<ConnectDeviceResult>;
  disconnectDevice(input?: {
    deviceId?: string;
    purpose?: string;
  }): Promise<DisconnectDeviceResult>;
  getCapabilities(input?: {
    deviceId?: string;
    purpose?: string;
  }): Promise<GetCapabilitiesResult>;
  getAccounts(input?: {
    deviceId?: string;
    purpose?: string;
  }): Promise<GetAccountsResult>;
  policyGet(input?: {
    deviceId?: string;
    purpose?: string;
  }): Promise<PolicyGetResult>;
  getApprovalHistory(input?: {
    deviceId?: string;
    purpose?: string;
    limit?: number;
    beforeSeq?: string;
  }): Promise<GetApprovalHistoryResult>;
  signTransaction(input: {
    deviceId?: string;
    purpose?: string;
    chain: string;
    method: string;
    network: "mainnet" | "testnet" | "devnet" | "localnet";
    txBytes: string;
  }): Promise<SignTransactionResult>;
  signPersonalMessage(input: {
    deviceId?: string;
    purpose?: string;
    chain: string;
    method: string;
    network: "mainnet" | "testnet" | "devnet" | "localnet";
    message: string;
  }): Promise<SignPersonalMessageResult>;
}

function deviceApiFromCore(core: AgentQCore): AgentQDeviceClient {
  return {
    scanDevices: (input = {}) => core.scanDevices(input),
    identifyDevices: (input = {}) => core.identifyDevices(input),
    selectDevice: (input) => core.selectDevice(input),
    listDevices: () => core.listDevices(),
    connectDevice: (input = {}) => core.connectDevice(input),
    disconnectDevice: (input = {}) => core.disconnectDevice(input),
    getCapabilities: (input = {}) => core.getCapabilities(input),
    getAccounts: (input = {}) => core.getAccounts(input),
    policyGet: (input = {}) => core.policyGet(input),
    getApprovalHistory: (input = {}) => core.getApprovalHistory(input),
    signTransaction: (input) => core.signTransaction(input),
    signPersonalMessage: (input) => core.signPersonalMessage(input),
  };
}

export function createDefaultAgentQDeviceClient(): AgentQDeviceClient {
  return deviceApiFromCore(new AgentQCore(new ConfigStore(), new SerialPortUsbDriver()));
}
