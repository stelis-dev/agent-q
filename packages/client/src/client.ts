import { ConfigStore } from "./config.js";
import { GatewayCore } from "./core.js";
import { SerialPortUsbDriver } from "./usb.js";
import type {
  CallMethodResult,
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
} from "./core.js";

export type {
  CallMethodResult,
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
} from "./core.js";

export interface DeviceClientCore {
  scanDevices(input?: Record<string, never>): Promise<ScanDevicesResult>;
  identifyDevices(input?: Record<string, never>): Promise<IdentifyDevicesResult>;
  selectDevice(input: { deviceId: string; purpose?: string }): Promise<SelectDeviceResult>;
  listDevices(): Promise<DeviceListResult>;
  connectDevice(input?: {
    deviceId?: string;
    purpose?: string;
    gatewayName?: string;
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
  getPolicy(input?: {
    deviceId?: string;
    purpose?: string;
  }): Promise<GetPolicyResult>;
  getApprovalHistory(input?: {
    deviceId?: string;
    purpose?: string;
    limit?: number;
    beforeSeq?: string;
  }): Promise<GetApprovalHistoryResult>;
  callMethod(input: {
    deviceId?: string;
    purpose?: string;
    chain: string;
    method: string;
    params?: Record<string, unknown>;
  }): Promise<CallMethodResult>;
}

function deviceClientFromCore(core: GatewayCore): DeviceClientCore {
  return {
    scanDevices: (input = {}) => core.scanDevices(input),
    identifyDevices: (input = {}) => core.identifyDevices(input),
    selectDevice: (input) => core.selectDevice(input),
    listDevices: () => core.listDevices(),
    connectDevice: (input = {}) => core.connectDevice(input),
    disconnectDevice: (input = {}) => core.disconnectDevice(input),
    getCapabilities: (input = {}) => core.getCapabilities(input),
    getAccounts: (input = {}) => core.getAccounts(input),
    getPolicy: (input = {}) => core.getPolicy(input),
    getApprovalHistory: (input = {}) => core.getApprovalHistory(input),
    callMethod: (input) => core.callMethod(input),
  };
}

export function createDefaultDeviceClientCore(): DeviceClientCore {
  return deviceClientFromCore(new GatewayCore(new ConfigStore(), new SerialPortUsbDriver()));
}
