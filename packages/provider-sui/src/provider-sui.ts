import {
  createDefaultDeviceClient,
  type DeviceClient,
} from "@stelis/agent-q-core/device";
import {
  connectDeviceSuccessOutputShape,
  credentialPrepareSuccessOutputShape,
  credentialProposeSuccessOutputShape,
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
import {
  FORBIDDEN_SECRET_FIELD_NAMES,
  type CredentialPrepareParams,
  type CredentialProposeParams,
} from "@stelis/agent-q-core/protocol";
import type {
  ConnectDeviceResult,
  CredentialPreparation,
  CredentialProposalOutcome,
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

export type CredentialPrepareInput = {
  deviceId?: string;
  purpose?: string;
} & CredentialPrepareParams;

export type CredentialProposeInput = {
  deviceId?: string;
  purpose?: string;
} & CredentialProposeParams;

export type SuiDeviceProviderCore = Pick<
  DeviceClient,
  | "scanDevices"
  | "identifyDevices"
  | "selectDevice"
  | "listDevices"
  | "connectDevice"
  | "disconnectDevice"
  | "getCapabilities"
  | "getAccounts"
  | "credentialPrepare"
  | "credentialPropose"
  | "signTransaction"
  | "signPersonalMessage"
>;

export interface SuiDeviceProviderOptions {
  core?: SuiDeviceProviderCore;
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
  CredentialPreparation,
  CredentialProposalOutcome,
  IdentifiedDevice,
  IdentifyDeviceFailure,
  IdentifyDevicesResult,
  ScanDevicesResult,
  SelectDeviceResult,
  SignPersonalMessageResult,
  SignTransactionResult,
};

export class SuiDeviceProvider {
  private readonly core: SuiDeviceProviderCore;

  constructor(options: SuiDeviceProviderOptions = {}) {
    this.core = options.core ?? createDefaultDeviceClient();
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

  async credentialPrepare(input: CredentialPrepareInput): Promise<CredentialPreparation> {
    return parseProviderOutput(credentialPrepareSuccessOutputShape, await this.core.credentialPrepare(input)) as CredentialPreparation;
  }

  async credentialPropose(input: CredentialProposeInput): Promise<CredentialProposalOutcome> {
    return parseProviderOutput(credentialProposeSuccessOutputShape, await this.core.credentialPropose(input)) as CredentialProposalOutcome;
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

export function createSuiDeviceProvider(options: SuiDeviceProviderOptions = {}): SuiDeviceProvider {
  return new SuiDeviceProvider(options);
}
