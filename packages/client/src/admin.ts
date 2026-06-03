import { ConfigStore } from "./config.js";
import { GatewayCore } from "./core.js";
import { SerialPortUsbDriver } from "./usb.js";

export { MAX_SCAN_TIMEOUT_MS, SerialPortUsbDriver } from "./usb.js";
export {
  DEFAULT_CALL_METHOD_TIMEOUT_MS,
  DEFAULT_POLICY_UPDATE_TIMEOUT_MS,
  GatewayCore,
  MAX_IDENTIFY_DURATION_MS,
} from "./core.js";
export type * from "./core.js";

export function createDefaultGatewayCore(): GatewayCore {
  return new GatewayCore(new ConfigStore(), new SerialPortUsbDriver());
}
