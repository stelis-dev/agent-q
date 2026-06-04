import { ConfigStore } from "./config.js";
import { GatewayCore } from "./core.js";
import { SerialPortUsbDriver } from "./usb.js";

export { SerialPortUsbDriver } from "./usb.js";
export { GatewayCore } from "./core.js";
export type * from "./core.js";

export function createDefaultGatewayCore(): GatewayCore {
  return new GatewayCore(new ConfigStore(), new SerialPortUsbDriver());
}
