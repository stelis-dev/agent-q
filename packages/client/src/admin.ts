import { ConfigStore } from "./config.js";
import { AgentQHostCore } from "./core.js";
import { SerialPortUsbDriver } from "./usb.js";

export { SerialPortUsbDriver } from "./usb.js";
export { AgentQHostCore } from "./core.js";
export type * from "./core.js";

export function createDefaultAgentQHostCore(): AgentQHostCore {
  return new AgentQHostCore(new ConfigStore(), new SerialPortUsbDriver());
}
