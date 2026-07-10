import {
  LocalTransportBleGateway,
  type LocalTransportBleSession,
} from "./local-transport.js";

/** @internal */
export type LocalTransportSessionOpener = (opticalPayload: string) => Promise<LocalTransportBleSession>;

/** @internal */
export function createLocalTransportSessionOpener(): LocalTransportSessionOpener {
  return async (opticalPayload) => {
    const gateway = new LocalTransportBleGateway({});
    return gateway.connect(opticalPayload);
  };
}
