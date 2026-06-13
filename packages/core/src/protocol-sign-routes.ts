import {
  SUI_CHAIN_ID,
  SUI_SIGN_PERSONAL_MESSAGE_METHOD,
  SUI_SIGN_TRANSACTION_METHOD,
} from "./protocol-primitives.js";
import {
  SIGN_CHAIN_PATTERN,
  SIGN_METHOD_PATTERN,
} from "./protocol-management-primitives.js";
import { ProtocolError } from "./protocol-error.js";

export type SignOperationType =
  | typeof SUI_SIGN_TRANSACTION_METHOD
  | typeof SUI_SIGN_PERSONAL_MESSAGE_METHOD;

export type SupportedSignRoute =
  | {
      operation: typeof SUI_SIGN_TRANSACTION_METHOD;
      chain: typeof SUI_CHAIN_ID;
      method: typeof SUI_SIGN_TRANSACTION_METHOD;
      route: "sui_sign_transaction";
    }
  | {
      operation: typeof SUI_SIGN_PERSONAL_MESSAGE_METHOD;
      chain: typeof SUI_CHAIN_ID;
      method: typeof SUI_SIGN_PERSONAL_MESSAGE_METHOD;
      route: "sui_sign_personal_message";
    };

export function identifySignRoute(
  operation: typeof SUI_SIGN_TRANSACTION_METHOD,
  chain: unknown,
  method: unknown,
): Extract<SupportedSignRoute, { operation: typeof SUI_SIGN_TRANSACTION_METHOD }>;
export function identifySignRoute(
  operation: typeof SUI_SIGN_PERSONAL_MESSAGE_METHOD,
  chain: unknown,
  method: unknown,
): Extract<SupportedSignRoute, { operation: typeof SUI_SIGN_PERSONAL_MESSAGE_METHOD }>;
export function identifySignRoute(
  operation: SignOperationType,
  chain: unknown,
  method: unknown,
): SupportedSignRoute;
export function identifySignRoute(
  operation: SignOperationType,
  chain: unknown,
  method: unknown,
): SupportedSignRoute {
  if (
    typeof chain !== "string" ||
    !SIGN_CHAIN_PATTERN.test(chain) ||
    typeof method !== "string" ||
    !SIGN_METHOD_PATTERN.test(method)
  ) {
    throw new ProtocolError("invalid_params", "Signing route identifiers are invalid.");
  }

  if (chain !== SUI_CHAIN_ID) {
    // Keep chain support explicit. Add a chain case only when its Firmware
    // adapter, core validation, capabilities, provider surface, tests, docs,
    // and hardware evidence implement the same contract.
    throw new ProtocolError("unsupported_chain", "Signing chain is unsupported.");
  }

  switch (operation) {
    case SUI_SIGN_TRANSACTION_METHOD:
      if (method === SUI_SIGN_TRANSACTION_METHOD) {
        return {
          operation,
          chain: SUI_CHAIN_ID,
          method: SUI_SIGN_TRANSACTION_METHOD,
          route: "sui_sign_transaction",
        };
      }
      break;
    case SUI_SIGN_PERSONAL_MESSAGE_METHOD:
      if (method === SUI_SIGN_PERSONAL_MESSAGE_METHOD) {
        return {
          operation,
          chain: SUI_CHAIN_ID,
          method: SUI_SIGN_PERSONAL_MESSAGE_METHOD,
          route: "sui_sign_personal_message",
        };
      }
      break;
  }
  throw new ProtocolError("unsupported_method", "Signing method is unsupported.");
}
