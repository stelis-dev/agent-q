export const INTERNAL_PIN_INPUT_WINDOW_MS = 30000;
export const INTERNAL_WRONG_PIN_ATTEMPTS_BEFORE_LOCKOUT = 5;
export const INTERNAL_PIN_LOCKOUT_MS = 30000;
export const INTERNAL_TRANSPORT_MARGIN_MS = 5000;
export const INTERNAL_REQUEST_WINDOW_MS = INTERNAL_PIN_INPUT_WINDOW_MS;
export const INTERNAL_LOCAL_PIN_INTERACTION_DEADLINE_MS =
  INTERNAL_WRONG_PIN_ATTEMPTS_BEFORE_LOCKOUT * INTERNAL_PIN_INPUT_WINDOW_MS +
  INTERNAL_PIN_LOCKOUT_MS +
  INTERNAL_TRANSPORT_MARGIN_MS;
export const INTERNAL_USB_DEADLINE_MS = INTERNAL_REQUEST_WINDOW_MS;
export const INTERNAL_DISCONNECT_DEADLINE_MS = INTERNAL_REQUEST_WINDOW_MS;
export const INTERNAL_POLICY_UPDATE_DEADLINE_MS = INTERNAL_LOCAL_PIN_INTERACTION_DEADLINE_MS;
export const INTERNAL_SIGN_TRANSACTION_DEADLINE_MS = INTERNAL_LOCAL_PIN_INTERACTION_DEADLINE_MS;
export const INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS = INTERNAL_LOCAL_PIN_INTERACTION_DEADLINE_MS;
export const INTERNAL_CONNECT_DEADLINE_MS = INTERNAL_LOCAL_PIN_INTERACTION_DEADLINE_MS;
// Minimum usable staged-payload chunk size for current host/provider deadline
// estimates. Firmware may advertise a larger per-chunk limit, but smaller
// limits would make the advertised payload maximum impossible to guarantee
// within the transaction deadline chosen before capability exchange completes.
export const PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES = 2048;

export const DEFAULT_AGENT_Q_USB_BAUD_RATE = 115200;
export const AGENT_Q_USB_VENDOR_ID = "303a";
export const AGENT_Q_USB_PRODUCT_ID = "1001";
export const AGENT_Q_USB_VENDOR_ID_NUMBER = 0x303a;
export const AGENT_Q_USB_PRODUCT_ID_NUMBER = 0x1001;

// Current Firmware responses are bounded by protocol parsers. This transport
// cap catches malformed or hostile streams before an unterminated line can grow
// without bound, while leaving room for the largest allowed read responses.
export const MAX_PROTOCOL_RESPONSE_LINE_BYTES = 64 * 1024;
