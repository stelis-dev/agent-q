import { MAX_PROTOCOL_RESPONSE_LINE_BYTES } from "./transport-invariants.js";
import { ProtocolError } from "./protocol-error.js";

export const PROTOCOL_VERSION = 1;
// sessionTtlMs is uint32 wire metadata. Gateway does not use it as the session
// authority; it is bounded here only to reject malformed Firmware responses.
export const MAX_SESSION_TTL_MS = 4_294_967_295;
export const MAX_RAW_PROTOCOL_JSON_BYTES = 4096;
export { MAX_PROTOCOL_RESPONSE_LINE_BYTES };

export const SUI_CHAIN_ID = "sui";
export const SUI_SIGN_TRANSACTION_METHOD = "sign_transaction";
export const SUI_SIGN_PERSONAL_MESSAGE_METHOD = "sign_personal_message";
export type SuiSignMethod =
  | typeof SUI_SIGN_TRANSACTION_METHOD
  | typeof SUI_SIGN_PERSONAL_MESSAGE_METHOD;
export const SUI_SIGN_TRANSACTION_NETWORKS = ["mainnet", "testnet", "devnet", "localnet"] as const;
export type SuiSignTransactionNetwork = (typeof SUI_SIGN_TRANSACTION_NETWORKS)[number];
export const MAX_SUI_SIGN_TRANSACTION_TX_BYTES = 384;
export const MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS = 512;
export const MAX_SUI_SIGN_PERSONAL_MESSAGE_BYTES = 256;
export const MAX_SUI_SIGN_PERSONAL_MESSAGE_BASE64_CHARS = 344;

export const SUI_ADDRESS_PATTERN = /^0x[0-9a-f]{64}$/;
// Raw 32-byte Ed25519 public key as base64 is exactly 43 payload chars + one "=".
export const ED25519_PUBLIC_KEY_BASE64_PATTERN = /^[A-Za-z0-9+/]{43}=$/;
// Sui Ed25519 signatures are scheme flag + 64-byte signature + 32-byte public key.
export const SUI_ED25519_SIGNATURE_BASE64_PATTERN = /^[A-Za-z0-9+/]{130}==$/;
export const SUI_DERIVATION_PATH = "m/44'/784'/0'/0'/0'";
export const MAX_CAPABILITY_CHAINS = 1;
export const MAX_CAPABILITY_ACCOUNTS_PER_CHAIN = 1;
export const MAX_SIGNING_CAPABILITIES = 2;
export const MAX_ACCOUNTS_PER_RESPONSE = 1;

export const HASH_ID_PATTERN = /^sha256:[0-9a-f]{64}$/;
export const RULE_REF_PATTERN = /^[a-z][a-z0-9_.:/-]{0,31}$/;

export const UNSUPPORTED_METHOD_MESSAGE = "Method is not supported.";
export const SIGN_RESULT_ERROR_MESSAGES = {
  user_rejected: "The signing request was rejected on the device.",
  user_timed_out: "The signing request timed out on the device.",
  policy_rejected: "The signing request was rejected by device policy.",
  signing_failed: "The device could not produce a signature.",
} as const;
export type SignResultErrorCode = keyof typeof SIGN_RESULT_ERROR_MESSAGES;

export const FORBIDDEN_SECRET_FIELD_NAMES = [
  "entropy",
  "mnemonic",
  "phrase",
  "prefixes",
  "privateKey",
  "private_key",
  "privateMaterial",
  "private_material",
  "recoveryPhrase",
  "recovery_phrase",
  "rootEntropy",
  "root_entropy",
  "rootMaterial",
  "root_material",
  "secret",
  "seed",
  "signingKey",
  "signing_key",
  "words",
] as const;

export const BASE64_CANONICAL_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const FORBIDDEN_SECRET_FIELD_NAME_SET = new Set(
  FORBIDDEN_SECRET_FIELD_NAMES.map((fieldName) => fieldName.toLowerCase()),
);

export function createRequestId(): string {
  return `req_${hexLower(randomBytesPortable(12))}`;
}

export function consumeProtocolResponseChunk(
  buffer: string,
  chunk: string,
  maxLineBytes = MAX_PROTOCOL_RESPONSE_LINE_BYTES,
): { buffer: string; lines: string[] } {
  const combined = buffer + chunk;
  const parts = combined.split("\n");
  const nextBuffer = parts.pop() ?? "";
  const lines = parts;

  for (const line of lines) {
    if (utf8ByteLength(line) > maxLineBytes) {
      throw new ProtocolError("protocol_error", "Protocol response line exceeds maximum length.");
    }
  }
  if (utf8ByteLength(nextBuffer) > maxLineBytes) {
    throw new ProtocolError("protocol_error", "Protocol response line exceeds maximum length.");
  }

  return { buffer: nextBuffer, lines };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new ProtocolError("invalid_params", `${label} must be an object.`);
  }
  return value;
}

export function requireOnlyKeys(value: Record<string, unknown>, allowedKeys: readonly string[], label: string): void {
  if (!hasOnlyObjectKeys(value, allowedKeys)) {
    throw new ProtocolError("protocol_error", `${label} contains unsupported fields.`);
  }
}

export function hasOnlyObjectKeys(value: Record<string, unknown>, allowedKeys: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowedKeys.includes(key));
}

export function hasSecretPayloadKey(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.some((item) => hasSecretPayloadKey(item));
  }
  if (!isRecord(value)) {
    return false;
  }
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_SECRET_FIELD_NAME_SET.has(key.toLowerCase())) {
      return true;
    }
    if (hasSecretPayloadKey(child)) {
      return true;
    }
  }
  return false;
}

export function rejectSecretPayload(value: Record<string, unknown>, label: string): void {
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", `${label} must not include secret material.`);
  }
}

export function validateCanonicalBase64Payload(
  value: unknown,
  maxChars: number,
  maxBytes: number,
  label: string,
  errorCode = "invalid_params",
): string {
  if (typeof value !== "string") {
    throw new ProtocolError(errorCode, `${label} must be base64.`);
  }
  if (value.length === 0 || value.length > maxChars || !BASE64_CANONICAL_PATTERN.test(value)) {
    throw new ProtocolError(errorCode, `${label} must be canonical base64.`);
  }
  const decoded = decodeCanonicalBase64(value);
  if (decoded === null || decoded.length === 0 || decoded.length > maxBytes) {
    throw new ProtocolError(errorCode, `${label} is outside the supported size.`);
  }
  return value;
}

export function decodeCanonicalBase64(value: string): Uint8Array | null {
  if (value.length === 0 || value.length % 4 !== 0 || !BASE64_CANONICAL_PATTERN.test(value)) {
    return null;
  }
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const output = new Uint8Array((value.length / 4) * 3 - padding);
  let outputOffset = 0;

  for (let offset = 0; offset < value.length; offset += 4) {
    const first = decodeBase64Char(value.charCodeAt(offset));
    const second = decodeBase64Char(value.charCodeAt(offset + 1));
    const thirdPadded = value.charCodeAt(offset + 2) === 61;
    const fourthPadded = value.charCodeAt(offset + 3) === 61;
    const third = thirdPadded ? 0 : decodeBase64Char(value.charCodeAt(offset + 2));
    const fourth = fourthPadded ? 0 : decodeBase64Char(value.charCodeAt(offset + 3));
    if (first < 0 || second < 0 || third < 0 || fourth < 0) {
      return null;
    }
    const isFinalBlock = offset + 4 === value.length;
    if ((thirdPadded || fourthPadded) && !isFinalBlock) {
      return null;
    }
    if (thirdPadded && !fourthPadded) {
      return null;
    }
    if (thirdPadded && (second & 0x0f) !== 0) {
      return null;
    }
    if (!thirdPadded && fourthPadded && (third & 0x03) !== 0) {
      return null;
    }

    const triple = (first << 18) | (second << 12) | (third << 6) | fourth;
    if (outputOffset < output.length) {
      output[outputOffset++] = (triple >> 16) & 0xff;
    }
    if (outputOffset < output.length) {
      output[outputOffset++] = (triple >> 8) & 0xff;
    }
    if (outputOffset < output.length) {
      output[outputOffset++] = triple & 0xff;
    }
  }

  return output;
}

export function isSuiAddressForPublicKey(address: string, publicKeyBase64: string): boolean {
  if (!SUI_ADDRESS_PATTERN.test(address) || !ED25519_PUBLIC_KEY_BASE64_PATTERN.test(publicKeyBase64)) {
    return false;
  }
  const expectedAddress = deriveSuiAddressFromPublicKey(publicKeyBase64);
  return expectedAddress !== null && address === expectedAddress;
}

export function randomBytesPortable(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  const cryptoLike = (globalThis as { crypto?: { getRandomValues?: (array: Uint8Array) => Uint8Array } }).crypto;
  if (cryptoLike?.getRandomValues === undefined) {
    throw new Error("Secure random source is unavailable.");
  }
  cryptoLike.getRandomValues(bytes);
  return bytes;
}

export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

export function hexLower(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function decodeBase64Char(code: number): number {
  if (code >= 65 && code <= 90) {
    return code - 65;
  }
  if (code >= 97 && code <= 122) {
    return code - 71;
  }
  if (code >= 48 && code <= 57) {
    return code + 4;
  }
  if (code === 43) {
    return 62;
  }
  if (code === 47) {
    return 63;
  }
  return -1;
}

function deriveSuiAddressFromPublicKey(publicKeyBase64: string): string | null {
  const publicKey = decodeCanonicalBase64(publicKeyBase64);
  if (publicKey === null || publicKey.length !== 32) {
    return null;
  }

  const addressInput = new Uint8Array(33);
  addressInput[0] = 0x00; // Sui Ed25519 scheme flag.
  addressInput.set(publicKey, 1);
  return `0x${hexLower(blake2b256(addressInput))}`;
}

const U64_MASK = (1n << 64n) - 1n;
const BLAKE2B_BLOCK_BYTES = 128;
const BLAKE2B_256_BYTES = 32;
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
] as const;
const BLAKE2B_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
] as const;

function add64(...values: bigint[]): bigint {
  return values.reduce((sum, value) => (sum + value) & U64_MASK, 0n);
}

function rotr64(value: bigint, shift: number): bigint {
  return ((value >> BigInt(shift)) | (value << BigInt(64 - shift))) & U64_MASK;
}

function readU64Le(input: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let index = 0; index < 8; ++index) {
    value |= BigInt(input[offset + index] ?? 0) << BigInt(index * 8);
  }
  return value;
}

function writeU64Le(output: Uint8Array, offset: number, value: bigint): void {
  for (let index = 0; index < 8; ++index) {
    output[offset + index] = Number((value >> BigInt(index * 8)) & 0xffn);
  }
}

function blake2bCompress(h: bigint[], block: Uint8Array, bytesCompressed: bigint, isLast: boolean): void {
  const m = Array.from({ length: 16 }, (_, index) => readU64Le(block, index * 8));
  const v = [...h, ...BLAKE2B_IV];
  v[12] ^= bytesCompressed & U64_MASK;
  v[13] ^= bytesCompressed >> 64n;
  if (isLast) {
    v[14] ^= U64_MASK;
  }

  const g = (a: number, b: number, c: number, d: number, x: number, y: number): void => {
    v[a] = add64(v[a], v[b], m[x]);
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = add64(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = add64(v[a], v[b], m[y]);
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = add64(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 63);
  };

  for (let round = 0; round < 12; ++round) {
    const sigma = BLAKE2B_SIGMA[round % BLAKE2B_SIGMA.length];
    g(0, 4, 8, 12, sigma[0], sigma[1]);
    g(1, 5, 9, 13, sigma[2], sigma[3]);
    g(2, 6, 10, 14, sigma[4], sigma[5]);
    g(3, 7, 11, 15, sigma[6], sigma[7]);
    g(0, 5, 10, 15, sigma[8], sigma[9]);
    g(1, 6, 11, 12, sigma[10], sigma[11]);
    g(2, 7, 8, 13, sigma[12], sigma[13]);
    g(3, 4, 9, 14, sigma[14], sigma[15]);
  }

  for (let index = 0; index < h.length; ++index) {
    h[index] = (h[index] ^ v[index] ^ v[index + 8]) & U64_MASK;
  }
}

function blake2b256(input: Uint8Array): Uint8Array {
  const h = [...BLAKE2B_IV];
  h[0] ^= 0x01010000n ^ BigInt(BLAKE2B_256_BYTES);

  let offset = 0;
  let bytesCompressed = 0n;
  while (offset + BLAKE2B_BLOCK_BYTES < input.length) {
    bytesCompressed += BigInt(BLAKE2B_BLOCK_BYTES);
    blake2bCompress(h, input.subarray(offset, offset + BLAKE2B_BLOCK_BYTES), bytesCompressed, false);
    offset += BLAKE2B_BLOCK_BYTES;
  }

  const finalBlock = new Uint8Array(BLAKE2B_BLOCK_BYTES);
  const remaining = input.subarray(offset);
  finalBlock.set(remaining);
  bytesCompressed += BigInt(remaining.length);
  blake2bCompress(h, finalBlock, bytesCompressed, true);

  const digest = new Uint8Array(BLAKE2B_256_BYTES);
  for (let index = 0; index < BLAKE2B_256_BYTES / 8; ++index) {
    writeU64Le(digest, index * 8, h[index]);
  }
  return digest;
}
