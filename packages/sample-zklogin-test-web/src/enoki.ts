import type { ZkLoginSignatureInputs } from "@mysten/sui/zklogin";

export type EnokiNetwork = "mainnet" | "testnet" | "devnet";
export type EnokiAuthProvider = "google" | "facebook" | "twitch";

export type EnokiConfig = {
  apiUrl: string;
  apiKey: string;
};

export type EnokiAppProvider = {
  providerType: EnokiAuthProvider;
  clientId: string;
};

export type EnokiNonce = {
  nonce: string;
  randomness: string;
  epoch: number;
  maxEpoch: number;
  estimatedExpiration: number;
};

export type EnokiZkLogin = {
  address: string;
  publicKey: string;
};

export async function getEnokiApp(config: EnokiConfig): Promise<EnokiAppProvider[]> {
  const data = await enokiFetchData(config, "app", { method: "GET" });
  if (!isRecord(data) || !Array.isArray(data.authenticationProviders)) {
    throw new Error("Enoki app response did not contain authentication providers.");
  }
  return data.authenticationProviders
    .filter((entry): entry is EnokiAppProvider => {
      return isRecord(entry) &&
        isSupportedProvider(entry.providerType) &&
        typeof entry.clientId === "string" &&
        entry.clientId.length > 0;
    });
}

export async function createEnokiNonce(
  config: EnokiConfig,
  input: {
    network: EnokiNetwork;
    ephemeralPublicKey: string;
    additionalEpochs?: number;
  },
): Promise<EnokiNonce> {
  const data = await enokiFetchData(config, "zklogin/nonce", {
    method: "POST",
    body: JSON.stringify({
      network: input.network,
      ephemeralPublicKey: input.ephemeralPublicKey,
      additionalEpochs: input.additionalEpochs,
    }),
  });
  return parseEnokiNonce(data);
}

export async function getEnokiZkLogin(
  config: EnokiConfig,
  jwt: string,
): Promise<EnokiZkLogin> {
  const data = await enokiFetchData(config, "zklogin", {
    method: "GET",
    jwt,
  });
  if (!isRecord(data) || typeof data.address !== "string" || typeof data.publicKey !== "string") {
    throw new Error("Enoki zkLogin response did not contain address and public key.");
  }
  return {
    address: data.address,
    publicKey: data.publicKey,
  };
}

export async function createEnokiZkp(
  config: EnokiConfig,
  input: {
    network: EnokiNetwork;
    jwt: string;
    ephemeralPublicKey: string;
    maxEpoch: number;
    randomness: string;
  },
): Promise<ZkLoginSignatureInputs> {
  const data = await enokiFetchData(config, "zklogin/zkp", {
    method: "POST",
    jwt: input.jwt,
    body: JSON.stringify({
      network: input.network,
      ephemeralPublicKey: input.ephemeralPublicKey,
      maxEpoch: input.maxEpoch,
      randomness: input.randomness,
    }),
  });
  if (!isRecord(data) || !hasProofInputKeys(data)) {
    throw new Error("Enoki ZKP response did not contain zkLogin signature inputs.");
  }
  return data as unknown as ZkLoginSignatureInputs;
}

export function toEnokiNetwork(network: string): EnokiNetwork {
  if (network === "mainnet" || network === "testnet" || network === "devnet") {
    return network;
  }
  throw new Error("Enoki zkLogin is available only on mainnet, testnet, and devnet.");
}

export function defaultOAuthAuthorizeUrl(provider: EnokiAuthProvider): string {
  switch (provider) {
    case "google":
      return "https://accounts.google.com/o/oauth2/v2/auth";
    case "facebook":
      return "https://www.facebook.com/v17.0/dialog/oauth";
    case "twitch":
      return "https://id.twitch.tv/oauth2/authorize";
  }
}

type EnokiFetchInit = {
  method: "GET" | "POST";
  body?: string;
  jwt?: string;
};

async function enokiFetchData(
  config: EnokiConfig,
  path: string,
  init: EnokiFetchInit,
): Promise<unknown> {
  const apiUrl = normalizeApiUrl(config.apiUrl);
  const apiKey = config.apiKey.trim();
  if (apiKey.length === 0) {
    throw new Error("Enoki public API key is required.");
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
    "Request-Id": requestId(),
  };
  if (init.jwt !== undefined) {
    headers["zklogin-jwt"] = init.jwt;
  }

  const response = await fetch(`${apiUrl}/v1/${path}`, {
    method: init.method,
    headers,
    body: init.body,
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(enokiErrorMessage(response.status));
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("Enoki API returned non-JSON response.");
  }
  if (!isRecord(parsed) || !("data" in parsed)) {
    throw new Error("Enoki API response did not contain data.");
  }
  return parsed.data;
}

function normalizeApiUrl(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    throw new Error("Enoki API URL is required.");
  }
  return trimmed.replace(/\/+$/, "").replace(/\/v1$/, "");
}

function parseEnokiNonce(value: unknown): EnokiNonce {
  if (!isRecord(value) ||
    typeof value.nonce !== "string" ||
    typeof value.randomness !== "string" ||
    typeof value.epoch !== "number" ||
    typeof value.maxEpoch !== "number" ||
    typeof value.estimatedExpiration !== "number") {
    throw new Error("Enoki nonce response was malformed.");
  }
  return {
    nonce: value.nonce,
    randomness: value.randomness,
    epoch: value.epoch,
    maxEpoch: value.maxEpoch,
    estimatedExpiration: value.estimatedExpiration,
  };
}

function hasProofInputKeys(value: Record<string, unknown>): boolean {
  return (
    isRecord(value.proofPoints) &&
    isRecord(value.issBase64Details) &&
    typeof value.headerBase64 === "string" &&
    typeof value.addressSeed === "string"
  );
}

function isSupportedProvider(value: unknown): value is EnokiAuthProvider {
  return value === "google" || value === "facebook" || value === "twitch";
}

function enokiErrorMessage(status: number): string {
  return `Enoki API failed (${status}).`;
}

function requestId(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
