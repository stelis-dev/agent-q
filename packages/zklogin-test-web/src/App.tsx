import { useEffect, useMemo, useState } from "react";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { fromBase64, toBase64 } from "@mysten/sui/utils";
import {
  ZkLoginPublicIdentifier,
  generateNonce,
  generateRandomness,
  jwtToAddress,
  type ZkLoginSignatureInputs,
} from "@mysten/sui/zklogin";
import type {
  Account,
  CapabilitiesResponse,
  CredentialPrepareResultResponse,
  CredentialProposeParams,
  SignResultResponse,
  SuiSignTransactionNetwork,
  ZkLoginSignatureInputsDto,
} from "@stelis/agent-q-core/protocol";
import {
  AgentQSerialClient,
  type AgentQConnectedSession,
  isWebSerialAvailable,
} from "./agent-q-serial";

type NoticeTone = "neutral" | "success" | "error";
type Notice = {
  tone: NoticeTone;
  title: string;
  lines: string[];
};

const NETWORKS: SuiSignTransactionNetwork[] = ["testnet", "devnet", "mainnet", "localnet"];
const DEFAULT_GAS_BUDGET_MIST = "10000000";
const DEFAULT_TRANSFER_AMOUNT_MIST = "1";

function App() {
  const [client] = useState(() => new AgentQSerialClient());
  const [busy, setBusy] = useState<string | null>(null);
  const [session, setSession] = useState<AgentQConnectedSession | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilitiesResponse | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [network, setNetwork] = useState<SuiSignTransactionNetwork>("testnet");
  const [maxEpoch, setMaxEpoch] = useState("10");
  const [randomness, setRandomness] = useState(() => generateRandomness());
  const [preparation, setPreparation] = useState<CredentialPrepareResultResponse["preparation"] | null>(null);
  const [nonce, setNonce] = useState("");
  const [oauthAuthorizeUrl, setOauthAuthorizeUrl] = useState("");
  const [oauthClientId, setOauthClientId] = useState("");
  const [oauthRedirectUri, setOauthRedirectUri] = useState(() => globalThis.location?.origin ?? "");
  const [oauthScope, setOauthScope] = useState("openid email profile");
  const [jwt, setJwt] = useState("");
  const [userSalt, setUserSalt] = useState("");
  const [legacyAddress, setLegacyAddress] = useState(false);
  const [proofAddress, setProofAddress] = useState("");
  const [proofPublicKey, setProofPublicKey] = useState("");
  const [proofJson, setProofJson] = useState("");
  const [amountMist, setAmountMist] = useState(DEFAULT_TRANSFER_AMOUNT_MIST);
  const [gasBudgetMist, setGasBudgetMist] = useState(DEFAULT_GAS_BUDGET_MIST);
  const [lastTxBytes, setLastTxBytes] = useState("");
  const [lastSignature, setLastSignature] = useState<SignResultResponse | null>(null);
  const [notice, setNotice] = useState<Notice>({
    tone: "neutral",
    title: "Idle",
    lines: ["No device session."],
  });

  const webSerialAvailable = isWebSerialAvailable();
  const activeAccount = accounts.find((account) => account.chain === "sui") ?? null;
  const setupBlockedReason = getSetupBlockedReason(session, activeAccount);
  const setupBlocked = setupBlockedReason !== null;
  const canUseConnectedDevice = webSerialAvailable && session !== null && busy === null;

  const credentialCapability = useMemo(() => {
    return capabilities?.credentials?.find((entry) => entry.chain === "sui" && entry.credential === "zklogin") ?? null;
  }, [capabilities]);

  useEffect(() => {
    captureJwtFromRedirect(setJwt, setNotice);
    return () => {
      void client.dispose();
    };
  }, [client]);

  async function run(title: string, action: () => Promise<void>): Promise<void> {
    setBusy(title);
    try {
      await action();
    } catch (error) {
      setNotice({
        tone: "error",
        title,
        lines: [errorMessage(error)],
      });
    } finally {
      setBusy(null);
    }
  }

  async function refresh(): Promise<void> {
    const [nextCapabilities, nextAccounts] = await Promise.all([
      client.getCapabilities(),
      client.getAccounts(),
    ]);
    setCapabilities(nextCapabilities);
    setAccounts(nextAccounts.accounts);
    setNotice({
      tone: "success",
      title: "Device refreshed",
      lines: [
        `${nextAccounts.accounts.length} active account record(s).`,
        `Credential setup: ${nextCapabilities.credentials === undefined ? "not advertised" : "advertised"}.`,
      ],
    });
  }

  async function connect(): Promise<void> {
    await run("Connect", async () => {
      const nextSession = await client.connect();
      setSession(nextSession);
      await refresh();
    });
  }

  async function disconnect(): Promise<void> {
    await run("Disconnect", async () => {
      await client.disconnect();
      setSession(null);
      setCapabilities(null);
      setAccounts([]);
      setPreparation(null);
      setNonce("");
      setNotice({
        tone: "neutral",
        title: "Disconnected",
        lines: ["Session cleared."],
      });
    });
  }

  async function prepare(): Promise<void> {
    await run("Prepare zkLogin", async () => {
      if (setupBlockedReason !== null) {
        throw new Error(setupBlockedReason);
      }
      const response = await client.credentialPrepare();
      const nextNonce = computeNonce(response.preparation.publicKey, maxEpoch, randomness);
      setPreparation(response.preparation);
      setNonce(nextNonce);
      setNotice({
        tone: "success",
        title: "Preparation received",
        lines: [
          `Preparation address: ${short(response.preparation.address)}`,
          `Nonce: ${nextNonce}`,
        ],
      });
    });
  }

  function randomize(): void {
    setRandomness(generateRandomness());
  }

  function openOAuth(): void {
    try {
      if (nonce.length === 0) {
        throw new Error("Prepare first to create a nonce.");
      }
      if (oauthAuthorizeUrl.trim().length === 0 || oauthClientId.trim().length === 0) {
        throw new Error("Authorization URL and client ID are required.");
      }
      const url = new URL(oauthAuthorizeUrl.trim());
      url.searchParams.set("response_type", "id_token");
      url.searchParams.set("client_id", oauthClientId.trim());
      url.searchParams.set("redirect_uri", oauthRedirectUri.trim());
      url.searchParams.set("scope", oauthScope.trim());
      url.searchParams.set("nonce", nonce);
      globalThis.open(url.toString(), "_blank", "noopener,noreferrer");
      setNotice({
        tone: "neutral",
        title: "OAuth opened",
        lines: ["Return with an id_token in the redirect URL or paste the JWT."],
      });
    } catch (error) {
      setNotice({
        tone: "error",
        title: "OAuth",
        lines: [errorMessage(error)],
      });
    }
  }

  function computeAddress(): void {
    try {
      if (jwt.trim().length === 0 || userSalt.trim().length === 0) {
        throw new Error("JWT and user salt are required.");
      }
      const address = jwtToAddress(jwt.trim(), userSalt.trim(), legacyAddress);
      setProofAddress(address);
      setNotice({
        tone: "success",
        title: "Address computed",
        lines: [`zkLogin address: ${address}`],
      });
    } catch (error) {
      setNotice({
        tone: "error",
        title: "Address",
        lines: [errorMessage(error)],
      });
    }
  }

  async function propose(): Promise<void> {
    await run("Propose proof", async () => {
      if (setupBlockedReason !== null) {
        throw new Error(setupBlockedReason);
      }
      const params = buildCredentialProposeParams({
        network,
        maxEpoch,
        proofAddress,
        proofPublicKey,
        proofJson,
      });
      setProofPublicKey(params.publicKey);
      const response = await client.credentialPropose(params);
      if (response.sessionEnded) {
        client.clearSession();
        setSession(null);
        setCapabilities(null);
        setAccounts([]);
      } else {
        await refresh();
      }
      setNotice({
        tone: response.status === "activated" ? "success" : "error",
        title: "Proof proposal result",
        lines: [
          `Status: ${response.status}`,
          `Reason: ${response.reasonCode}`,
          `Session ended: ${String(response.sessionEnded)}`,
        ],
      });
    });
  }

  async function buildAndSignTransaction(): Promise<void> {
    await run("Sign test transaction", async () => {
      if (activeAccount === null) {
        throw new Error("No active Sui account.");
      }
      const txBytes = await buildSelfTransferTxBytes({
        network,
        sender: activeAccount.address,
        amountMist,
        gasBudgetMist,
      });
      setLastTxBytes(txBytes);
      const response = await client.signTransaction({ network, txBytes });
      setLastSignature(response);
      setNotice({
        tone: response.status === "signed" ? "success" : "error",
        title: "Sign result",
        lines: signResultLines(response, txBytes),
      });
    });
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <h1>Agent-Q zkLogin Test</h1>
          <p>{webSerialAvailable ? "Web Serial ready" : "Web Serial unavailable"}</p>
        </div>
        <div className="header-actions">
          <button type="button" onClick={connect} disabled={!webSerialAvailable || busy !== null}>
            Connect
          </button>
          <button type="button" onClick={() => void run("Refresh", refresh)} disabled={!canUseConnectedDevice}>
            Refresh
          </button>
          <button type="button" onClick={disconnect} disabled={!canUseConnectedDevice}>
            Disconnect
          </button>
        </div>
      </header>

      <section className="status-strip" data-tone={notice.tone}>
        <strong>{busy ?? notice.title}</strong>
        {notice.lines.map((line) => (
          <span key={line}>{line}</span>
        ))}
      </section>

      <div className="workspace-grid">
        <section className="panel device-panel">
          <div className="panel-title">
            <h2>Device</h2>
            <span>{session === null ? "disconnected" : session.device.state}</span>
          </div>
          <dl className="facts">
            <div>
              <dt>Device ID</dt>
              <dd>{session === null ? "none" : session.deviceId}</dd>
            </div>
            <div>
              <dt>Firmware</dt>
              <dd>{session === null ? "none" : `${session.device.firmwareName} ${session.device.firmwareVersion}`}</dd>
            </div>
            <div>
              <dt>Credential ops</dt>
              <dd>{credentialCapability === null ? "not advertised" : credentialCapability.operations.join(", ")}</dd>
            </div>
          </dl>
          <AccountView account={activeAccount} />
          {setupBlockedReason !== null && (
            <p className="inline-warning">{setupBlockedReason}</p>
          )}
        </section>

        <section className="panel">
          <div className="panel-title">
            <h2>Preparation</h2>
            <span>{preparation === null ? "not prepared" : "prepared"}</span>
          </div>
          <div className="form-grid two">
            <label>
              Network
              <select value={network} onChange={(event) => setNetwork(event.target.value as SuiSignTransactionNetwork)}>
                {NETWORKS.map((entry) => (
                  <option key={entry} value={entry}>{entry}</option>
                ))}
              </select>
            </label>
            <label>
              Max epoch
              <input value={maxEpoch} onChange={(event) => setMaxEpoch(event.target.value)} inputMode="numeric" />
            </label>
          </div>
          <label>
            Randomness
            <div className="inline-control">
              <input value={randomness} onChange={(event) => setRandomness(event.target.value)} inputMode="numeric" />
              <button type="button" onClick={randomize} disabled={busy !== null}>Random</button>
            </div>
          </label>
          <button type="button" className="primary" onClick={prepare} disabled={!canUseConnectedDevice || setupBlocked}>
            Prepare nonce
          </button>
          <dl className="facts compact">
            <div>
              <dt>Native prep address</dt>
              <dd>{preparation === null ? "none" : preparation.address}</dd>
            </div>
            <div>
              <dt>Nonce</dt>
              <dd>{nonce.length === 0 ? "none" : nonce}</dd>
            </div>
          </dl>
        </section>

        <section className="panel">
          <div className="panel-title">
            <h2>OAuth</h2>
            <span>{jwt.trim().length === 0 ? "no jwt" : "jwt captured"}</span>
          </div>
          <label>
            Authorization URL
            <input value={oauthAuthorizeUrl} onChange={(event) => setOauthAuthorizeUrl(event.target.value)} placeholder="https://..." />
          </label>
          <div className="form-grid two">
            <label>
              Client ID
              <input value={oauthClientId} onChange={(event) => setOauthClientId(event.target.value)} />
            </label>
            <label>
              Scope
              <input value={oauthScope} onChange={(event) => setOauthScope(event.target.value)} />
            </label>
          </div>
          <label>
            Redirect URI
            <input value={oauthRedirectUri} onChange={(event) => setOauthRedirectUri(event.target.value)} />
          </label>
          <button type="button" onClick={openOAuth} disabled={busy !== null || nonce.length === 0}>
            Open provider login
          </button>
          <label>
            JWT
            <textarea value={jwt} onChange={(event) => setJwt(event.target.value)} rows={3} spellCheck={false} />
          </label>
          <div className="form-grid salt-grid">
            <label>
              User salt
              <input value={userSalt} onChange={(event) => setUserSalt(event.target.value)} inputMode="numeric" />
            </label>
            <label className="checkbox-row">
              <input type="checkbox" checked={legacyAddress} onChange={(event) => setLegacyAddress(event.target.checked)} />
              Legacy address
            </label>
          </div>
          <button type="button" onClick={computeAddress} disabled={busy !== null}>
            Compute address
          </button>
        </section>

        <section className="panel">
          <div className="panel-title">
            <h2>Proof Proposal</h2>
            <span>{setupBlocked ? "locked" : "ready"}</span>
          </div>
          <label>
            zkLogin address
            <input value={proofAddress} onChange={(event) => setProofAddress(event.target.value)} spellCheck={false} />
          </label>
          <label>
            zkLogin public key
            <input value={proofPublicKey} onChange={(event) => setProofPublicKey(event.target.value)} spellCheck={false} />
          </label>
          <label>
            Proof JSON
            <textarea value={proofJson} onChange={(event) => setProofJson(event.target.value)} rows={9} spellCheck={false} />
          </label>
          <button type="button" className="primary" onClick={propose} disabled={!canUseConnectedDevice || setupBlocked}>
            Propose proof
          </button>
        </section>

        <section className="panel transaction-panel">
          <div className="panel-title">
            <h2>Transaction</h2>
            <span>sign only</span>
          </div>
          <div className="form-grid two">
            <label>
              Amount MIST
              <input value={amountMist} onChange={(event) => setAmountMist(event.target.value)} inputMode="numeric" />
            </label>
            <label>
              Gas budget MIST
              <input value={gasBudgetMist} onChange={(event) => setGasBudgetMist(event.target.value)} inputMode="numeric" />
            </label>
          </div>
          <button type="button" className="primary" onClick={buildAndSignTransaction} disabled={!canUseConnectedDevice || activeAccount === null}>
            Build and sign
          </button>
          <label>
            Last txBytes
            <textarea value={lastTxBytes} readOnly rows={4} spellCheck={false} />
          </label>
          <dl className="facts compact">
            <div>
              <dt>Status</dt>
              <dd>{lastSignature === null ? "none" : lastSignature.status}</dd>
            </div>
            <div>
              <dt>Signature</dt>
              <dd>{lastSignature?.status === "signed" ? short(lastSignature.signature) : "none"}</dd>
            </div>
          </dl>
        </section>
      </div>
    </main>
  );
}

function AccountView({ account }: { account: Account | null }) {
  if (account === null) {
    return (
      <div className="account-box empty">
        <span>No active Sui account</span>
      </div>
    );
  }
  return (
    <div className="account-box">
      <div>
        <strong>{account.keyScheme}</strong>
        <span>{account.chain}</span>
      </div>
      <code>{account.address}</code>
      <code>{account.publicKey}</code>
      {"derivationPath" in account && <span>{account.derivationPath}</span>}
    </div>
  );
}

function getSetupBlockedReason(
  session: AgentQConnectedSession | null,
  account: Account | null,
): string | null {
  if (session === null) {
    return "Connect and read the active account first.";
  }
  if (account === null) {
    return "No active Sui account is available.";
  }
  if (account.keyScheme === "zklogin") {
    return "zkLogin account metadata is active. Clear it locally in Settings > Sui before preparing new proof material.";
  }
  if (account.keyScheme !== "ed25519") {
    return "Active account metadata is not a native Ed25519 account.";
  }
  return null;
}

function computeNonce(publicKey: string, maxEpoch: string, randomness: string): string {
  const epoch = parseSafeInteger(maxEpoch, "maxEpoch");
  const trimmedRandomness = randomness.trim();
  if (trimmedRandomness.length === 0 || !/^\d+$/.test(trimmedRandomness)) {
    throw new Error("Randomness must be a decimal integer.");
  }
  const bytes = fromBase64(publicKey);
  if (bytes.length !== 33 || bytes[0] !== 0) {
    throw new Error("Preparation public key is not a scheme-prefixed Ed25519 public key.");
  }
  return generateNonce(new Ed25519PublicKey(bytes.slice(1)), epoch, trimmedRandomness);
}

function buildCredentialProposeParams(input: {
  network: SuiSignTransactionNetwork;
  maxEpoch: string;
  proofAddress: string;
  proofPublicKey: string;
  proofJson: string;
}): CredentialProposeParams {
  const root = parseObjectJson(input.proofJson, "Proof JSON");
  const inputs = selectProofInputs(root);
  const address = stringValue(root.address) ?? input.proofAddress.trim();
  if (address.length === 0) {
    throw new Error("zkLogin address is required.");
  }
  const explicitPublicKey = stringValue(root.publicKey) ?? input.proofPublicKey.trim();
  const publicKey = explicitPublicKey.length > 0 ? explicitPublicKey : deriveZkLoginPublicKey(address, inputs);
  const maxEpoch = stringValue(root.maxEpoch) ?? input.maxEpoch.trim();
  if (maxEpoch.length === 0 || !/^\d+$/.test(maxEpoch)) {
    throw new Error("maxEpoch must be a decimal integer.");
  }
  return {
    chain: "sui",
    credential: "zklogin",
    network: input.network,
    address,
    publicKey,
    maxEpoch,
    inputs,
  };
}

function selectProofInputs(root: Record<string, unknown>): ZkLoginSignatureInputsDto {
  const candidate = isRecord(root.inputs) ? root.inputs : root;
  if (!hasProofInputKeys(candidate)) {
    throw new Error("Proof JSON must contain zkLogin signature inputs.");
  }
  return candidate as unknown as ZkLoginSignatureInputsDto;
}

function deriveZkLoginPublicKey(address: string, inputs: ZkLoginSignatureInputsDto): string {
  return ZkLoginPublicIdentifier
    .fromProof(address, inputs as unknown as ZkLoginSignatureInputs)
    .toSuiPublicKey();
}

async function buildSelfTransferTxBytes(input: {
  network: SuiSignTransactionNetwork;
  sender: string;
  amountMist: string;
  gasBudgetMist: string;
}): Promise<string> {
  if (input.network === "localnet") {
    throw new Error("localnet transaction build needs a custom fullnode URL, which this test app does not configure.");
  }
  const amount = parsePositiveBigInt(input.amountMist, "amount MIST");
  const gasBudget = parsePositiveBigInt(input.gasBudgetMist, "gas budget MIST");
  const client = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl(input.network) });
  const transaction = new Transaction();
  transaction.setSender(input.sender);
  transaction.setGasBudget(gasBudget);
  const [coin] = transaction.splitCoins(transaction.gas, [amount]);
  transaction.transferObjects([coin], input.sender);
  const bytes = await transaction.build({ client });
  return toBase64(bytes);
}

function parseSafeInteger(value: string, label: string): number {
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`${label} must be a decimal integer.`);
  }
  const parsed = Number(trimmed);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${label} must fit in a JavaScript safe integer for Sui SDK nonce generation.`);
  }
  return parsed;
}

function parsePositiveBigInt(value: string, label: string): bigint {
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`${label} must be a decimal integer.`);
  }
  const parsed = BigInt(trimmed);
  if (parsed <= 0n) {
    throw new Error(`${label} must be greater than zero.`);
  }
  return parsed;
}

function parseObjectJson(value: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
  if (!isRecord(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return parsed;
}

function captureJwtFromRedirect(
  setJwt: (value: string) => void,
  setNotice: (notice: Notice) => void,
): void {
  const token = redirectTokenFromParams(globalThis.location.hash) ??
    redirectTokenFromParams(globalThis.location.search);
  if (token === null || token.length === 0) {
    return;
  }
  setJwt(token);
  globalThis.history.replaceState(null, "", scrubRedirectTokenUrl());
  setNotice({
    tone: "success",
    title: "JWT captured",
    lines: ["Redirect token copied into the JWT field."],
  });
}

function redirectTokenFromParams(value: string): string | null {
  const params = new URLSearchParams(stripUrlParamPrefix(value));
  return params.get("id_token") ?? params.get("jwt");
}

function scrubRedirectTokenUrl(): string {
  const searchParams = new URLSearchParams(globalThis.location.search);
  searchParams.delete("id_token");
  searchParams.delete("jwt");

  let nextUrl = globalThis.location.pathname;
  const search = searchParams.toString();
  if (search.length > 0) {
    nextUrl += `?${search}`;
  }

  const hash = stripUrlParamPrefix(globalThis.location.hash);
  if (hash.length === 0) {
    return nextUrl;
  }
  const hashParams = new URLSearchParams(hash);
  if (!hashParams.has("id_token") && !hashParams.has("jwt")) {
    return `${nextUrl}${globalThis.location.hash}`;
  }
  hashParams.delete("id_token");
  hashParams.delete("jwt");
  const cleanHash = hashParams.toString();
  return cleanHash.length === 0 ? nextUrl : `${nextUrl}#${cleanHash}`;
}

function stripUrlParamPrefix(value: string): string {
  return value.startsWith("#") || value.startsWith("?") ? value.slice(1) : value;
}

function signResultLines(response: SignResultResponse, txBytes: string): string[] {
  if (response.status === "signed") {
    return [
      `Authorization: ${response.authorization}`,
      `txBytes chars: ${txBytes.length}`,
      `Signature: ${short(response.signature)}`,
    ];
  }
  if ("error" in response) {
    return [
      `Status: ${response.status}`,
      `Authorization: ${response.authorization}`,
      `${response.error.code}: ${response.error.message}`,
    ];
  }
  return [`Status: ${response.status}`];
}

function stringValue(value: unknown): string | null {
  if (typeof value === "string") {
    return value.trim();
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return String(value);
  }
  return null;
}

function hasProofInputKeys(value: Record<string, unknown>): boolean {
  return (
    isRecord(value.proofPoints) &&
    isRecord(value.issBase64Details) &&
    typeof value.headerBase64 === "string" &&
    typeof value.addressSeed === "string"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function short(value: string): string {
  return value.length <= 36 ? value : `${value.slice(0, 22)}...${value.slice(-10)}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export default App;
