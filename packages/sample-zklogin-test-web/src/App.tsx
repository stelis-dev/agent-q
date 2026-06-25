import { useEffect, useMemo, useState } from "react";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";
import { toBase64 } from "@mysten/sui/utils";
import {
  ZkLoginPublicIdentifier,
  type ZkLoginSignatureInputs,
} from "@mysten/sui/zklogin";
import {
  createEnokiNonce,
  createEnokiZkp,
  defaultOAuthAuthorizeUrl,
  getEnokiApp,
  getEnokiZkLogin,
  toEnokiNetwork,
  type EnokiAuthProvider,
  type EnokiConfig,
} from "./enoki";
import type {
  ConnectDeviceResult,
  CredentialPrepareResult,
  CredentialProposeInput,
} from "@stelis/agent-q-provider-sui/provider-sui";
import {
  createAgentQSuiBrowserProvider,
  isAgentQSuiBrowserProviderAvailable,
} from "@stelis/agent-q-provider-sui/browser";
import type {
  AgentQSuiWalletGetCapabilitiesResult,
  AgentQSuiWalletSignTransactionResult,
  AgentQSuiWalletSuiAccount,
} from "@stelis/agent-q-provider-sui/wallet-standard";

type NoticeTone = "neutral" | "success" | "error";
type Notice = {
  tone: NoticeTone;
  title: string;
  lines: string[];
};
type SuiSignTransactionNetwork = CredentialProposeInput["network"];
type CredentialPreparation = Extract<CredentialPrepareResult, { source: "live" }>["preparation"];
type ZkLoginSignatureInputsDto = CredentialProposeInput["inputs"];
type CredentialCapabilityView = {
  chain: "sui";
  credential: "zklogin";
  operations: string[];
};
type LiveDeviceState = {
  capabilities: AgentQSuiWalletGetCapabilitiesResult;
  accounts: AgentQSuiWalletSuiAccount[];
  credentialCapability: CredentialCapabilityView | null;
  activeAccount: AgentQSuiWalletSuiAccount | null;
};
type PendingEnokiLogin = {
  version: 1;
  createdAt: number;
  enokiConfig: EnokiConfig;
  network: Exclude<SuiSignTransactionNetwork, "localnet">;
  provider: EnokiAuthProvider;
  preparation: CredentialPreparation;
  nonce: string;
  maxEpoch: string;
  randomness: string;
};

const TEST_NETWORK: Exclude<SuiSignTransactionNetwork, "localnet"> = "testnet";
const GOOGLE_PROVIDER: EnokiAuthProvider = "google";
const DEFAULT_GAS_BUDGET_MIST = "10000000";
const DEFAULT_TRANSFER_AMOUNT_MIST = "1";
const DEFAULT_ENOKI_API_URL = envString("VITE_ENOKI_API_URL", "https://api.enoki.mystenlabs.com");
const DEFAULT_ENOKI_API_KEY = envString("VITE_ENOKI_PUBLIC_API_KEY", "");
const DEFAULT_GOOGLE_CLIENT_ID = envString("VITE_ZKLOGIN_GOOGLE_CLIENT_ID", "");
const DEFAULT_REDIRECT_URI = envString("VITE_ZKLOGIN_REDIRECT_URI", defaultCallbackUrl());
const CLIENT_NAME = "Agent-Q zkLogin test web";
const PROVIDER_PURPOSE = "sample-zklogin-test-web";
const ENOKI_LOGIN_STORAGE_KEY = "agent-q:sample-zklogin-test-web:enoki-login";
const OAUTH_CALLBACK_MESSAGE_TYPE = "agent-q:sample-zklogin-test-web:oauth-token";

function App() {
  const [provider] = useState(() => createAgentQSuiBrowserProvider({ clientName: CLIENT_NAME }));
  const [busy, setBusy] = useState<string | null>(null);
  const [session, setSession] = useState<ConnectDeviceResult | null>(null);
  const [capabilities, setCapabilities] = useState<AgentQSuiWalletGetCapabilitiesResult | null>(null);
  const [accounts, setAccounts] = useState<AgentQSuiWalletSuiAccount[]>([]);
  const [enokiApiUrl, setEnokiApiUrl] = useState(DEFAULT_ENOKI_API_URL);
  const [enokiApiKey, setEnokiApiKey] = useState(DEFAULT_ENOKI_API_KEY);
  const [enokiAdditionalEpochs, setEnokiAdditionalEpochs] = useState("2");
  const [oauthClientId, setOauthClientId] = useState(DEFAULT_GOOGLE_CLIENT_ID);
  const [oauthRedirectUri, setOauthRedirectUri] = useState(DEFAULT_REDIRECT_URI);
  const [oauthScope, setOauthScope] = useState("openid email profile");
  const [amountMist, setAmountMist] = useState(DEFAULT_TRANSFER_AMOUNT_MIST);
  const [gasBudgetMist, setGasBudgetMist] = useState(DEFAULT_GAS_BUDGET_MIST);
  const [lastTxBytes, setLastTxBytes] = useState("");
  const [lastSignature, setLastSignature] = useState<AgentQSuiWalletSignTransactionResult | null>(null);
  const [notice, setNotice] = useState<Notice>({
    tone: "neutral",
    title: "Idle",
    lines: ["Ready to set up zkLogin with Enoki."],
  });

  const providerAvailable = isAgentQSuiBrowserProviderAvailable();
  const activeAccount = accounts.find((account) => account.chain === "sui") ?? null;
  const credentialCapability = useMemo(() => {
    return findCredentialCapability(capabilities);
  }, [capabilities]);
  const setupBlockedReason = getSetupBlockedReason(session, activeAccount, credentialCapability);
  const visibleSetupBlockedReason = session === null ? null : setupBlockedReason;
  const canUseConnectedDevice = providerAvailable && session !== null && busy === null;
  const canStartZkLoginSetup = providerAvailable && busy === null && setupBlockedReason === null;
  const activeZkLoginAccount = activeAccount?.keyScheme === "zklogin" ? activeAccount : null;
  const activeZkLoginAddress = activeZkLoginAccount?.address ?? "";
  const canSignZkLoginTest = canUseConnectedDevice && activeZkLoginAccount !== null;
  const activeAccountStatus = activeAccount === null
    ? "No active Sui account"
    : `${activeAccount.keyScheme} ${short(activeAccount.address)}`;

  useEffect(() => {
    const onMessage = (event: MessageEvent<unknown>) => {
      if (event.origin !== globalThis.location.origin || !isRecord(event.data)) {
        return;
      }
      if (event.data.type !== OAUTH_CALLBACK_MESSAGE_TYPE || typeof event.data.idToken !== "string") {
        return;
      }
      void finishEnokiLogin(event.data.idToken);
    };
    globalThis.addEventListener("message", onMessage);
    consumeOAuthRedirect((token) => void finishEnokiLogin(token), setNotice);
    return () => {
      globalThis.removeEventListener("message", onMessage);
      provider.dispose();
    };
  }, [provider]);

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

  async function readLiveDevice(showNotice = false): Promise<LiveDeviceState> {
    const [nextCapabilities, nextAccounts] = await Promise.all([
      provider.getCapabilities({ purpose: PROVIDER_PURPOSE }),
      provider.getAccounts({ purpose: PROVIDER_PURPOSE }),
    ]);
    if (nextCapabilities.source !== "live" || nextAccounts.source !== "live" || !Array.isArray(nextAccounts.accounts)) {
      clearDeviceMirror();
      throw new Error(`Device session is not live: ${resultSummary(nextCapabilities)} / ${resultSummary(nextAccounts)}.`);
    }
    const nextCredentialCapability = findCredentialCapability(nextCapabilities);
    const nextAccountsList = nextAccounts.accounts.filter((account): account is AgentQSuiWalletSuiAccount => {
      return account.chain === "sui" && (account.keyScheme === "ed25519" || account.keyScheme === "zklogin");
    });
    const nextActiveAccount = nextAccountsList.find((account) => account.chain === "sui") ?? null;
    setCapabilities(nextCapabilities);
    setAccounts(nextAccountsList);
    if (nextActiveAccount?.keyScheme !== "zklogin") {
      setLastTxBytes("");
      setLastSignature(null);
    }
    if (showNotice) {
      setNotice({
        tone: "success",
        title: "Device refreshed",
        lines: [
          nextActiveAccount === null ? "No active Sui account." : `${nextActiveAccount.keyScheme} ${short(nextActiveAccount.address)}`,
          `Credential setup: ${nextCredentialCapability === null ? "not advertised" : "advertised"}.`,
        ],
      });
    }
    return {
      capabilities: nextCapabilities,
      accounts: nextAccountsList,
      credentialCapability: nextCredentialCapability,
      activeAccount: nextActiveAccount,
    };
  }

  async function ensureConnected(): Promise<{ session: ConnectDeviceResult } & LiveDeviceState> {
    setBusy("Connect Agent-Q");
    const nextSession = parseConnectedDevice(await provider.connectDevice({
      clientName: CLIENT_NAME,
      purpose: PROVIDER_PURPOSE,
    }));
    setSession(nextSession);
    const live = await readLiveDevice();
    return { session: nextSession, ...live };
  }

  async function connect(): Promise<void> {
    await run("Connect", async () => {
      const live = await ensureConnected();
      setNotice({
        tone: "success",
        title: "Connected",
        lines: [
          live.activeAccount === null ? "No active Sui account." : `${live.activeAccount.keyScheme} ${short(live.activeAccount.address)}`,
        ],
      });
    });
  }

  async function refresh(): Promise<void> {
    await run("Refresh", async () => {
      await readLiveDevice(true);
    });
  }

  async function disconnect(): Promise<void> {
    await run("Disconnect", async () => {
      await provider.disconnectDevice({ purpose: PROVIDER_PURPOSE });
      clearDeviceMirror();
      removePendingEnokiLogin();
      setNotice({
        tone: "neutral",
        title: "Disconnected",
        lines: ["Session cleared."],
      });
    });
  }

  function currentEnokiConfig(): EnokiConfig {
    return { apiUrl: enokiApiUrl, apiKey: enokiApiKey };
  }

  function requireEnokiConfig(): EnokiConfig {
    const config = currentEnokiConfig();
    if (config.apiUrl.trim().length === 0) {
      throw new Error("Enoki API URL is required.");
    }
    if (config.apiKey.trim().length === 0) {
      throw new Error("Enoki public API key is required.");
    }
    return config;
  }

  async function resolveEnokiOAuth(config: EnokiConfig): Promise<{
    provider: EnokiAuthProvider;
    clientId: string;
  }> {
    const explicitClientId = oauthClientId.trim();
    if (explicitClientId.length > 0) {
      return { provider: GOOGLE_PROVIDER, clientId: explicitClientId };
    }
    const providers = await getEnokiApp(config);
    const selected = providers.find((entry) => entry.providerType === GOOGLE_PROVIDER) ?? null;
    if (selected === null) {
      throw new Error("Enoki app metadata did not include a Google OAuth provider.");
    }
    setOauthClientId(selected.clientId);
    return {
      provider: selected.providerType,
      clientId: selected.clientId,
    };
  }

  async function loginWithEnoki(): Promise<void> {
    await run("Set up zkLogin", async () => {
      setBusy("Prepare Enoki login");
      const enokiConfig = requireEnokiConfig();
      const live = await ensureConnected();
      const blockedReason = getSetupBlockedReason(live.session, live.activeAccount, live.credentialCapability);
      if (blockedReason !== null) {
        throw new Error(blockedReason);
      }
      const oauth = await resolveEnokiOAuth(enokiConfig);
      const response = await provider.credentialPrepare({
        chain: "sui",
        credential: "zklogin",
        purpose: PROVIDER_PURPOSE,
      });
      if (response.source !== "live") {
        clearDeviceMirror();
        throw new Error(`Credential preparation did not return live data: ${resultSummary(response)}.`);
      }
      const nextNonce = await createEnokiNonce(enokiConfig, {
        network: toEnokiNetwork(TEST_NETWORK),
        ephemeralPublicKey: response.preparation.publicKey,
        additionalEpochs: parseOptionalEpochs(enokiAdditionalEpochs),
      });
      const pending: PendingEnokiLogin = {
        version: 1,
        createdAt: Date.now(),
        enokiConfig,
        network: TEST_NETWORK,
        provider: oauth.provider,
        preparation: response.preparation,
        nonce: nextNonce.nonce,
        maxEpoch: String(nextNonce.maxEpoch),
        randomness: nextNonce.randomness,
      };
      writePendingEnokiLogin(pending);
      openEnokiOAuth({
        pending,
        clientId: oauth.clientId,
        redirectUri: oauthRedirectUri,
        scope: oauthScope,
      });
      setNotice({
        tone: "neutral",
        title: "Google login opened",
        lines: [
          "Google login is waiting in the popup.",
          `Expires: ${formatTimestamp(nextNonce.estimatedExpiration)}`,
        ],
      });
    });
  }

  async function finishEnokiLogin(idToken: string): Promise<void> {
    await run("Finish Enoki login", async () => {
      const pending = readPendingEnokiLogin();
      if (pending === null) {
        throw new Error("No pending Enoki login was found. Start login again.");
      }
      removePendingEnokiLogin();
      const trimmedJwt = idToken.trim();
      if (trimmedJwt.length === 0) {
        throw new Error("OAuth callback did not contain an id_token.");
      }
      setBusy("Create Enoki proof");
      const maxEpochNumber = parseSafeInteger(pending.maxEpoch, "maxEpoch");
      const [login, proof] = await Promise.all([
        getEnokiZkLogin(pending.enokiConfig, trimmedJwt),
        createEnokiZkp(pending.enokiConfig, {
          network: toEnokiNetwork(pending.network),
          jwt: trimmedJwt,
          ephemeralPublicKey: pending.preparation.publicKey,
          maxEpoch: maxEpochNumber,
          randomness: parseDecimalString(pending.randomness, "randomness"),
        }),
      ]);
      const proofInputs = proof as unknown as ZkLoginSignatureInputsDto;
      const derivedPublicKey = deriveZkLoginPublicKey(login.address, proofInputs);
      if (derivedPublicKey !== login.publicKey) {
        throw new Error("Enoki address/public key did not match the returned proof inputs.");
      }

      setBusy("Propose zkLogin proof");
      const live = await ensureConnected();
      const blockedReason = getSetupBlockedReason(live.session, live.activeAccount, live.credentialCapability);
      if (blockedReason !== null) {
        throw new Error(blockedReason);
      }
      const response = await provider.credentialPropose({
        chain: "sui",
        credential: "zklogin",
        network: pending.network,
        address: login.address,
        publicKey: login.publicKey,
        maxEpoch: pending.maxEpoch,
        inputs: proofInputs,
        purpose: PROVIDER_PURPOSE,
      });
      if (response.source !== "live") {
        clearDeviceMirror();
        setNotice({
          tone: "error",
          title: "zkLogin proposal failed",
          lines: [`Source: ${response.source}`, `Reason: ${response.reason ?? "unknown"}`],
        });
        return;
      }
      if (response.status !== "activated") {
        if (response.sessionEnded) {
          clearDeviceMirror();
        } else {
          await readLiveDevice();
        }
        setNotice({
          tone: "error",
          title: "zkLogin proposal rejected",
          lines: [
            `Status: ${response.status}`,
            `Reason: ${response.reasonCode}`,
          ],
        });
        return;
      }

      if (response.sessionEnded) {
        clearDeviceMirror();
        setBusy("Reconnect zkLogin account");
        const nextSession = parseConnectedDevice(await provider.connectDevice({
          clientName: CLIENT_NAME,
          purpose: PROVIDER_PURPOSE,
        }));
        setSession(nextSession);
      }
      const refreshed = await readLiveDevice();
      if (refreshed.activeAccount?.keyScheme !== "zklogin" || refreshed.activeAccount.address !== login.address) {
        throw new Error("Device did not return the activated zkLogin account after reconnect.");
      }
      setNotice({
        tone: "success",
        title: "zkLogin activated",
        lines: [
          `Address: ${short(refreshed.activeAccount.address)}`,
          `Active account: ${refreshed.activeAccount.keyScheme}`,
        ],
      });
    });
  }

  async function buildAndSignTransaction(): Promise<void> {
    await run("Sign test transaction", async () => {
      const live = await readLiveDevice();
      const signingAccount = live.activeAccount?.keyScheme === "zklogin" ? live.activeAccount : null;
      if (signingAccount === null) {
        throw new Error("Activate zkLogin before running the transaction signing test.");
      }
      const txBytes = await buildSelfTransferTxBytes({
        network: TEST_NETWORK,
        sender: signingAccount.address,
        amountMist,
        gasBudgetMist,
      });
      setLastTxBytes(txBytes);
      const response = await provider.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network: TEST_NETWORK,
        txBytes,
        purpose: PROVIDER_PURPOSE,
      });
      setLastSignature(response);
      if (response.source !== "live") {
        clearDeviceMirror();
      }
      setNotice({
        tone: response.source === "live" && response.status === "signed" ? "success" : "error",
        title: "Signing outcome",
        lines: signResultLines(response, txBytes),
      });
    });
  }

  function clearDeviceMirror(): void {
    setSession(null);
    setCapabilities(null);
    setAccounts([]);
    setLastTxBytes("");
    setLastSignature(null);
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <h1>Agent-Q zkLogin Test</h1>
          <p>{providerAvailable ? "Agent-Q ready" : "Agent-Q unavailable"} · Network: {TEST_NETWORK}</p>
        </div>
      </header>

      <section className="status-strip" data-tone={notice.tone}>
        <strong>{busy ?? notice.title}</strong>
        {notice.lines.map((line) => (
          <span key={line}>{line}</span>
        ))}
      </section>

      <div className="flow-stack">
        <section className="flow-step">
          <div className="flow-step-head">
            <span>1</span>
            <div>
              <h2>Connect device</h2>
              <p>{activeAccountStatus}</p>
            </div>
          </div>
          <div className="button-row">
            <button type="button" className="primary" onClick={connect} disabled={!providerAvailable || busy !== null}>
              Connect device
            </button>
            <button type="button" onClick={refresh} disabled={!canUseConnectedDevice}>
              Reload device state
            </button>
            <button type="button" onClick={disconnect} disabled={!canUseConnectedDevice}>
              Disconnect device
            </button>
          </div>
          <details className="settings-slide">
            <summary>Device details</summary>
            <dl className="facts">
              <div>
                <dt>State</dt>
                <dd>{session === null ? "disconnected" : session.device.state}</dd>
              </div>
              <div>
                <dt>Credential ops</dt>
                <dd>{credentialCapability === null ? "not advertised" : credentialCapability.operations.join(", ")}</dd>
              </div>
            </dl>
          </details>
          {visibleSetupBlockedReason !== null && (
            <p className="inline-warning">{visibleSetupBlockedReason}</p>
          )}
        </section>

        <section className="flow-step">
          <div className="flow-step-head">
            <span>2</span>
            <div>
              <h2>Enoki configuration</h2>
              <p>Google OAuth</p>
            </div>
          </div>
          <details className="settings-slide">
            <summary>Open Enoki settings</summary>
            <label>
              Enoki API URL
              <input value={enokiApiUrl} onChange={(event) => setEnokiApiUrl(event.target.value)} spellCheck={false} />
            </label>
            <label>
              Enoki public API key
              <input value={enokiApiKey} onChange={(event) => setEnokiApiKey(event.target.value)} spellCheck={false} />
            </label>
            <div className="form-grid two">
              <label>
                Google OAuth client ID
                <input value={oauthClientId} onChange={(event) => setOauthClientId(event.target.value)} spellCheck={false} />
              </label>
              <label>
                Additional epochs
                <input value={enokiAdditionalEpochs} onChange={(event) => setEnokiAdditionalEpochs(event.target.value)} inputMode="numeric" />
              </label>
            </div>
            <label>
              Callback URL
              <input value={oauthRedirectUri} onChange={(event) => setOauthRedirectUri(event.target.value)} spellCheck={false} />
            </label>
            <label>
              Scope
              <input value={oauthScope} onChange={(event) => setOauthScope(event.target.value)} spellCheck={false} />
            </label>
          </details>
        </section>

        <section className="flow-step">
          <div className="flow-step-head">
            <span>3</span>
            <div>
              <h2>Set up zkLogin</h2>
              <p>{activeZkLoginAddress.length === 0 ? "not activated" : short(activeZkLoginAddress)}</p>
            </div>
          </div>
          <button type="button" className="primary login-button" onClick={loginWithEnoki} disabled={!canStartZkLoginSetup}>
            Set up zkLogin with Google
          </button>
        </section>

        <section className="flow-step">
          <div className="flow-step-head">
            <span>4</span>
            <div>
              <h2>Transaction signing test</h2>
              <p>{lastSignature === null ? "not signed" : signStatusLabel(lastSignature)}</p>
            </div>
          </div>
          <button type="button" className="primary" onClick={buildAndSignTransaction} disabled={!canSignZkLoginTest}>
            Sign test transfer
          </button>
          <details className="settings-slide">
            <summary>Transaction details</summary>
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
            <label>
              Last txBytes
              <textarea value={lastTxBytes} readOnly rows={4} spellCheck={false} />
            </label>
            <dl className="facts compact">
              <div>
                <dt>Status</dt>
                <dd>{lastSignature === null ? "none" : signStatusLabel(lastSignature)}</dd>
              </div>
              <div>
                <dt>Address</dt>
                <dd>{activeZkLoginAddress.length === 0 ? "none" : activeZkLoginAddress}</dd>
              </div>
              <div>
                <dt>Signature</dt>
                <dd>{lastSignature?.source === "live" && lastSignature.status === "signed" ? short(lastSignature.signature) : "none"}</dd>
              </div>
            </dl>
          </details>
        </section>
      </div>
    </main>
  );
}

function getSetupBlockedReason(
  session: ConnectDeviceResult | null,
  account: AgentQSuiWalletSuiAccount | null,
  credentialCapability: CredentialCapabilityView | null,
): string | null {
  if (session === null) {
    return "Connect and read the active account first.";
  }
  if (account === null) {
    return "No active Sui account is available.";
  }
  if (account.keyScheme === "zklogin") {
    return "zkLogin account metadata is active. Clear it locally in Settings > Accounts > Sui before preparing new proof material.";
  }
  if (account.keyScheme !== "ed25519") {
    return "Active account metadata is not a native Ed25519 account.";
  }
  if (credentialCapability === null) {
    return "Connected device does not advertise zkLogin credential setup.";
  }
  return null;
}

function parseConnectedDevice(value: unknown): ConnectDeviceResult {
  if (!isRecord(value) || value.source !== "connected" || typeof value.deviceId !== "string") {
    throw new Error("Agent-Q browser provider did not return a connected device.");
  }
  if (typeof value.sessionTtlMs !== "number" || typeof value.connectedAt !== "string") {
    throw new Error("Agent-Q browser provider returned malformed connection metadata.");
  }
  if (!isRecord(value.device) ||
    typeof value.device.state !== "string" ||
    typeof value.device.firmwareName !== "string" ||
    typeof value.device.firmwareVersion !== "string") {
    throw new Error("Agent-Q browser provider returned malformed device metadata.");
  }
  return value as ConnectDeviceResult;
}

function findCredentialCapability(
  capabilities: AgentQSuiWalletGetCapabilitiesResult | null,
): CredentialCapabilityView | null {
  if (capabilities === null || capabilities.source !== "live" || !Array.isArray(capabilities.credentials)) {
    return null;
  }
  for (const entry of capabilities.credentials) {
    if (!isRecord(entry) || entry.chain !== "sui" || entry.credential !== "zklogin") {
      continue;
    }
    const operations = Array.isArray(entry.operations)
      ? entry.operations.filter((operation): operation is string => typeof operation === "string")
      : [];
    return { chain: "sui", credential: "zklogin", operations };
  }
  return null;
}

function openEnokiOAuth(input: {
  pending: PendingEnokiLogin;
  clientId: string;
  redirectUri: string;
  scope: string;
}): void {
  const redirectUri = input.redirectUri.trim();
  if (redirectUri.length === 0) {
    throw new Error("Callback URL is required.");
  }
  const url = new URL(defaultOAuthAuthorizeUrl(input.pending.provider));
  url.searchParams.set("response_type", "id_token");
  url.searchParams.set("client_id", input.clientId.trim());
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", input.scope.trim());
  url.searchParams.set("nonce", input.pending.nonce);
  const popup = globalThis.open(
    url.toString(),
    "agent-q-zklogin-oauth",
    "popup,width=520,height=720",
  );
  if (popup === null) {
    globalThis.location.assign(url.toString());
    return;
  }
  popup.focus();
}

function consumeOAuthRedirect(
  complete: (idToken: string) => void,
  setNotice: (notice: Notice) => void,
): void {
  const token = redirectTokenFromParams(globalThis.location.hash) ??
    redirectTokenFromParams(globalThis.location.search);
  if (token === null || token.length === 0) {
    if (redirectHasTokenParam(globalThis.location.hash) ||
      redirectHasTokenParam(globalThis.location.search)) {
      globalThis.history.replaceState(null, "", scrubRedirectTokenUrl());
      setNotice({
        tone: "error",
        title: "OAuth callback",
        lines: ["Google callback did not contain an id_token."],
      });
    }
    return;
  }
  globalThis.history.replaceState(null, "", scrubRedirectTokenUrl());
  if (globalThis.opener !== null && globalThis.opener !== globalThis) {
    globalThis.opener.postMessage({
      type: OAUTH_CALLBACK_MESSAGE_TYPE,
      idToken: token,
    }, globalThis.location.origin);
    setNotice({
      tone: "success",
      title: "OAuth complete",
      lines: ["Returning to the login window."],
    });
    globalThis.setTimeout(() => globalThis.close(), 0);
    return;
  }
  complete(token);
}

function redirectTokenFromParams(value: string): string | null {
  const params = new URLSearchParams(stripUrlParamPrefix(value));
  return params.get("id_token");
}

function redirectHasTokenParam(value: string): boolean {
  const params = new URLSearchParams(stripUrlParamPrefix(value));
  return params.has("id_token") || params.has("jwt");
}

function scrubRedirectTokenUrl(): string {
  const searchParams = new URLSearchParams(globalThis.location.search);
  searchParams.delete("id_token");
  searchParams.delete("jwt");

  let nextUrl = callbackReturnPath(globalThis.location.pathname);
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

function defaultCallbackUrl(): string {
  const origin = globalThis.location?.origin ?? "";
  return origin.length === 0 ? "" : `${origin}/callback.html`;
}

function callbackReturnPath(pathname: string): string {
  if (pathname === "/callback.html" || pathname === "/callback") {
    return "/";
  }
  if (pathname.endsWith("/callback.html")) {
    return pathname.slice(0, -"/callback.html".length) || "/";
  }
  if (pathname.endsWith("/callback")) {
    return pathname.slice(0, -"/callback".length) || "/";
  }
  return pathname;
}

function writePendingEnokiLogin(value: PendingEnokiLogin): void {
  globalThis.sessionStorage?.setItem(ENOKI_LOGIN_STORAGE_KEY, JSON.stringify(value));
}

function readPendingEnokiLogin(): PendingEnokiLogin | null {
  const raw = globalThis.sessionStorage?.getItem(ENOKI_LOGIN_STORAGE_KEY);
  if (raw === null || raw === undefined) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    removePendingEnokiLogin();
    return null;
  }
  if (!isPendingEnokiLogin(parsed)) {
    removePendingEnokiLogin();
    return null;
  }
  return parsed;
}

function removePendingEnokiLogin(): void {
  globalThis.sessionStorage?.removeItem(ENOKI_LOGIN_STORAGE_KEY);
}

function isPendingEnokiLogin(value: unknown): value is PendingEnokiLogin {
  return isRecord(value) &&
    value.version === 1 &&
    typeof value.createdAt === "number" &&
    isRecord(value.enokiConfig) &&
    typeof value.enokiConfig.apiUrl === "string" &&
    typeof value.enokiConfig.apiKey === "string" &&
    value.network === TEST_NETWORK &&
    value.provider === GOOGLE_PROVIDER &&
    isRecord(value.preparation) &&
    typeof value.preparation.publicKey === "string" &&
    typeof value.preparation.address === "string" &&
    typeof value.nonce === "string" &&
    typeof value.maxEpoch === "string" &&
    typeof value.randomness === "string";
}

function deriveZkLoginPublicKey(address: string, inputs: ZkLoginSignatureInputsDto): string {
  return ZkLoginPublicIdentifier
    .fromProof(address, inputs as unknown as ZkLoginSignatureInputs)
    .toSuiPublicKey();
}

async function buildSelfTransferTxBytes(input: {
  network: Exclude<SuiSignTransactionNetwork, "localnet">;
  sender: string;
  amountMist: string;
  gasBudgetMist: string;
}): Promise<string> {
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
  const trimmed = parseDecimalString(value, label);
  const parsed = Number(trimmed);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${label} must fit in a JavaScript safe integer.`);
  }
  return parsed;
}

function parseOptionalEpochs(value: string): number | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return undefined;
  }
  const parsed = parseSafeInteger(trimmed, "Enoki additional epochs");
  if (parsed > 30) {
    throw new Error("Enoki additional epochs must be between 0 and 30.");
  }
  return parsed;
}

function parseDecimalString(value: string, label: string): string {
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`${label} must be a decimal integer.`);
  }
  return trimmed;
}

function parsePositiveBigInt(value: string, label: string): bigint {
  const trimmed = parseDecimalString(value, label);
  const parsed = BigInt(trimmed);
  if (parsed <= 0n) {
    throw new Error(`${label} must be greater than zero.`);
  }
  return parsed;
}

function resultSummary(value: unknown): string {
  if (!isRecord(value)) {
    return "invalid result";
  }
  const source = typeof value.source === "string" ? value.source : "unknown";
  const reason = typeof value.reason === "string" ? `/${value.reason}` : "";
  return `${source}${reason}`;
}

function signResultLines(response: AgentQSuiWalletSignTransactionResult, txBytes: string): string[] {
  if (response.source !== "live") {
    return [
      `Source: ${response.source}`,
      `Reason: ${response.reason ?? "unknown"}`,
    ];
  }
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
      response.error.message ?? "No error message returned.",
    ];
  }
  return [`Status: ${response.status}`];
}

function signStatusLabel(response: AgentQSuiWalletSignTransactionResult): string {
  return response.source === "live" ? response.status ?? "unknown" : response.source;
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

function envString(name: string, fallback: string): string {
  const value = import.meta.env[name];
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function formatTimestamp(value: number): string {
  if (!Number.isFinite(value) || value <= 0) {
    return "unknown";
  }
  return new Date(value).toISOString();
}

export default App;
