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
import {
  createEnokiNonce,
  createEnokiZkp,
  defaultOAuthAuthorizeUrl,
  getEnokiApp,
  getEnokiZkLogin,
  toEnokiNetwork,
  type EnokiAppProvider,
  type EnokiAuthProvider,
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
type CredentialProposalInput = Omit<CredentialProposeInput, "deviceId" | "purpose">;
type ZkLoginSignatureInputsDto = CredentialProposalInput["inputs"];
type CredentialCapabilityView = {
  chain: "sui";
  credential: "zklogin";
  operations: string[];
};

const NETWORKS: SuiSignTransactionNetwork[] = ["testnet", "devnet", "mainnet", "localnet"];
const DEFAULT_GAS_BUDGET_MIST = "10000000";
const DEFAULT_TRANSFER_AMOUNT_MIST = "1";
const DEFAULT_ENOKI_API_URL = envString("VITE_ENOKI_API_URL", "https://api.enoki.mystenlabs.com");
const DEFAULT_ENOKI_API_KEY = envString("VITE_ENOKI_PUBLIC_API_KEY", "");
const DEFAULT_GOOGLE_CLIENT_ID = envString("VITE_ZKLOGIN_GOOGLE_CLIENT_ID", "");
const ENOKI_PROVIDERS: EnokiAuthProvider[] = ["google", "facebook", "twitch"];
const CLIENT_NAME = "Agent-Q zkLogin test web";
const PROVIDER_PURPOSE = "zklogin-test-web";

function App() {
  const [provider] = useState(() => createAgentQSuiBrowserProvider({ clientName: CLIENT_NAME }));
  const [busy, setBusy] = useState<string | null>(null);
  const [session, setSession] = useState<ConnectDeviceResult | null>(null);
  const [capabilities, setCapabilities] = useState<AgentQSuiWalletGetCapabilitiesResult | null>(null);
  const [accounts, setAccounts] = useState<AgentQSuiWalletSuiAccount[]>([]);
  const [network, setNetwork] = useState<SuiSignTransactionNetwork>("testnet");
  const [enokiApiUrl, setEnokiApiUrl] = useState(DEFAULT_ENOKI_API_URL);
  const [enokiApiKey, setEnokiApiKey] = useState(DEFAULT_ENOKI_API_KEY);
  const [enokiAdditionalEpochs, setEnokiAdditionalEpochs] = useState("2");
  const [enokiProvider, setEnokiProvider] = useState<EnokiAuthProvider>("google");
  const [enokiAppProviders, setEnokiAppProviders] = useState<EnokiAppProvider[]>([]);
  const [maxEpoch, setMaxEpoch] = useState("10");
  const [randomness, setRandomness] = useState(() => generateRandomness());
  const [preparation, setPreparation] = useState<CredentialPreparation | null>(null);
  const [nonce, setNonce] = useState("");
  const [oauthAuthorizeUrl, setOauthAuthorizeUrl] = useState(() => defaultOAuthAuthorizeUrl("google"));
  const [oauthClientId, setOauthClientId] = useState(DEFAULT_GOOGLE_CLIENT_ID);
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
  const [lastSignature, setLastSignature] = useState<AgentQSuiWalletSignTransactionResult | null>(null);
  const [notice, setNotice] = useState<Notice>({
    tone: "neutral",
    title: "Idle",
    lines: ["No device session."],
  });

  const providerAvailable = isAgentQSuiBrowserProviderAvailable();
  const activeAccount = accounts.find((account) => account.chain === "sui") ?? null;

  const credentialCapability = useMemo(() => {
    return findCredentialCapability(capabilities);
  }, [capabilities]);
  const setupBlockedReason = getSetupBlockedReason(session, activeAccount, credentialCapability);
  const setupBlocked = setupBlockedReason !== null;
  const canUseConnectedDevice = providerAvailable && session !== null && busy === null;

  useEffect(() => {
    captureJwtFromRedirect(setJwt, setNotice);
    return () => {
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

  async function refresh(): Promise<void> {
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
    setCapabilities(nextCapabilities);
    setAccounts(nextAccountsList);
    setNotice({
      tone: "success",
      title: "Device refreshed",
      lines: [
        `${nextAccountsList.length} active account record(s).`,
        `Credential setup: ${nextCredentialCapability === null ? "not advertised" : "advertised"}.`,
      ],
    });
  }

  async function connect(): Promise<void> {
    await run("Connect", async () => {
      const nextSession = parseConnectedDevice(await provider.connectDevice({
        clientName: CLIENT_NAME,
        purpose: PROVIDER_PURPOSE,
      }));
      setSession(nextSession);
      await refresh();
    });
  }

  async function disconnect(): Promise<void> {
    await run("Disconnect", async () => {
      await provider.disconnectDevice({ purpose: PROVIDER_PURPOSE });
      clearDeviceMirror();
      setNotice({
        tone: "neutral",
        title: "Disconnected",
        lines: ["Session cleared."],
      });
    });
  }

  async function prepare(): Promise<void> {
    await run("Prepare local nonce", async () => {
      if (setupBlockedReason !== null) {
        throw new Error(setupBlockedReason);
      }
      const response = await provider.credentialPrepare({
        chain: "sui",
        credential: "zklogin",
        purpose: PROVIDER_PURPOSE,
      });
      if (response.source !== "live") {
        clearDeviceMirror();
        throw new Error(`Credential preparation did not return live data: ${resultSummary(response)}.`);
      }
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

  function currentEnokiConfig() {
    return { apiUrl: enokiApiUrl, apiKey: enokiApiKey };
  }

  function requireEnokiConfig() {
    const config = currentEnokiConfig();
    if (config.apiUrl.trim().length === 0) {
      throw new Error("Enoki API URL is required.");
    }
    if (config.apiKey.trim().length === 0) {
      throw new Error("Enoki public API key is required.");
    }
    return config;
  }

  async function loadEnokiApp(): Promise<void> {
    await run("Load Enoki app", async () => {
      const providers = await getEnokiApp(requireEnokiConfig());
      setEnokiAppProviders(providers);
      const selected = providers.find((entry) => entry.providerType === enokiProvider) ?? providers[0] ?? null;
      if (selected !== null) {
        setEnokiProvider(selected.providerType);
        setOauthAuthorizeUrl(defaultOAuthAuthorizeUrl(selected.providerType));
        setOauthClientId(selected.clientId);
      }
      setNotice({
        tone: "success",
        title: "Enoki app loaded",
        lines: [
          providers.length === 0 ? "No supported OAuth providers returned." : `Providers: ${providers.map((entry) => entry.providerType).join(", ")}`,
          selected === null ? "Client ID not changed." : `Selected client ID for ${selected.providerType}.`,
        ],
      });
    });
  }

  async function prepareWithEnoki(): Promise<void> {
    await run("Prepare Enoki nonce", async () => {
      if (setupBlockedReason !== null) {
        throw new Error(setupBlockedReason);
      }
      const enokiNetwork = toEnokiNetwork(network);
      const enokiConfig = requireEnokiConfig();
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
        network: enokiNetwork,
        ephemeralPublicKey: response.preparation.publicKey,
        additionalEpochs: parseOptionalEpochs(enokiAdditionalEpochs),
      });
      setPreparation(response.preparation);
      setNonce(nextNonce.nonce);
      setMaxEpoch(String(nextNonce.maxEpoch));
      setRandomness(nextNonce.randomness);
      setNotice({
        tone: "success",
        title: "Enoki nonce received",
        lines: [
          `Preparation address: ${short(response.preparation.address)}`,
          `Max epoch: ${nextNonce.maxEpoch}`,
          `Expires: ${formatTimestamp(nextNonce.estimatedExpiration)}`,
        ],
      });
    });
  }

  function selectEnokiProvider(providerName: EnokiAuthProvider): void {
    setEnokiProvider(providerName);
    setOauthAuthorizeUrl(defaultOAuthAuthorizeUrl(providerName));
    const providerMetadata = enokiAppProviders.find((entry) => entry.providerType === providerName);
    if (providerMetadata !== undefined) {
      setOauthClientId(providerMetadata.clientId);
    }
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
      if (enokiProvider === "twitch") {
        url.searchParams.set("force_verify", "true");
      }
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

  async function createProofWithEnoki(): Promise<void> {
    await run("Create Enoki proof", async () => {
      if (setupBlockedReason !== null) {
        throw new Error(setupBlockedReason);
      }
      if (preparation === null) {
        throw new Error("Prepare Enoki nonce first.");
      }
      const trimmedJwt = jwt.trim();
      if (trimmedJwt.length === 0) {
        throw new Error("JWT is required.");
      }
      const enokiNetwork = toEnokiNetwork(network);
      const enokiConfig = requireEnokiConfig();
      const maxEpochNumber = parseSafeInteger(maxEpoch, "maxEpoch");
      const nextRandomness = parseDecimalString(randomness, "randomness");
      const [login, proof] = await Promise.all([
        getEnokiZkLogin(enokiConfig, trimmedJwt),
        createEnokiZkp(enokiConfig, {
          network: enokiNetwork,
          jwt: trimmedJwt,
          ephemeralPublicKey: preparation.publicKey,
          maxEpoch: maxEpochNumber,
          randomness: nextRandomness,
        }),
      ]);
      const derivedPublicKey = deriveZkLoginPublicKey(login.address, proof as unknown as ZkLoginSignatureInputsDto);
      if (derivedPublicKey !== login.publicKey) {
        throw new Error("Enoki address/public key did not match the returned proof inputs.");
      }
      const proposal = {
        address: login.address,
        publicKey: login.publicKey,
        maxEpoch: String(maxEpochNumber),
        inputs: proof,
      };
      setProofAddress(login.address);
      setProofPublicKey(login.publicKey);
      setProofJson(JSON.stringify(proposal, null, 2));
      setJwt("");
      setNotice({
        tone: "success",
        title: "Enoki proof ready",
        lines: [
          `zkLogin address: ${short(login.address)}`,
          "JWT cleared from this page after proof creation.",
        ],
      });
    });
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
      const response = await provider.credentialPropose({
        ...params,
        purpose: PROVIDER_PURPOSE,
      });
      if (response.source !== "live") {
        clearDeviceMirror();
        throw new Error(`Credential proposal did not return a live result: ${resultSummary(response)}.`);
      }
      if (response.sessionEnded) {
        clearDeviceMirror();
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
      const response = await provider.signTransaction({
        chain: "sui",
        method: "sign_transaction",
        network,
        txBytes,
        purpose: PROVIDER_PURPOSE,
      });
      setLastSignature(response);
      if (response.source !== "live") {
        clearDeviceMirror();
      }
      setNotice({
        tone: response.source === "live" && response.status === "signed" ? "success" : "error",
        title: "Sign result",
        lines: signResultLines(response, txBytes),
      });
    });
  }

  function clearDeviceMirror(): void {
    setSession(null);
    setCapabilities(null);
    setAccounts([]);
    setPreparation(null);
    setNonce("");
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <h1>Agent-Q zkLogin Test</h1>
          <p>{providerAvailable ? "Agent-Q browser provider ready" : "Agent-Q browser provider unavailable"}</p>
        </div>
        <div className="header-actions">
          <button type="button" onClick={connect} disabled={!providerAvailable || busy !== null}>
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
              Enoki additional epochs
              <input value={enokiAdditionalEpochs} onChange={(event) => setEnokiAdditionalEpochs(event.target.value)} inputMode="numeric" />
            </label>
          </div>
          <div className="form-grid two">
            <label>
              Max epoch
              <input value={maxEpoch} onChange={(event) => setMaxEpoch(event.target.value)} inputMode="numeric" />
            </label>
            <label>
              Randomness
              <div className="inline-control">
                <input value={randomness} onChange={(event) => setRandomness(event.target.value)} inputMode="numeric" />
                <button type="button" onClick={randomize} disabled={busy !== null}>Random</button>
              </div>
            </label>
          </div>
          <div className="button-row">
            <button type="button" className="primary" onClick={prepareWithEnoki} disabled={!canUseConnectedDevice || setupBlocked}>
              Prepare Enoki nonce
            </button>
            <button type="button" onClick={prepare} disabled={!canUseConnectedDevice || setupBlocked}>
              Prepare local nonce
            </button>
          </div>
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
            Enoki API URL
            <input value={enokiApiUrl} onChange={(event) => setEnokiApiUrl(event.target.value)} spellCheck={false} />
          </label>
          <label>
            Enoki public API key
            <input value={enokiApiKey} onChange={(event) => setEnokiApiKey(event.target.value)} spellCheck={false} />
          </label>
          <div className="form-grid two">
            <label>
              Provider
              <select value={enokiProvider} onChange={(event) => selectEnokiProvider(event.target.value as EnokiAuthProvider)}>
                {ENOKI_PROVIDERS.map((entry) => (
                  <option key={entry} value={entry}>{entry}</option>
                ))}
              </select>
            </label>
            <label>
              Client ID
              <input value={oauthClientId} onChange={(event) => setOauthClientId(event.target.value)} />
            </label>
          </div>
          <button type="button" onClick={loadEnokiApp} disabled={busy !== null}>
            Load Enoki app
          </button>
          <label>
            Authorization URL
            <input value={oauthAuthorizeUrl} onChange={(event) => setOauthAuthorizeUrl(event.target.value)} placeholder="https://..." />
          </label>
          <label>
            Scope
            <input value={oauthScope} onChange={(event) => setOauthScope(event.target.value)} />
          </label>
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
          <dl className="facts compact">
            <div>
              <dt>Loaded providers</dt>
              <dd>{enokiAppProviders.length === 0 ? "none" : enokiAppProviders.map((entry) => entry.providerType).join(", ")}</dd>
            </div>
            <div>
              <dt>Continuity</dt>
              <dd>Enoki app, OAuth client ID, issuer, and subject</dd>
            </div>
          </dl>
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
          <button type="button" onClick={createProofWithEnoki} disabled={!canUseConnectedDevice || setupBlocked || preparation === null || jwt.trim().length === 0}>
            Create Enoki proof
          </button>
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
              <dd>{lastSignature === null ? "none" : signStatusLabel(lastSignature)}</dd>
            </div>
            <div>
              <dt>Signature</dt>
              <dd>{lastSignature?.source === "live" && lastSignature.status === "signed" ? short(lastSignature.signature) : "none"}</dd>
            </div>
          </dl>
        </section>
      </div>
    </main>
  );
}

function AccountView({ account }: { account: AgentQSuiWalletSuiAccount | null }) {
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
    return "zkLogin account metadata is active. Clear it locally in Settings > Sui before preparing new proof material.";
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

function resultSummary(value: unknown): string {
  if (!isRecord(value)) {
    return "invalid result";
  }
  const source = typeof value.source === "string" ? value.source : "unknown";
  const reason = typeof value.reason === "string" ? `/${value.reason}` : "";
  return `${source}${reason}`;
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
}): CredentialProposalInput {
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
