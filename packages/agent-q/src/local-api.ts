import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AgentQCore } from "@stelis/agent-q-core";
import {
  AgentQError,
  hostSuccessOutputSchemas,
  isSafeDeviceId,
  isValidPurpose,
  toPublicError,
  toPublicErrorFromUnknown,
} from "@stelis/agent-q-core/adapter-internal";
import {
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS,
} from "@stelis/agent-q-core/protocol";

export const DEFAULT_LOCAL_API_HOST = "127.0.0.1";
export const DEFAULT_LOCAL_API_PORT = 8787;
const MAX_LOCAL_API_JSON_BYTES = 16384;
const MAX_LOCAL_API_SIGN_TRANSACTION_JSON_BYTES =
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS + MAX_RAW_PROTOCOL_JSON_BYTES;
const LOCAL_API_LOOPBACK_HOSTS = new Set([DEFAULT_LOCAL_API_HOST, "localhost", "::1"]);
const SUI_TYPE_TAG = "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
const ONE_SUI_MIST = "1000000000";

export type LocalApiAgentQCore = Pick<
  AgentQCore,
  | "listDevices"
  | "scanDevices"
  | "connectDevice"
  | "disconnectDevice"
  | "getAccounts"
  | "policyGet"
  | "getApprovalHistory"
  | "policyPropose"
  | "signTransaction"
>;

export interface StartedLocalApiServer {
  server: Server;
  url: string;
}

interface RequestBody {
  [key: string]: unknown;
}

interface SuccessSchema {
  parse(raw: unknown): object;
}

export function createLocalApiHttpServer(core: LocalApiAgentQCore): Server {
  return createServer((request, response) => {
    void handleLocalApiRequest(core, request, response);
  });
}

export async function startLocalApiServer(options: {
  core: LocalApiAgentQCore;
  host?: string;
  port?: number;
}): Promise<StartedLocalApiServer> {
  const host = validateLocalApiHost(options.host ?? DEFAULT_LOCAL_API_HOST);
  const port = options.port ?? DEFAULT_LOCAL_API_PORT;
  const server = createLocalApiHttpServer(options.core);

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  return { server, url: `http://${formatLocalApiHostForUrl(host)}:${port}/` };
}

function validateLocalApiHost(host: string): string {
  if (!LOCAL_API_LOOPBACK_HOSTS.has(host)) {
    throw new AgentQError("invalid_params", "Local API host must be loopback-only.", false);
  }
  return host;
}

function formatLocalApiHostForUrl(host: string): string {
  return host.includes(":") ? `[${host}]` : host;
}

export function buildMinimalSuiTestnetPolicy(): Record<string, unknown> {
  return {
    schema: "agentq.policy",
    defaultAction: "reject",
    blockchains: [
      {
        blockchain: "sui",
        networks: [
          {
            network: "testnet",
            policies: [
              {
                id: "sign-testnet-sui-up-to-one",
                action: "sign",
                conditions: [
                  { field: "sui.token_sources.source", op: "eq", value: "gas_coin" },
                  {
                    field: "sui.token_totals_by_type.amount_raw",
                    where: { type: SUI_TYPE_TAG },
                    op: "lte",
                    value: ONE_SUI_MIST,
                  },
                  { field: "sui.token_unknown_amount_present", op: "eq", value: "false" },
                ],
              },
            ],
          },
        ],
      },
    ],
  };
}

async function handleLocalApiRequest(
  core: LocalApiAgentQCore,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  try {
    if (request.method === "GET" && request.url === "/") {
      sendText(response, 200, "text/html; charset=utf-8", ADMIN_HTML);
      return;
    }
    if (request.method === "GET" && request.url === "/admin.css") {
      sendText(response, 200, "text/css; charset=utf-8", ADMIN_CSS);
      return;
    }
    if (request.method === "GET" && request.url === "/admin.js") {
      sendText(response, 200, "text/javascript; charset=utf-8", ADMIN_JS);
      return;
    }
    if (!request.url?.startsWith("/api/")) {
      sendPublicError(response, 404, "unsupported_method", false);
      return;
    }
    if (request.method !== "POST") {
      sendPublicError(response, 405, "unsupported_method", false);
      return;
    }
    validateLocalApiRequest(request);

    const body = await readJsonBody(request, localApiJsonBodyLimit(request.url));
    switch (request.url) {
      case "/api/list_devices":
        expectKeys(body, []);
        sendSanitizedSuccess(response, hostSuccessOutputSchemas.listDevices, await core.listDevices());
        return;
      case "/api/scan_devices":
        expectKeys(body, []);
        sendSanitizedSuccess(response, hostSuccessOutputSchemas.scanDevices, await core.scanDevices());
        return;
      case "/api/connect":
        expectKeys(body, ["deviceId", "purpose"]);
        sendSanitizedSuccess(
          response,
          hostSuccessOutputSchemas.connectDevice,
          await core.connectDevice(deviceScopedInput(body)),
        );
        return;
      case "/api/disconnect":
        expectKeys(body, ["deviceId", "purpose"]);
        sendSanitizedSuccess(
          response,
          hostSuccessOutputSchemas.disconnectDevice,
          await core.disconnectDevice(deviceScopedInput(body)),
        );
        return;
      case "/api/get_accounts":
        expectKeys(body, ["deviceId", "purpose"]);
        sendSanitizedSuccess(
          response,
          hostSuccessOutputSchemas.getAccounts,
          await core.getAccounts(deviceScopedInput(body)),
        );
        return;
      case "/api/sign_transaction":
        expectKeys(body, ["deviceId", "purpose", "chain", "method", "network", "txBytes"]);
        sendSanitizedSuccess(
          response,
          hostSuccessOutputSchemas.signTransaction,
          await core.signTransaction(signTransactionInput(body)),
        );
        return;
      case "/api/policy_get":
        expectKeys(body, ["deviceId", "purpose"]);
        sendSanitizedSuccess(
          response,
          hostSuccessOutputSchemas.policyGet,
          await core.policyGet(deviceScopedInput(body)),
        );
        return;
      case "/api/get_approval_history":
        expectKeys(body, ["deviceId", "purpose"]);
        sendSanitizedSuccess(
          response,
          hostSuccessOutputSchemas.getApprovalHistory,
          await core.getApprovalHistory({ ...deviceScopedInput(body), limit: 4 }),
        );
        return;
      case "/api/policy_template_minimal_sui_testnet":
        expectKeys(body, []);
        sendJson(response, 200, { ok: true, result: { policy: buildMinimalSuiTestnetPolicy() } });
        return;
      case "/api/policy_propose": {
        expectKeys(body, ["deviceId", "purpose", "policy"]);
        const { deviceId, purpose, policy } = policyProposalInput(body);
        sendSanitizedSuccess(
          response,
          hostSuccessOutputSchemas.policyPropose,
          await core.policyPropose({ deviceId, purpose, policy }),
        );
        return;
      }
      default:
        sendPublicError(response, 404, "unsupported_method", false);
    }
  } catch (error) {
    const publicError = toPublicErrorFromUnknown(error);
    sendJson(response, publicError.retryable ? 503 : 400, {
      ok: false,
      error: publicError,
    });
  }
}

function validateLocalApiRequest(request: IncomingMessage): void {
  const contentType = singleHeader(request, "content-type");
  if (!isJsonContentType(contentType)) {
    throw new AgentQError("invalid_params", "Local API requests must use application/json.", false);
  }

  const fetchSite = singleHeader(request, "sec-fetch-site");
  if (fetchSite !== undefined && fetchSite !== "same-origin" && fetchSite !== "none") {
    throw new AgentQError("invalid_params", "Local API requests must be same-origin.", false);
  }

  const origin = singleHeader(request, "origin");
  if (origin === undefined) {
    return;
  }
  const host = singleHeader(request, "host");
  if (host === undefined || !isSameOrigin(origin, host)) {
    throw new AgentQError("invalid_params", "Local API requests must be same-origin.", false);
  }
}

function singleHeader(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new AgentQError("invalid_params", "Local API request header is invalid.", false);
  }
  return value;
}

function isJsonContentType(contentType: string | undefined): boolean {
  return contentType?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

function isSameOrigin(origin: string, host: string): boolean {
  try {
    const url = new URL(origin);
    return url.protocol === "http:" && url.host === host;
  } catch {
    return false;
  }
}

function localApiJsonBodyLimit(url: string | undefined): number {
  return url === "/api/sign_transaction"
    ? MAX_LOCAL_API_SIGN_TRANSACTION_JSON_BYTES
    : MAX_LOCAL_API_JSON_BYTES;
}

async function readJsonBody(request: IncomingMessage, maxBytes: number): Promise<RequestBody> {
  let raw = "";
  for await (const chunk of request) {
    raw += chunk;
    if (Buffer.byteLength(raw, "utf8") > maxBytes) {
      throw new AgentQError("invalid_params", "Local API request body is too large.", false);
    }
  }
  if (raw.length === 0) {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AgentQError("invalid_request", "Local API request body is not valid JSON.", false);
  }
  if (!isRecord(parsed) || Array.isArray(parsed)) {
    throw new AgentQError("invalid_params", "Local API request body must be a JSON object.", false);
  }
  return parsed;
}

function deviceScopedInput(body: RequestBody): { deviceId?: string; purpose?: string } {
  const input: { deviceId?: string; purpose?: string } = {};
  if (Object.prototype.hasOwnProperty.call(body, "deviceId")) {
    if (!isSafeDeviceId(body.deviceId)) {
      throw new AgentQError("invalid_device_id", "Local API request deviceId is invalid.", false);
    }
    input.deviceId = body.deviceId;
  }
  if (Object.prototype.hasOwnProperty.call(body, "purpose")) {
    if (typeof body.purpose !== "string" || !isValidPurpose(body.purpose)) {
      throw new AgentQError("invalid_params", "Local API request purpose is invalid.", false);
    }
    input.purpose = body.purpose;
  }
  return input;
}

function signTransactionInput(body: RequestBody): {
  deviceId?: string;
  purpose?: string;
  chain: string;
  method: string;
  network: unknown;
  txBytes: string;
} {
  return {
    ...deviceScopedInput(body),
    chain: requiredString(body, "chain"),
    method: requiredString(body, "method"),
    network: body.network,
    txBytes: requiredString(body, "txBytes"),
  };
}

function policyProposalInput(body: RequestBody): {
  deviceId?: string;
  purpose?: string;
  policy: Record<string, unknown>;
} {
  const policy = body.policy;
  if (!isRecord(policy) || Array.isArray(policy)) {
    throw new AgentQError("invalid_params", "Local API policy proposal must be a JSON object.", false);
  }
  return {
    ...deviceScopedInput(body),
    policy,
  };
}

function requiredString(body: RequestBody, key: string): string {
  const value = body[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new AgentQError("invalid_params", "Local API request field is invalid.", false);
  }
  return value;
}

function expectKeys(body: RequestBody, allowedKeys: string[]): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(body)) {
    if (!allowed.has(key)) {
      throw new AgentQError("invalid_params", "Local API request includes an unsupported field.", false);
    }
  }
}

function isRecord(value: unknown): value is RequestBody {
  return typeof value === "object" && value !== null;
}

function sendPublicError(response: ServerResponse, statusCode: number, code: string, retryable: boolean): void {
  sendJson(response, statusCode, { ok: false, error: toPublicError(code, retryable) });
}

function sendSanitizedSuccess(response: ServerResponse, schema: SuccessSchema, raw: unknown): void {
  let result: object;
  try {
    result = schema.parse(raw);
  } catch {
    sendPublicError(response, 500, "internal_output_error", false);
    return;
  }
  sendJson(response, 200, { ok: true, result });
}

function sendJson(response: ServerResponse, statusCode: number, body: unknown): void {
  sendText(response, statusCode, "application/json; charset=utf-8", `${JSON.stringify(body)}\n`);
}

function sendText(response: ServerResponse, statusCode: number, contentType: string, body: string): void {
  response.writeHead(statusCode, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(body);
}

const ADMIN_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent-Q Admin</title>
  <link rel="stylesheet" href="/admin.css">
</head>
<body>
  <main class="layout">
    <header class="topbar">
      <div>
        <h1>Agent-Q Admin</h1>
        <p>Local device management through Agent-Q. Firmware owns approval and policy commit.</p>
      </div>
      <button id="refreshButton" type="button">Refresh</button>
    </header>

    <section class="band">
      <div class="sectionHeader">
        <h2>Device</h2>
        <div class="actions">
          <button id="scanButton" type="button">Scan</button>
          <button id="connectButton" type="button">Connect</button>
          <button id="disconnectButton" type="button">Disconnect</button>
        </div>
      </div>
      <label class="field">
        <span>Selected device</span>
        <select id="deviceSelect"></select>
      </label>
      <pre id="deviceOutput" class="output"></pre>
    </section>

    <section class="band">
      <div class="sectionHeader">
        <h2>Policy</h2>
        <div class="actions">
          <button id="policyButton" type="button">Load Active</button>
          <button id="minimalPolicyButton" type="button">Use Minimal Test Policy</button>
          <button id="submitPolicyButton" type="button">Submit Editor Policy</button>
        </div>
      </div>
      <p>
        Admin submits policy proposals only. Firmware validates, reviews, commits,
        and later evaluates policy-mode signing requests.
      </p>
      <textarea id="policyEditor" class="editor" spellcheck="false"></textarea>
      <pre id="policyOutput" class="output"></pre>
    </section>

    <section class="band">
      <div class="sectionHeader">
        <h2>Approval History</h2>
        <button id="historyButton" type="button">Load History</button>
      </div>
      <pre id="historyOutput" class="output"></pre>
    </section>

    <section class="band">
      <h2>Result</h2>
      <pre id="resultOutput" class="output"></pre>
    </section>
  </main>
  <div id="policySaveOverlay" class="statusOverlay" role="status" aria-live="polite" hidden>
    <div class="statusCard">
      <div class="spinner" aria-hidden="true"></div>
      <h2>Saving policy</h2>
      <p id="policySaveOverlayText">Waiting for device-local approval.</p>
    </div>
  </div>
  <script src="/admin.js" type="module"></script>
</body>
</html>
`;

const ADMIN_CSS = `:root {
  color-scheme: light;
  --bg: #f6f7f8;
  --text: #111827;
  --muted: #5b6472;
  --line: #d7dce2;
  --panel: #ffffff;
  --accent: #0f766e;
  --accentText: #ffffff;
  --danger: #b42318;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
}

.layout {
  width: min(1120px, calc(100% - 32px));
  margin: 0 auto;
  padding: 24px 0 40px;
  display: grid;
  gap: 16px;
}

.topbar,
.sectionHeader,
.actions,
.formGrid {
  display: flex;
  align-items: center;
  gap: 12px;
}

.topbar,
.sectionHeader {
  justify-content: space-between;
}

h1,
h2,
p {
  margin: 0;
}

h1 {
  font-size: 28px;
  line-height: 1.2;
}

h2 {
  font-size: 16px;
  line-height: 1.4;
}

p,
.field span {
  color: var(--muted);
}

.band {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 16px;
  display: grid;
  gap: 12px;
}

button,
select,
textarea {
  border: 1px solid var(--line);
  border-radius: 6px;
  min-height: 36px;
  padding: 0 12px;
  font: inherit;
  background: #ffffff;
  color: var(--text);
}

button {
  background: var(--accent);
  border-color: var(--accent);
  color: var(--accentText);
  cursor: pointer;
}

button:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.editor {
  width: 100%;
  min-height: 280px;
  padding: 12px;
  resize: vertical;
  background: #ffffff;
  color: var(--text);
  font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

.field {
  display: grid;
  gap: 6px;
}

.formGrid {
  justify-content: flex-start;
}

.output {
  min-height: 72px;
  max-height: 260px;
  overflow: auto;
  margin: 0;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #0f172a;
  color: #e5edf6;
  font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  white-space: pre-wrap;
}

.statusOverlay[hidden] {
  display: none;
}

.statusOverlay {
  position: fixed;
  inset: 0;
  z-index: 20;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgb(15 23 42 / 0.42);
}

.statusCard {
  width: min(360px, 100%);
  padding: 24px;
  border: 1px solid var(--line);
  border-radius: 10px;
  background: var(--panel);
  box-shadow: 0 18px 40px rgb(15 23 42 / 0.22);
  display: grid;
  justify-items: center;
  gap: 12px;
  text-align: center;
}

.spinner {
  width: 34px;
  height: 34px;
  border: 4px solid var(--line);
  border-top-color: var(--accent);
  border-radius: 999px;
  animation: spin 900ms linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.error {
  color: var(--danger);
}

@media (max-width: 720px) {
  .topbar,
  .sectionHeader,
  .actions,
  .formGrid {
    align-items: stretch;
    flex-direction: column;
  }

  button,
  select,
  textarea {
    width: 100%;
  }
}
`;

const ADMIN_JS = `const state = {
  devices: [],
  selectedDeviceId: "",
};

const el = {
  refreshButton: document.getElementById("refreshButton"),
  scanButton: document.getElementById("scanButton"),
  connectButton: document.getElementById("connectButton"),
  disconnectButton: document.getElementById("disconnectButton"),
  policyButton: document.getElementById("policyButton"),
  minimalPolicyButton: document.getElementById("minimalPolicyButton"),
  submitPolicyButton: document.getElementById("submitPolicyButton"),
  historyButton: document.getElementById("historyButton"),
  deviceSelect: document.getElementById("deviceSelect"),
  deviceOutput: document.getElementById("deviceOutput"),
  policyEditor: document.getElementById("policyEditor"),
  policyOutput: document.getElementById("policyOutput"),
  historyOutput: document.getElementById("historyOutput"),
  resultOutput: document.getElementById("resultOutput"),
  policySaveOverlay: document.getElementById("policySaveOverlay"),
  policySaveOverlayText: document.getElementById("policySaveOverlayText"),
};

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function selectedDeviceInput() {
  return state.selectedDeviceId ? { deviceId: state.selectedDeviceId } : {};
}

async function api(path, body = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!payload.ok) {
    throw payload.error;
  }
  return payload.result;
}

function show(target, value) {
  target.classList.remove("error");
  target.textContent = typeof value === "string" ? value : pretty(value);
}

function showError(target, error) {
  target.classList.add("error");
  target.textContent = pretty(error);
}

function showPolicySaveOverlay(message) {
  el.policySaveOverlayText.textContent = message;
  el.policySaveOverlay.hidden = false;
}

function hidePolicySaveOverlay() {
  el.policySaveOverlay.hidden = true;
}

function setBusy(isBusy) {
  for (const button of [
    el.refreshButton,
    el.scanButton,
    el.connectButton,
    el.disconnectButton,
    el.policyButton,
    el.minimalPolicyButton,
    el.submitPolicyButton,
    el.historyButton,
  ]) {
    button.disabled = isBusy;
  }
}

function renderDevices(result) {
  const devices = result.devices ?? [];
  state.devices = devices;
  const current = state.selectedDeviceId || result.activeDeviceId || devices[0]?.deviceId || "";
  state.selectedDeviceId = current;
  el.deviceSelect.innerHTML = "";
  for (const device of devices) {
    const option = document.createElement("option");
    option.value = device.deviceId;
    option.textContent = device.label ? device.label + " (" + device.deviceId + ")" : device.deviceId;
    option.selected = device.deviceId === current;
    el.deviceSelect.appendChild(option);
  }
  if (devices.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No known devices";
    el.deviceSelect.appendChild(option);
  }
  show(el.deviceOutput, result);
}

async function refreshDevices() {
  setBusy(true);
  try {
    renderDevices(await api("/api/list_devices"));
  } catch (error) {
    showError(el.resultOutput, error);
  } finally {
    setBusy(false);
  }
}

async function scanDevices() {
  setBusy(true);
  try {
    show(el.resultOutput, await api("/api/scan_devices"));
    renderDevices(await api("/api/list_devices"));
  } catch (error) {
    showError(el.resultOutput, error);
  } finally {
    setBusy(false);
  }
}

async function run(path, target, body = selectedDeviceInput()) {
  setBusy(true);
  try {
    show(target, await api(path, body));
  } catch (error) {
    showError(target, error);
  } finally {
    setBusy(false);
  }
}

function setPolicyEditor(policy) {
  el.policyEditor.value = pretty(policy);
}

function parsePolicyEditor() {
  try {
    return JSON.parse(el.policyEditor.value);
  } catch (error) {
    throw {
      code: "invalid_request",
      message: error instanceof Error ? error.message : "Policy editor JSON is invalid.",
      retryable: false,
    };
  }
}

async function loadActivePolicy() {
  setBusy(true);
  try {
    const result = await api("/api/policy_get", selectedDeviceInput());
    setPolicyEditor(result.policy);
    show(el.policyOutput, result);
  } catch (error) {
    showError(el.policyOutput, error);
  } finally {
    setBusy(false);
  }
}

async function loadPolicyTemplate(path) {
  try {
    const result = await api(path);
    setPolicyEditor(result.policy);
    show(el.policyOutput, { templateLoaded: true, policy: result.policy });
  } catch (error) {
    showError(el.policyOutput, error);
  }
}

async function submitEditorPolicy() {
  setBusy(true);
  showPolicySaveOverlay("Parsing policy JSON.");
  let busy = true;
  const clearBusy = () => {
    if (busy) {
      setBusy(false);
      busy = false;
    }
  };
  try {
    const policy = parsePolicyEditor();
    showPolicySaveOverlay("Waiting for device-local approval.");
    const result = await api("/api/policy_propose", {
      ...selectedDeviceInput(),
      policy,
    });
    showPolicySaveOverlay("Refreshing active policy.");
    const active = await api("/api/policy_get", selectedDeviceInput());
    showPolicySaveOverlay("Updating approval history.");
    const history = await api("/api/get_approval_history", selectedDeviceInput());
    setPolicyEditor(active.policy);
    show(el.policyOutput, active);
    show(el.historyOutput, history);
    show(el.resultOutput, result);
    hidePolicySaveOverlay();
  } catch (error) {
    hidePolicySaveOverlay();
    showError(el.resultOutput, error);
  } finally {
    clearBusy();
  }
}

el.refreshButton.addEventListener("click", refreshDevices);
el.scanButton.addEventListener("click", scanDevices);
el.connectButton.addEventListener("click", () => run("/api/connect", el.resultOutput));
el.disconnectButton.addEventListener("click", () => run("/api/disconnect", el.resultOutput));
el.policyButton.addEventListener("click", loadActivePolicy);
el.historyButton.addEventListener("click", () => run("/api/get_approval_history", el.historyOutput));
el.minimalPolicyButton.addEventListener("click", () => loadPolicyTemplate("/api/policy_template_minimal_sui_testnet"));
el.submitPolicyButton.addEventListener("click", submitEditorPolicy);
el.deviceSelect.addEventListener("change", () => {
  state.selectedDeviceId = el.deviceSelect.value;
});

await refreshDevices();
await loadPolicyTemplate("/api/policy_template_minimal_sui_testnet");
`;
