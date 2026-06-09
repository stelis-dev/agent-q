import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AgentQCore, type DeviceListResult } from "@stelis/agent-q-core";
import {
  AgentQError,
  hostSuccessOutputSchemas,
  isSafeDeviceId,
  isValidPurpose,
  toAgentQError,
  toPublicError,
} from "@stelis/agent-q-core/adapter-internal";

export const DEFAULT_LOCAL_API_HOST = "127.0.0.1";
export const DEFAULT_LOCAL_API_PORT = 8787;
const MAX_LOCAL_API_JSON_BYTES = 16384;
const LOCAL_API_LOOPBACK_HOSTS = new Set([DEFAULT_LOCAL_API_HOST, "localhost", "::1"]);

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

export function buildRejectOnlySuiPolicy(): Record<string, unknown> {
  return {
    schema: "agentq.policy.v0",
    defaultAction: "reject",
    rules: [],
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

    const body = await readJsonBody(request);
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
      case "/api/policy_preview":
        expectKeys(body, []);
        sendJson(response, 200, { ok: true, result: { policy: buildRejectOnlySuiPolicy() } });
        return;
      case "/api/policy_propose_reject": {
        expectKeys(body, ["deviceId", "purpose"]);
        const policy = buildRejectOnlySuiPolicy();
        sendSanitizedSuccess(
          response,
          hostSuccessOutputSchemas.policyPropose,
          await core.policyPropose({
            ...deviceScopedInput(body),
            policy,
          }),
        );
        return;
      }
      default:
        sendPublicError(response, 404, "unsupported_method", false);
    }
  } catch (error) {
    const agentQError = toAgentQError(error);
    sendJson(response, agentQError.retryable ? 503 : 400, {
      ok: false,
      error: toPublicError(agentQError.code, agentQError.retryable),
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

async function readJsonBody(request: IncomingMessage): Promise<RequestBody> {
  let raw = "";
  for await (const chunk of request) {
    raw += chunk;
    if (Buffer.byteLength(raw, "utf8") > MAX_LOCAL_API_JSON_BYTES) {
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
    throw new AgentQError("invalid_json", "Local API request body is not valid JSON.", false);
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
      throw new AgentQError("invalid_purpose", "Local API request purpose is invalid.", false);
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
        <h2>Active Policy</h2>
        <button id="policyButton" type="button">Load Policy</button>
      </div>
      <pre id="policyOutput" class="output"></pre>
    </section>

    <section class="band">
      <div class="sectionHeader">
        <h2>Reject Policy Proposal</h2>
        <button id="proposalButton" type="button">Submit Proposal</button>
      </div>
      <pre id="proposalOutput" class="output"></pre>
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
select {
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
  select {
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
  proposalButton: document.getElementById("proposalButton"),
  historyButton: document.getElementById("historyButton"),
  deviceSelect: document.getElementById("deviceSelect"),
  deviceOutput: document.getElementById("deviceOutput"),
  policyOutput: document.getElementById("policyOutput"),
  proposalOutput: document.getElementById("proposalOutput"),
  historyOutput: document.getElementById("historyOutput"),
  resultOutput: document.getElementById("resultOutput"),
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

function setBusy(isBusy) {
  for (const button of [
    el.refreshButton,
    el.scanButton,
    el.connectButton,
    el.disconnectButton,
    el.policyButton,
    el.proposalButton,
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

async function refreshProposalPreview() {
  try {
    const result = await api("/api/policy_preview");
    show(el.proposalOutput, result.policy);
  } catch (error) {
    showError(el.proposalOutput, error);
  }
}

async function submitProposal() {
  setBusy(true);
  show(el.resultOutput, "Waiting for device-local approval.");
  try {
    const result = await api("/api/policy_propose_reject", {
      ...selectedDeviceInput(),
    });
    show(el.resultOutput, result);
    show(el.policyOutput, await api("/api/policy_get", selectedDeviceInput()));
    show(el.historyOutput, await api("/api/get_approval_history", selectedDeviceInput()));
  } catch (error) {
    showError(el.resultOutput, error);
  } finally {
    setBusy(false);
  }
}

el.refreshButton.addEventListener("click", refreshDevices);
el.scanButton.addEventListener("click", scanDevices);
el.connectButton.addEventListener("click", () => run("/api/connect", el.resultOutput));
el.disconnectButton.addEventListener("click", () => run("/api/disconnect", el.resultOutput));
el.policyButton.addEventListener("click", () => run("/api/policy_get", el.policyOutput));
el.historyButton.addEventListener("click", () => run("/api/get_approval_history", el.historyOutput));
el.proposalButton.addEventListener("click", submitProposal);
el.deviceSelect.addEventListener("change", () => {
  state.selectedDeviceId = el.deviceSelect.value;
});

await refreshDevices();
await refreshProposalPreview();
`;
