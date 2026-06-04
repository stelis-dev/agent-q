import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type GatewayCore, type DeviceListResult } from "@stelis/agent-q-client/admin";
import {
  GatewayError,
  gatewaySuccessOutputSchemas,
  isSafeDeviceId,
  toGatewayError,
  toPublicError,
} from "@stelis/agent-q-client/adapter-internal";

export const DEFAULT_ADMIN_HOST = "127.0.0.1";
export const DEFAULT_ADMIN_PORT = 8787;
const MAX_ADMIN_JSON_BYTES = 16384;
const ADMIN_LOOPBACK_HOSTS = new Set([DEFAULT_ADMIN_HOST, "localhost", "::1"]);

const SUI_NETWORKS = ["devnet", "testnet", "mainnet"] as const;
type SuiNetwork = (typeof SUI_NETWORKS)[number];

export type AdminGatewayCore = Pick<
  GatewayCore,
  | "listDevices"
  | "scanDevices"
  | "connectDevice"
  | "disconnectDevice"
  | "getPolicy"
  | "getApprovalHistory"
  | "proposePolicyUpdate"
>;

export interface StartedAdminGateway {
  server: Server;
  url: string;
}

interface RequestBody {
  [key: string]: unknown;
}

interface SuccessSchema {
  parse(raw: unknown): object;
}

export function createAdminHttpServer(core: AdminGatewayCore): Server {
  return createServer((request, response) => {
    void handleAdminRequest(core, request, response);
  });
}

export async function startAdminGateway(options: {
  core: AdminGatewayCore;
  host?: string;
  port?: number;
}): Promise<StartedAdminGateway> {
  const host = validateAdminHost(options.host ?? DEFAULT_ADMIN_HOST);
  const port = options.port ?? DEFAULT_ADMIN_PORT;
  const server = createAdminHttpServer(options.core);

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  return { server, url: `http://${formatAdminHostForUrl(host)}:${port}/` };
}

function validateAdminHost(host: string): string {
  if (!ADMIN_LOOPBACK_HOSTS.has(host)) {
    throw new GatewayError("invalid_params", "Admin host must be loopback-only.", false);
  }
  return host;
}

function formatAdminHostForUrl(host: string): string {
  return host.includes(":") ? `[${host}]` : host;
}

export function buildRejectOnlySuiPolicy(network: unknown): Record<string, unknown> {
  if (!isSuiNetwork(network)) {
    throw new GatewayError("invalid_params", "policy template network is invalid.", false);
  }
  return {
    schema: "agentq.policy.v0",
    defaultAction: "reject",
    rules: [
      {
        id: `reject-sui-${network}`,
        chain: "sui",
        method: "sign_transaction",
        action: "reject",
        criteria: [
          {
            field: "common.network",
            op: "eq",
            value: network,
          },
        ],
      },
    ],
  };
}

async function handleAdminRequest(
  core: AdminGatewayCore,
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
    validateAdminApiRequest(request);

    const body = await readJsonBody(request);
    switch (request.url) {
      case "/api/list_devices":
        expectKeys(body, []);
        sendSanitizedSuccess(response, gatewaySuccessOutputSchemas.listDevices, await core.listDevices());
        return;
      case "/api/scan_devices":
        expectKeys(body, []);
        sendSanitizedSuccess(response, gatewaySuccessOutputSchemas.scanDevices, await core.scanDevices());
        return;
      case "/api/connect":
        expectKeys(body, ["deviceId"]);
        sendSanitizedSuccess(
          response,
          gatewaySuccessOutputSchemas.connectDevice,
          await core.connectDevice(deviceScopedInput(body)),
        );
        return;
      case "/api/disconnect":
        expectKeys(body, ["deviceId"]);
        sendSanitizedSuccess(
          response,
          gatewaySuccessOutputSchemas.disconnectDevice,
          await core.disconnectDevice(deviceScopedInput(body)),
        );
        return;
      case "/api/get_policy":
        expectKeys(body, ["deviceId"]);
        sendSanitizedSuccess(
          response,
          gatewaySuccessOutputSchemas.getPolicy,
          await core.getPolicy(deviceScopedInput(body)),
        );
        return;
      case "/api/get_approval_history":
        expectKeys(body, ["deviceId"]);
        sendSanitizedSuccess(
          response,
          gatewaySuccessOutputSchemas.getApprovalHistory,
          await core.getApprovalHistory({ ...deviceScopedInput(body), limit: 4 }),
        );
        return;
      case "/api/policy_preview":
        expectKeys(body, ["network"]);
        sendJson(response, 200, { ok: true, result: { policy: buildRejectOnlySuiPolicy(body.network) } });
        return;
      case "/api/propose_reject_policy": {
        expectKeys(body, ["deviceId", "network"]);
        const policy = buildRejectOnlySuiPolicy(body.network);
        sendSanitizedSuccess(
          response,
          gatewaySuccessOutputSchemas.proposePolicyUpdate,
          await core.proposePolicyUpdate({
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
    const gatewayError = toGatewayError(error);
    sendJson(response, gatewayError.retryable ? 503 : 400, {
      ok: false,
      error: toPublicError(gatewayError.code, gatewayError.retryable),
    });
  }
}

function validateAdminApiRequest(request: IncomingMessage): void {
  const contentType = singleHeader(request, "content-type");
  if (!isJsonContentType(contentType)) {
    throw new GatewayError("invalid_params", "Admin API requests must use application/json.", false);
  }

  const fetchSite = singleHeader(request, "sec-fetch-site");
  if (fetchSite !== undefined && fetchSite !== "same-origin" && fetchSite !== "none") {
    throw new GatewayError("invalid_params", "Admin API requests must be same-origin.", false);
  }

  const origin = singleHeader(request, "origin");
  if (origin === undefined) {
    return;
  }
  const host = singleHeader(request, "host");
  if (host === undefined || !isSameOrigin(origin, host)) {
    throw new GatewayError("invalid_params", "Admin API requests must be same-origin.", false);
  }
}

function singleHeader(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new GatewayError("invalid_params", "Admin request header is invalid.", false);
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
    if (Buffer.byteLength(raw, "utf8") > MAX_ADMIN_JSON_BYTES) {
      throw new GatewayError("invalid_params", "Admin request body is too large.", false);
    }
  }
  if (raw.length === 0) {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new GatewayError("invalid_json", "Admin request body is not valid JSON.", false);
  }
  if (!isRecord(parsed) || Array.isArray(parsed)) {
    throw new GatewayError("invalid_params", "Admin request body must be a JSON object.", false);
  }
  return parsed;
}

function deviceScopedInput(body: RequestBody): { deviceId?: string } {
  if (!Object.prototype.hasOwnProperty.call(body, "deviceId")) {
    return {};
  }
  if (!isSafeDeviceId(body.deviceId)) {
    throw new GatewayError("invalid_device_id", "Admin request deviceId is invalid.", false);
  }
  return { deviceId: body.deviceId };
}

function expectKeys(body: RequestBody, allowedKeys: string[]): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(body)) {
    if (!allowed.has(key)) {
      throw new GatewayError("invalid_params", "Admin request includes an unsupported field.", false);
    }
  }
}

function isSuiNetwork(value: unknown): value is SuiNetwork {
  return typeof value === "string" && SUI_NETWORKS.includes(value as SuiNetwork);
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
        <p>Local device management through Gateway. Firmware owns approval and policy commit.</p>
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
      <div class="formGrid">
        <label class="field">
          <span>Sui network</span>
          <select id="networkSelect">
            <option value="devnet">devnet</option>
            <option value="testnet">testnet</option>
            <option value="mainnet">mainnet</option>
          </select>
        </label>
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
  networkSelect: document.getElementById("networkSelect"),
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
    const result = await api("/api/policy_preview", { network: el.networkSelect.value });
    show(el.proposalOutput, result.policy);
  } catch (error) {
    showError(el.proposalOutput, error);
  }
}

async function submitProposal() {
  setBusy(true);
  show(el.resultOutput, "Waiting for device-local approval.");
  try {
    const result = await api("/api/propose_reject_policy", {
      ...selectedDeviceInput(),
      network: el.networkSelect.value,
    });
    show(el.resultOutput, result);
    show(el.policyOutput, await api("/api/get_policy", selectedDeviceInput()));
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
el.policyButton.addEventListener("click", () => run("/api/get_policy", el.policyOutput));
el.historyButton.addEventListener("click", () => run("/api/get_approval_history", el.historyOutput));
el.proposalButton.addEventListener("click", submitProposal);
el.networkSelect.addEventListener("change", refreshProposalPreview);
el.deviceSelect.addEventListener("change", () => {
  state.selectedDeviceId = el.deviceSelect.value;
});

await refreshDevices();
await refreshProposalPreview();
`;
