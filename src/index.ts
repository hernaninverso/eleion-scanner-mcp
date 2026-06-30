#!/usr/bin/env node
/**
 * Eleion Scanner MCP server
 * -------------------------
 * Drive the Eleion security scanner from an AI agent: register one of your own
 * domains, prove ownership, queue a security scan, and read the findings
 * (severity, CVE, title, priority). Wraps the hosted Eleion Scanner API
 * (https://scanner-api.eleion.io).
 *
 * Tools:
 *   - scanner_register_target(target_url)            -> POST /v1/targets
 *   - scanner_verify_target(target_id)              -> POST /v1/targets/{id}/verify
 *   - scanner_start_scan(target_id, scan_profile?)  -> POST /v1/scans
 *   - scanner_get_scan_status(scan_id)              -> GET  /v1/scans/{id}
 *   - scanner_get_findings(scan_id)                 -> GET  /v1/scans/{id}/findings
 *
 * Auth: set SCANNER_API_KEY (a tenant API key from https://scan.eleion.io).
 * Note: you can only scan domains you have registered and verified ownership of.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const API_BASE = (process.env.SCANNER_API_BASE || "https://scanner-api.eleion.io").replace(/\/+$/, "");
const API_KEY = process.env.SCANNER_API_KEY || "";
const USER_AGENT = "eleion-scanner-mcp/0.1.0";
const TIMEOUT_MS = 25_000;
const PROFILES = ["basic", "full", "deep"];

// strict runtime arg validation (avoid Number()/String() coercion of null/objects)
function reqStr(v: unknown, max = 2048): string | null {
  return typeof v === "string" && v.trim().length > 0 && v.length <= max ? v.trim() : null;
}
function reqPosInt(v: unknown): number | null {
  if (typeof v === "number" && Number.isSafeInteger(v) && v > 0) return v;
  if (typeof v === "string" && /^[0-9]{1,15}$/.test(v)) {
    const n = Number(v);
    if (Number.isSafeInteger(n) && n > 0) return n;
  }
  return null;
}

function needKey(): string | null {
  if (API_KEY) return null;
  return "No API key configured. Set SCANNER_API_KEY (a tenant key from https://scan.eleion.io). You can only scan domains you have registered and verified.";
}

async function apiCall(method: string, path: string, body?: unknown): Promise<string> {
  const nk = needKey();
  if (nk) return nk;
  const headers: Record<string, string> = { Authorization: `Bearer ${API_KEY}`, "User-Agent": USER_AGENT };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (e) {
    const err = e as Error;
    if (err.name === "TimeoutError" || err.name === "AbortError") return `The scanner API did not respond within ${TIMEOUT_MS / 1000}s.`;
    return `Could not reach the scanner API at ${API_BASE}.`;
  }
  const text = await res.text();
  // Status-specific messages BEFORE attempting JSON (a gateway may return HTML).
  if (res.status === 401 || res.status === 403) return "Authentication failed: SCANNER_API_KEY is missing, invalid, or lacks the required scope.";
  if (res.status === 404) return "Not found (the target or scan id does not exist, or is not yours).";
  if (res.status === 429) return "Rate limit or quota reached. Try again later or check your plan.";
  let data: any;
  try {
    data = JSON.parse(text);
  } catch {
    return `The scanner API returned a non-JSON response (HTTP ${res.status}).`;
  }
  if (res.status < 200 || res.status >= 300) {
    const msg = data?.error?.message || data?.detail || data?.message || `HTTP ${res.status}`;
    return `Scanner request failed: ${String(msg).slice(0, 300)}`;
  }
  return JSON.stringify(data, null, 2);
}

const TOOLS = [
  {
    name: "scanner_register_target",
    description:
      "Register one of YOUR OWN domains/URLs to be security-scanned. Returns a verification_token plus the DNS TXT " +
      "record (or /.well-known URL) you must publish to prove ownership before scanning. You can only scan domains you own.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { target_url: { type: "string", description: "The http(s) URL/domain to register (must be a public host you control).", maxLength: 2048 } },
      required: ["target_url"],
    },
  },
  {
    name: "scanner_verify_target",
    description: "Verify domain ownership of a previously registered target by checking the DNS TXT / .well-known record you published. Returns whether verification succeeded.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { target_id: { type: "integer", minimum: 1, description: "The target id returned by scanner_register_target." } },
      required: ["target_id"],
    },
  },
  {
    name: "scanner_start_scan",
    description: "Queue a security scan over a target you have already registered AND verified. Returns a scan_id and status. Poll scanner_get_scan_status until completed, then read scanner_get_findings.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        target_id: { type: "integer", minimum: 1, description: "The verified target id." },
        scan_profile: { type: "string", enum: PROFILES, default: "basic", description: "Scan depth." },
      },
      required: ["target_id"],
    },
  },
  {
    name: "scanner_get_scan_status",
    description: "Get the status of a scan (queued|running|completed|failed) and how many findings it has.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { scan_id: { type: "string", description: "The scan id.", maxLength: 128 } },
      required: ["scan_id"],
    },
  },
  {
    name: "scanner_get_findings",
    description: "List the security findings of a completed scan (severity, CVE, template, title, URL, priority_score), ordered by priority.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { scan_id: { type: "string", description: "The scan id.", maxLength: 128 } },
      required: ["scan_id"],
    },
  },
];

const server = new Server({ name: "eleion-scanner", version: "0.1.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: rawArgs } = req.params;
  const a = (rawArgs ?? {}) as Record<string, unknown>;
  try {
    let text: string;
    if (name === "scanner_register_target") {
      const url = reqStr(a.target_url);
      text = url ? await apiCall("POST", "/v1/targets", { target_url: url }) : "target_url (non-empty string) is required.";
    } else if (name === "scanner_verify_target") {
      const id = reqPosInt(a.target_id);
      text = id ? await apiCall("POST", `/v1/targets/${id}/verify`) : "target_id (positive integer) is required.";
    } else if (name === "scanner_start_scan") {
      const id = reqPosInt(a.target_id);
      if (!id) text = "target_id (positive integer) is required.";
      else {
        let profile = reqStr(a.scan_profile, 16) ?? "basic";
        if (!PROFILES.includes(profile)) profile = "basic";
        text = await apiCall("POST", "/v1/scans", { target_id: id, scan_profile: profile });
      }
    } else if (name === "scanner_get_scan_status") {
      const id = reqStr(a.scan_id, 128);
      text = id ? await apiCall("GET", `/v1/scans/${encodeURIComponent(id)}`) : "scan_id (string) is required.";
    } else if (name === "scanner_get_findings") {
      const id = reqStr(a.scan_id, 128);
      text = id ? await apiCall("GET", `/v1/scans/${encodeURIComponent(id)}/findings`) : "scan_id (string) is required.";
    } else {
      return { isError: true, content: [{ type: "text", text: `Unknown tool: ${name}` }] };
    }
    return { content: [{ type: "text", text }] };
  } catch (e) {
    return { isError: true, content: [{ type: "text", text: `Tool ${name} failed: ${(e as Error).message}` }] };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("eleion-scanner MCP server running on stdio\n");
}

main().catch((e) => {
  process.stderr.write(`fatal: ${(e as Error).message}\n`);
  process.exit(1);
});
