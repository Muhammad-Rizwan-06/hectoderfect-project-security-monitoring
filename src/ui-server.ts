#!/usr/bin/env node
import "dotenv/config";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { auditLockfile } from "./audit.js";
import { explainFindings } from "./gemma.js";
import { errorMessage } from "./lockfile.js";
import { formatJsonReport, sha256Hex } from "./report.js";
import { getDevnetWalletStatus, submitDevnetReceipt, type SolanaReceipt } from "./solana.js";
import type { AuditReport } from "./types.js";

const HOST = "127.0.0.1";
const MAX_BODY_BYTES = 16 * 1024;
const webDirectory = resolve(fileURLToPath(new URL(".", import.meta.url)), "..", "web");
const assets = new Map([
  ["/", { file: "index.html", type: "text/html; charset=utf-8" }],
  ["/app.js", { file: "app.js", type: "text/javascript; charset=utf-8" }],
  ["/styles.css", { file: "styles.css", type: "text/css; charset=utf-8" }],
]);

interface ScanState {
  report: AuditReport;
  reportSha256: string;
}

function sendJson(response: ServerResponse, status: number, payload: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(payload));
}

function sendError(response: ServerResponse, status: number, message: string): void {
  sendJson(response, status, { error: message });
}

function setSecurityHeaders(response: ServerResponse): void {
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("x-frame-options", "DENY");
  response.setHeader(
    "content-security-policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; " +
      "font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  );
}

function validLocalHost(request: IncomingMessage, port: number): boolean {
  return request.headers.host === `${HOST}:${port}`;
}

function validLocalOrigin(request: IncomingMessage, port: number): boolean {
  return request.headers.origin === `http://${HOST}:${port}` && validLocalHost(request, port);
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
    throw new Error("Content-Type must be application/json.");
  }
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of request) {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += data.length;
    if (totalBytes > MAX_BODY_BYTES) throw new Error("Request body exceeds the allowed size.");
    chunks.push(data);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new Error("Request body must be valid JSON.");
  }
}

function objectBody(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Request body must be a JSON object.");
  }
  return value as Record<string, unknown>;
}

function configuredPort(): number {
  const rawPort = process.env.DEPGUARD_UI_PORT?.trim() || "4173";
  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("DEPGUARD_UI_PORT must be an integer from 1 to 65535.");
  }
  return port;
}

export function createDashboardServer(port: number) {
  let lastScan: ScanState | undefined;
  let lastReceipt: SolanaReceipt | undefined;

  return createServer(async (request, response) => {
    setSecurityHeaders(response);
    if (!validLocalHost(request, port)) {
      sendError(response, 403, "Dashboard accepts requests only through its local address.");
      return;
    }

    const requestUrl = new URL(request.url ?? "/", `http://${HOST}:${port}`);
    const pathname = requestUrl.pathname;

    if (request.method === "GET" && pathname === "/api/solana/status") {
      sendJson(response, 200, await getDevnetWalletStatus());
      return;
    }
    if (request.method === "GET" && pathname === "/api/config") {
      sendJson(response, 200, { defaultLockfile: resolve(process.cwd(), "package-lock.json") });
      return;
    }

    if (request.method === "GET" && assets.has(pathname)) {
      const asset = assets.get(pathname);
      if (!asset) {
        sendError(response, 404, "Not found.");
        return;
      }
      try {
        const content = await readFile(resolve(webDirectory, asset.file));
        response.writeHead(200, {
          "content-type": asset.type,
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        response.end(content);
      } catch (error) {
        sendError(response, 500, `Could not read dashboard asset: ${errorMessage(error)}`);
      }
      return;
    }

    if (request.method !== "POST") {
      sendError(response, 404, "Not found.");
      return;
    }
    if (!validLocalOrigin(request, port)) {
      sendError(response, 403, "POST requests must originate from this local dashboard.");
      return;
    }

    if (pathname === "/api/scan") {
      try {
        const body = objectBody(await readJsonBody(request));
        if (typeof body.lockfile !== "string" || body.lockfile.trim().length === 0 || body.lockfile.length > 2048) {
          throw new Error("Provide an absolute path to a package-lock.json file.");
        }
        const lockfilePath = body.lockfile.trim();
        if (!isAbsolute(lockfilePath) || extname(lockfilePath).toLowerCase() !== ".json" ||
            lockfilePath.split(/[\\/]/).at(-1)?.toLowerCase() !== "package-lock.json") {
          throw new Error("Lockfile path must be an absolute path to a package-lock.json file.");
        }
        if (body.explain !== undefined && typeof body.explain !== "boolean") {
          throw new Error("The explain option must be a boolean.");
        }

        const { report } = await auditLockfile(lockfilePath, { osv: true });
        if (body.explain) await explainFindings(report.findings);
        const formatted = formatJsonReport(report);
        lastScan = { report, reportSha256: sha256Hex(formatted) };
        lastReceipt = undefined;
        sendJson(response, 200, {
          report,
          reportSha256: lastScan.reportSha256,
        });
      } catch (error) {
        sendError(response, 400, errorMessage(error));
      }
      return;
    }

    if (pathname === "/api/solana/receipt") {
      try {
        const body = objectBody(await readJsonBody(request));
        if (typeof body.reportSha256 !== "string" || !/^[a-f0-9]{64}$/.test(body.reportSha256)) {
          throw new Error("Provide a valid SHA-256 report digest.");
        }
        if (!lastScan || body.reportSha256 !== lastScan.reportSha256) {
          throw new Error("Scan a lockfile first; receipts are limited to the latest report from this session.");
        }
        if (lastReceipt?.reportSha256 === body.reportSha256) {
          sendJson(response, 200, lastReceipt);
          return;
        }
        lastReceipt = await submitDevnetReceipt(body.reportSha256);
        sendJson(response, 200, lastReceipt);
      } catch (error) {
        sendError(response, 400, errorMessage(error));
      }
      return;
    }

    sendError(response, 404, "Not found.");
  });
}

function start(): void {
  const port = configuredPort();
  const server = createDashboardServer(port);
  server.on("error", (error: NodeJS.ErrnoException) => {
    console.error(`DepGuard dashboard failed: ${error.message}`);
    process.exitCode = 1;
  });
  server.listen(port, HOST, () => {
    console.log(`DepGuard Solana dashboard: http://${HOST}:${port}`);
    console.log("The dashboard is bound to loopback; do not expose it through a public proxy.");
  });
}

start();
