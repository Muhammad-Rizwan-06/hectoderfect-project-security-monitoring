import type { Advisory, DependencyNode, OsvBatchResponse, OsvVulnerability } from "./types.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const BATCH_SIZE = 1000;
const REQUEST_TIMEOUT_MS = 20_000;

function normalizedSeverity(vulnerability: OsvVulnerability): string {
  const declared =
    vulnerability.database_specific?.severity ??
    vulnerability.ecosystem_specific?.severity;
  if (declared) return declared.toUpperCase();
  for (const entry of vulnerability.severity ?? []) {
    const score = Number(entry.score);
    if (Number.isFinite(score) && score >= 0 && score <= 10) {
      if (score >= 9) return "CRITICAL";
      if (score >= 7) return "HIGH";
      if (score >= 4) return "MEDIUM";
      return "LOW";
    }
  }
  return "UNKNOWN";
}

function advisoryFromOsv(
  vulnerability: OsvVulnerability,
  node: DependencyNode,
): Advisory {
  return {
    ecosystem: "npm",
    packageName: node.name,
    packageVersion: node.version,
    id: vulnerability.id,
    summary: vulnerability.summary?.trim() || "No advisory summary provided.",
    details: vulnerability.details?.trim() || "",
    severity: normalizedSeverity(vulnerability),
    references: (vulnerability.references ?? [])
      .map((reference) => reference.url)
      .filter((url): url is string => Boolean(url)),
    source: "OSV",
  };
}

async function postBatch(
  nodes: DependencyNode[],
  fetchImpl: typeof fetch,
): Promise<OsvBatchResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetchImpl(OSV_BATCH_URL, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        queries: nodes.map((node) => ({
          package: { ecosystem: "npm", name: node.name },
          version: node.version,
        })),
      }),
      signal: controller.signal,
    });
    if (!response.ok) {
      const body = (await response.text()).slice(0, 500);
      throw new Error(`OSV returned HTTP ${response.status}: ${body || response.statusText}`);
    }
    const payload: unknown = await response.json();
    if (
      typeof payload !== "object" ||
      payload === null ||
      !("results" in payload) ||
      !Array.isArray(payload.results) ||
      payload.results.length !== nodes.length
    ) {
      throw new Error("OSV returned an invalid batch response.");
    }
    return payload as OsvBatchResponse;
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error(`OSV request timed out after ${REQUEST_TIMEOUT_MS} ms.`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

export async function queryOsv(
  nodes: DependencyNode[],
  fetchImpl: typeof fetch = fetch,
): Promise<Advisory[]> {
  const unique = new Map<string, DependencyNode>();
  for (const node of nodes) unique.set(`${node.name}\0${node.version}`, node);
  const packages = [...unique.values()];
  const advisories: Advisory[] = [];

  for (let offset = 0; offset < packages.length; offset += BATCH_SIZE) {
    const batch = packages.slice(offset, offset + BATCH_SIZE);
    const response = await postBatch(batch, fetchImpl);
    for (const [index, result] of response.results.entries()) {
      const node = batch[index];
      if (!node) throw new Error("OSV batch response index did not match its request.");
      for (const vulnerability of result.vulns ?? []) {
        advisories.push(advisoryFromOsv(vulnerability, node));
      }
    }
  }
  return advisories;
}
