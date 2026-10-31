import { createHash } from "node:crypto";
import type { Advisory, AuditReport, DependencyNode, Finding } from "./types.js";

export function createAuditReport(
  lockfilePath: string,
  nodes: DependencyNode[],
  advisories: Advisory[],
  sources: string[],
): AuditReport {
  const nodeByPackage = new Map<string, DependencyNode[]>();
  for (const node of nodes) {
    const key = `${node.name}\0${node.version}`;
    const entries = nodeByPackage.get(key) ?? [];
    entries.push(node);
    nodeByPackage.set(key, entries);
  }

  const findingsByInstance = new Map<string, Finding>();
  for (const advisory of advisories) {
    const key = `${advisory.packageName}\0${advisory.packageVersion}`;
    for (const node of nodeByPackage.get(key) ?? []) {
      const findingKey = `${node.lockfilePath}\0${advisory.id}`;
      const existing = findingsByInstance.get(findingKey);
      if (existing) {
        existing.sources = [...new Set([...existing.sources, advisory.source])].sort();
        continue;
      }
      findingsByInstance.set(findingKey, {
        ...advisory,
        direct: node.direct,
        dependencyPath: node.dependencyPath,
        lockfilePath: node.lockfilePath,
        sources: [advisory.source],
      });
    }
  }
  const findings = [...findingsByInstance.values()].sort(
    (left, right) =>
      left.packageName.localeCompare(right.packageName) ||
      left.packageVersion.localeCompare(right.packageVersion) ||
      left.id.localeCompare(right.id) ||
      left.lockfilePath.localeCompare(right.lockfilePath),
  );
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    lockfile: lockfilePath,
    dependencyCount: nodes.length,
    sources: [...new Set(sources)].sort(),
    findings,
  };
}

export function formatTextReport(report: AuditReport): string {
  const lines = [
    "DepGuard dependency audit",
    `Lockfile: ${report.lockfile}`,
    `Dependencies checked: ${report.dependencyCount}`,
    `Sources: ${report.sources.join(", ") || "none"}`,
    `Vulnerabilities found: ${report.findings.length}`,
    "",
  ];
  if (report.findings.length === 0) {
    lines.push("No known vulnerabilities were returned by the selected sources.");
  } else {
    for (const finding of report.findings) {
      lines.push(
        `[${finding.severity}] ${finding.packageName}@${finding.packageVersion} — ${finding.id}`,
        `  ${finding.summary}`,
        `  Dependency path: ${finding.dependencyPath.join(" > ")}`,
        `  Type: ${finding.direct ? "direct" : "transitive"}`,
        `  Source: ${finding.sources.join(", ")}`,
      );
      if (finding.explanation) {
        lines.push(`  Gemma explanation (AI-generated; verify against the cited advisory): ${finding.explanation}`);
      }
      if (finding.references[0]) lines.push(`  Reference: ${finding.references[0]}`);
      lines.push("");
    }
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export function formatJsonReport(report: AuditReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function sha256Hex(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}
