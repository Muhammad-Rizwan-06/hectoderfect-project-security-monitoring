import assert from "node:assert/strict";
import { test } from "node:test";
import { createAuditReport, formatJsonReport, sha256Hex } from "../src/report.js";
import type { Advisory, DependencyNode } from "../src/types.js";

test("reports transitive package context and deduplicates same-source advisory records", () => {
  const node: DependencyNode = {
    lockfilePath: "node_modules/alpha/node_modules/beta",
    name: "beta",
    version: "2.0.0",
    direct: false,
    dependencyPath: ["alpha", "beta"],
  };
  const advisory: Advisory = {
    ecosystem: "npm",
    packageName: "beta",
    packageVersion: "2.0.0",
    id: "GHSA-test-1234",
    summary: "Test finding",
    details: "",
    severity: "HIGH",
    references: [],
    source: "OSV",
  };
  const report = createAuditReport("/fixture/package-lock.json", [node], [advisory, advisory], ["OSV"]);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0]?.direct, false);
  assert.deepEqual(report.findings[0]?.dependencyPath, ["alpha", "beta"]);
  assert.match(formatJsonReport(report), /"schemaVersion": 1/);
  assert.equal(sha256Hex("depguard"), "33dc419c4f962dc1ce413697750b369b98dea71434568ca69f2056afd1ef3866");
});
