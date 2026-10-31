import { readDependencyGraph } from "./lockfile.js";
import { queryOsv } from "./osv.js";
import { createAuditReport } from "./report.js";
import { queryAdvisories } from "./snowflake.js";
import type { Advisory, AuditReport } from "./types.js";

export interface AuditOptions {
  osv?: boolean;
  snowflake?: boolean;
}

export async function auditLockfile(
  lockfilePath: string,
  options: AuditOptions,
): Promise<{ report: AuditReport; advisories: Advisory[] }> {
  if (!options.osv && !options.snowflake) {
    throw new Error("Select at least one advisory source.");
  }
  const graph = await readDependencyGraph(lockfilePath);
  const advisories: Advisory[] = [];
  const sources: string[] = [];

  if (options.osv) {
    advisories.push(...(await queryOsv(graph.nodes)));
    sources.push("OSV");
  }
  if (options.snowflake) {
    advisories.push(
      ...(await queryAdvisories(
        graph.nodes.map(({ name, version }) => ({ name, version })),
      )),
    );
    sources.push("Snowflake (OSV mirror)");
  }

  return {
    report: createAuditReport(
      graph.lockfilePath,
      graph.nodes,
      advisories,
      sources,
    ),
    advisories,
  };
}
