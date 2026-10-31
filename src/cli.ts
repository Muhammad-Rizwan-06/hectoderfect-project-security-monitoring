#!/usr/bin/env node
import "dotenv/config";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { auditLockfile } from "./audit.js";
import { errorMessage } from "./lockfile.js";
import { formatJsonReport, formatTextReport, sha256Hex } from "./report.js";
import { ensureAdvisoryTable, saveAdvisories } from "./snowflake.js";
import { submitDevnetReceipt } from "./solana.js";
import { explainFindings } from "./gemma.js";

interface Arguments {
  command: string;
  lockfile: string;
  source: "osv" | "snowflake" | "both";
  format: "text" | "json";
  output?: string;
  receipt: boolean;
  explain: boolean;
}

function help(): string {
  return `DepGuard — npm dependency risk scanner

Usage:
  depguard scan [options]
  depguard sync [options]

Commands:
  scan     Check dependencies against the selected advisory sources.
  sync     Query OSV and upsert findings for this lockfile into Snowflake.

Options:
  --lockfile <path>       npm package-lock.json (default: package-lock.json)
  --source <source>       osv | snowflake | both (scan; default: osv)
  --format <format>       text | json (default: text)
  --out <path>            Write the report to a file as well as stdout.
  --receipt               Submit the report SHA-256 digest to Solana Devnet.
  --explain               Ask Gemma 4 to explain findings (requires GEMINI_API_KEY).
  -h, --help              Show this help.

Examples:
  depguard scan --lockfile package-lock.json
  depguard sync --lockfile package-lock.json
  depguard scan --source both --receipt`;
}

function parseArguments(argv: string[]): Arguments {
  const command = argv[0] ?? "";
  const args: Arguments = {
    command,
    lockfile: "package-lock.json",
    source: "osv",
    format: "text",
    receipt: false,
    explain: false,
  };
  for (let index = 1; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === "-h" || option === "--help") {
      args.command = "help";
      continue;
    }
    if (option === "--receipt") {
      args.receipt = true;
      continue;
    }
    if (option === "--explain") {
      args.explain = true;
      continue;
    }
    if (
      option === "--lockfile" ||
      option === "--source" ||
      option === "--format" ||
      option === "--out"
    ) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--"))
        throw new Error(`Expected a value after ${option}.`);
      index += 1;
      if (option === "--lockfile") args.lockfile = value;
      if (option === "--out") args.output = value;
      if (option === "--source") {
        if (value !== "osv" && value !== "snowflake" && value !== "both") {
          throw new Error("--source must be osv, snowflake, or both.");
        }
        args.source = value;
      }
      if (option === "--format") {
        if (value !== "text" && value !== "json")
          throw new Error("--format must be text or json.");
        args.format = value;
      }
      continue;
    }
    throw new Error(`Unknown option: ${option}`);
  }
  return args;
}

async function writeReport(
  path: string | undefined,
  contents: string,
  lockfile: string,
  receiptKeypairPath?: string,
): Promise<void> {
  if (!path) return;
  const absolutePath = resolve(path);
  if (absolutePath === resolve(lockfile)) {
    throw new Error("Report output must not overwrite the input lockfile.");
  }
  if (receiptKeypairPath && absolutePath === resolve(receiptKeypairPath)) {
    throw new Error("Report output must not overwrite the configured Solana keypair.");
  }
  await mkdir(dirname(absolutePath), { recursive: true });
  await writeFile(absolutePath, contents, "utf8");
  console.error(`Report saved to ${absolutePath}`);
}

async function main(argv: string[]): Promise<number> {
  if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") {
    console.log(help());
    return 0;
  }
  const args = parseArguments(argv);
  if (args.command === "help") {
    console.log(help());
    return 0;
  }
  if (args.command !== "scan" && args.command !== "sync") {
    throw new Error(`Unknown command "${args.command}". Use "scan" or "sync".`);
  }
  if (args.command === "sync" && args.receipt) {
    throw new Error(
      "Use scan --receipt to record a scan report; sync does not generate a report.",
    );
  }

  const useOsv =
    args.command === "sync" || args.source === "osv" || args.source === "both";
  const useSnowflake =
    args.command === "sync" ||
    args.source === "snowflake" ||
    args.source === "both";
  const { report, advisories } = await auditLockfile(args.lockfile, {
    osv: useOsv,
    snowflake: args.command === "sync" ? false : useSnowflake,
  });
  if (args.command === "sync") {
    await ensureAdvisoryTable();
    const saved = await saveAdvisories(advisories);
    console.log(
      `Synced ${saved} OSV advisory/package-version records to Snowflake.`,
    );
    console.log(
      `Snowflake scan table: ${process.env.SNOWFLAKE_TABLE || "PACKAGE_ADVISORIES"}`,
    );
  }

  if (args.explain) await explainFindings(report.findings);

  const formatted =
    args.format === "json"
      ? formatJsonReport(report)
      : formatTextReport(report);
  await writeReport(
    args.output,
    formatted,
    args.lockfile,
    args.receipt ? process.env.SOLANA_KEYPAIR_PATH : undefined,
  );
  process.stdout.write(formatted);

  if (args.receipt) {
    const receipt = await submitDevnetReceipt(sha256Hex(formatted));
    console.error(
      `Devnet receipt confirmed: ${receipt.signature}\n` +
        `Report SHA-256: ${receipt.reportSha256}\n` +
        `Explorer: ${receipt.explorerUrl}`,
    );
  }
  return report.findings.length > 0 ? 1 : 0;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    console.error(`depguard: ${errorMessage(error)}`);
    process.exitCode = 2;
  },
);
