# DepGuard

DepGuard is a defensive npm dependency auditor. It reads npm lockfiles, follows the installed direct and transitive dependency graph, and checks exact package versions against the [OSV.dev](https://osv.dev/) vulnerability service. Optional integrations mirror findings into Snowflake and publish a SHA-256 report receipt to Solana Devnet.

> **Scope:** this first release detects known advisories returned by OSV. It is not malware analysis, does not prove a package is safe, and does not infer malicious intent from publishing behavior.

## Requirements

- Node.js 20.18 or later and npm.
- An npm project with `package-lock.json` generated using lockfile version 2 or 3.
- Network access to `api.osv.dev` for live OSV checks.
- Optional Google AI Studio Gemini API key with access to Gemma 4 for AI-generated explanations.
- Snowflake account, warehouse, database, schema, and credentials only for Snowflake commands.
- A locally stored Solana Devnet keypair and test SOL only when submitting a receipt.

## Install and run

```powershell
npm install
npm run build
npm test
npm start
```

For development from a checkout, use:

```powershell
npx tsx src/cli.ts scan --lockfile .\package-lock.json
npx tsx src/cli.ts scan --lockfile .\package-lock.json --format json --out .\reports\audit.json
```

The CLI returns exit code `1` when findings exist and `0` when the selected sources return none. Configuration, parsing, or service errors return `2`; errors are not converted into clean scans.

## Commands

```text
depguard scan [--lockfile <path>] [--source osv|snowflake|both]
              [--format text|json] [--out <path>] [--explain] [--receipt]
depguard sync [--lockfile <path>]
```

Examples:

```powershell
# Live query to OSV.dev
npx tsx src/cli.ts scan --lockfile .\package-lock.json

# Query the Snowflake mirror, populated by the sync command below
npx tsx src/cli.ts scan --source snowflake --lockfile .\package-lock.json

# Query OSV and Snowflake, combine duplicate matches, and save JSON
npx tsx src/cli.ts scan --source both --format json --out .\audit.json

# Query OSV and upsert findings for these exact package versions to Snowflake
npx tsx src/cli.ts sync --lockfile .\package-lock.json

# Explain returned advisories with Gemma 4
npx tsx src/cli.ts scan --explain

# Submit the SHA-256 digest of the formatted report to Solana Devnet
npx tsx src/cli.ts scan --format json --out .\audit.json --receipt
```

## Optional Gemma 4 explanations

`--explain` asks Google AI Studio's Gemini API to explain matched advisories in accessible language. It supports `gemma-4-31b-it` (default) and `gemma-4-26b-a4b-it`. Put your API key in a local `.env` file or set it in the current shell:

```powershell
$env:GEMINI_API_KEY = "your-key"
$env:GEMMA_MODEL = "gemma-4-31b-it"
npx tsx src/cli.ts scan --explain
```

The key is sent to Google in the API-key header and is not placed in the URL or report. Only advisory metadata needed to explain findings is sent; DepGuard does not send source files or the full lockfile. Explanations are labeled as AI-generated and are supplementary: verify technical conclusions and remediation against the linked advisory. Without `--explain`, scans do not call the model.

## Threat-data source and Snowflake

OSV is the live public advisory source. Each scan submits exact npm package names and versions to OSV's batch query API (`POST https://api.osv.dev/v1/querybatch`); it does not download the full OSV dataset.

`sync` creates the configured table if needed, queries OSV for the current lockfile's dependency set, then upserts the returned advisory/package-version matches into Snowflake. This is an auditable Snowflake mirror of the current project's findings—not a full OSV feed import. A Snowflake-only scan checks exact package/version pairs present in that table. Run `sync` again after changing the lockfile to refresh its records.

Create a Snowflake database, schema, and warehouse and provide a role permitted to create/query the target table. Set credentials in your local environment (or a local `.env`, which is git-ignored):

```text
SNOWFLAKE_ACCOUNT=<account identifier>
SNOWFLAKE_USER=<username>
SNOWFLAKE_PASSWORD=<password>
SNOWFLAKE_WAREHOUSE=<warehouse>
SNOWFLAKE_DATABASE=<database>
SNOWFLAKE_SCHEMA=PUBLIC
SNOWFLAKE_ROLE=<optional role>
SNOWFLAKE_TABLE=PACKAGE_ADVISORIES
```

PowerShell example for the current terminal:

```powershell
$env:SNOWFLAKE_ACCOUNT = "org-account.region"
$env:SNOWFLAKE_USER = "..."
$env:SNOWFLAKE_PASSWORD = "..."
$env:SNOWFLAKE_WAREHOUSE = "COMPUTE_WH"
$env:SNOWFLAKE_DATABASE = "DEPguard"
npx tsx src/cli.ts sync --lockfile .\package-lock.json
```

You can also copy `.env.example` to `.env` and fill it in locally. **Never commit credentials.** Identifiers are validated before being included in SQL; values are passed as binds.

## Solana Devnet report receipt

The optional receipt contains only the SHA-256 digest of the exact formatted report bytes. DepGuard submits it as a Memo Program instruction to **Devnet only**, and displays the confirmed transaction signature and Explorer URL. Dependency names, report contents, and credentials are not written on-chain.

Install the Solana CLI using the [official installation guide](https://solana.com/docs/intro/installation), configure Devnet, and create/fund a Devnet wallet yourself. Keep the keypair outside this repository:

```powershell
solana config set --url https://api.devnet.solana.com
solana-keygen new --outfile "$HOME\.config\solana\depguard-devnet.json"
solana airdrop 1
solana balance
$env:SOLANA_KEYPAIR_PATH = "$HOME\.config\solana\depguard-devnet.json"
npx tsx src/cli.ts scan --receipt
```

Do not share or commit the keypair or recovery phrase. Devnet SOL has no monetary value. The receipt is tamper-evident evidence of a report digest; it does not independently validate the scanner's findings.

## Report fields

Reports include the checked dependency count, selected sources, advisory ID, summary, available severity, affected exact version, direct/transitive classification, dependency path, reference links, and sources that returned the match. Missing severity is reported as `UNKNOWN`, never guessed.

## Development and test fixtures

```powershell
npm run check
```

Unit tests use a small lockfile with an intentionally nested dependency and mocked OSV responses. They do not make real OSV, Snowflake, or Solana requests. The mock is test data only and is not included in live scan results.

Copilot assisted with the initial project structure, implementation, and test scaffolding. The scanner sends only advisory metadata to Gemma when `--explain` is explicitly supplied; it does not upload project source files or the full lockfile.

## Current limitations

- Supports npm `package-lock.json` lockfile versions 2 and 3. Other ecosystems and lockfile formats are not scanned.
- OSV supplies known vulnerability matches; this release does not detect malicious code, typosquats, account takeovers, or suspicious publishing patterns.
- Snowflake stores exact matches synchronized from OSV for the selected lockfile, not the complete public OSV database.
- Solana writes a Devnet Memo receipt. It does not register with SAID or assert that SAID's records are on-chain.
- Snowflake stores exact matches synchronized from OSV for the selected lockfile, not the complete public OSV database; this release does not provide a CoCo-managed dataset pipeline.

## License

MIT. See [LICENSE](./LICENSE).
