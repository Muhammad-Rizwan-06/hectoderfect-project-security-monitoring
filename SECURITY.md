# Security policy

## Scope

DepGuard is an early-stage dependency audit tool. It reports known advisories returned by OSV and can mirror those records to Snowflake. It is not a malware detector and cannot establish that a dependency is safe.

## Reporting a vulnerability

Do not post credentials, private keys, or sensitive package data in public issues. Until a private reporting channel is configured, contact the repository maintainers directly and include a minimal reproduction, affected version, and impact.

## Handling credentials

Snowflake credentials and Solana keypairs must remain local. Keep `.env` and keypair files out of version control. The Devnet receipt stores only the report's SHA-256 digest; a blockchain transaction is public and permanent.
