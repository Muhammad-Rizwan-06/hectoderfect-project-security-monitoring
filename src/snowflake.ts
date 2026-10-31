import snowflake from "snowflake-sdk";
import type { Advisory } from "./types.js";

interface SnowflakeRow {
  ECOSYSTEM: string;
  PACKAGE_NAME: string;
  PACKAGE_VERSION: string;
  ADVISORY_ID: string;
  SUMMARY: string;
  SEVERITY: string;
  REFERENCE_URL: string;
  SOURCE_URL: string;
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required Snowflake environment variable: ${name}`);
  return value;
}

function identifier(value: string, label: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_$]*$/.test(value)) {
    throw new Error(`${label} must be a simple Snowflake identifier (letters, digits, "_", "$").`);
  }
  return `"${value.toUpperCase()}"`;
}

function tableName(): string {
  const configured = process.env.SNOWFLAKE_TABLE?.trim() || "PACKAGE_ADVISORIES";
  const parts = configured.split(".");
  const database = process.env.SNOWFLAKE_DATABASE?.trim();
  const schema = process.env.SNOWFLAKE_SCHEMA?.trim() || "PUBLIC";
  if (parts.length === 1) {
    if (!database) throw new Error("Set SNOWFLAKE_DATABASE when SNOWFLAKE_TABLE is not fully qualified.");
    return [identifier(database, "SNOWFLAKE_DATABASE"), identifier(schema, "SNOWFLAKE_SCHEMA"), identifier(parts[0] ?? "", "SNOWFLAKE_TABLE")].join(".");
  }
  if (parts.length === 2) {
    if (!database) throw new Error("Set SNOWFLAKE_DATABASE when SNOWFLAKE_TABLE has two parts.");
    return [identifier(database, "SNOWFLAKE_DATABASE"), identifier(parts[0] ?? "", "SNOWFLAKE_TABLE schema"), identifier(parts[1] ?? "", "SNOWFLAKE_TABLE name")].join(".");
  }
  if (parts.length === 3) {
    return parts.map((part, index) => identifier(part, `SNOWFLAKE_TABLE part ${index + 1}`)).join(".");
  }
  throw new Error("SNOWFLAKE_TABLE must be TABLE, SCHEMA.TABLE, or DATABASE.SCHEMA.TABLE.");
}

function connectionOptions(): snowflake.ConnectionOptions {
  const options: snowflake.ConnectionOptions = {
    account: requiredEnv("SNOWFLAKE_ACCOUNT"),
    username: requiredEnv("SNOWFLAKE_USER"),
    password: requiredEnv("SNOWFLAKE_PASSWORD"),
    warehouse: requiredEnv("SNOWFLAKE_WAREHOUSE"),
    database: requiredEnv("SNOWFLAKE_DATABASE"),
    schema: process.env.SNOWFLAKE_SCHEMA?.trim() || "PUBLIC",
  };
  if (process.env.SNOWFLAKE_ROLE?.trim()) options.role = process.env.SNOWFLAKE_ROLE.trim();
  return options;
}

function connect(): Promise<snowflake.Connection> {
  const connection = snowflake.createConnection(connectionOptions());
  return new Promise((resolve, reject) => {
    connection.connect((error) => {
      if (error) reject(new Error(`Could not connect to Snowflake: ${error.message}`));
      else resolve(connection);
    });
  });
}

function execute<T>(
  connection: snowflake.Connection,
  sqlText: string,
  binds: snowflake.Bind[] = [],
): Promise<T[]> {
  return new Promise((resolve, reject) => {
    connection.execute({
      sqlText,
      binds,
      complete: (error, _statement, rows) => {
        if (error) reject(new Error(`Snowflake query failed: ${error.message}`));
        else resolve((rows ?? []) as T[]);
      },
    });
  });
}

async function close(connection: snowflake.Connection): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    connection.destroy((error) => {
      if (error) reject(new Error(`Could not close the Snowflake connection: ${error.message}`));
      else resolve();
    });
  });
}

async function withConnection<T>(operation: (connection: snowflake.Connection) => Promise<T>): Promise<T> {
  const connection = await connect();
  let operationError: unknown;
  try {
    return await operation(connection);
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      await close(connection);
    } catch (closeError) {
      if (!operationError) throw closeError;
    }
  }
}

export async function ensureAdvisoryTable(): Promise<string> {
  const table = tableName();
  await withConnection(async (connection) => {
    await execute(
      connection,
      `CREATE TABLE IF NOT EXISTS ${table} (
        ECOSYSTEM VARCHAR NOT NULL,
        PACKAGE_NAME VARCHAR NOT NULL,
        PACKAGE_VERSION VARCHAR NOT NULL,
        ADVISORY_ID VARCHAR NOT NULL,
        SUMMARY VARCHAR,
        SEVERITY VARCHAR,
        REFERENCE_URL VARCHAR,
        SOURCE_URL VARCHAR,
        SCANNED_AT TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
        CONSTRAINT PK_PACKAGE_ADVISORIES PRIMARY KEY
          (ECOSYSTEM, PACKAGE_NAME, PACKAGE_VERSION, ADVISORY_ID)
      )`,
    );
  });
  return table;
}

export async function saveAdvisories(advisories: Advisory[]): Promise<number> {
  const table = tableName();
  const unique = new Map<string, Advisory>();
  for (const advisory of advisories) {
    unique.set(
      `${advisory.ecosystem}\0${advisory.packageName}\0${advisory.packageVersion}\0${advisory.id}`,
      advisory,
    );
  }
  const rows = [...unique.values()];
  if (rows.length === 0) return 0;

  await withConnection(async (connection) => {
    for (let offset = 0; offset < rows.length; offset += 100) {
      const batch = rows.slice(offset, offset + 100);
      const values = batch.map(() => "(?, ?, ?, ?, ?, ?, ?, ?)").join(", ");
      const binds = batch.flatMap((advisory) => [
        advisory.ecosystem,
        advisory.packageName,
        advisory.packageVersion,
        advisory.id,
        advisory.summary,
        advisory.severity,
        advisory.references[0] ?? "",
        `https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`,
      ]);
      await execute(
        connection,
        `MERGE INTO ${table} target
         USING (
           SELECT column1 AS ECOSYSTEM, column2 AS PACKAGE_NAME, column3 AS PACKAGE_VERSION,
                  column4 AS ADVISORY_ID, column5 AS SUMMARY, column6 AS SEVERITY,
                  column7 AS REFERENCE_URL, column8 AS SOURCE_URL,
                  CURRENT_TIMESTAMP() AS SCANNED_AT
           FROM VALUES ${values}
         ) source
         ON target.ECOSYSTEM = source.ECOSYSTEM
            AND target.PACKAGE_NAME = source.PACKAGE_NAME
            AND target.PACKAGE_VERSION = source.PACKAGE_VERSION
            AND target.ADVISORY_ID = source.ADVISORY_ID
         WHEN MATCHED THEN UPDATE SET
           SUMMARY = source.SUMMARY, SEVERITY = source.SEVERITY,
           REFERENCE_URL = source.REFERENCE_URL, SOURCE_URL = source.SOURCE_URL,
           SCANNED_AT = source.SCANNED_AT
         WHEN NOT MATCHED THEN INSERT
           (ECOSYSTEM, PACKAGE_NAME, PACKAGE_VERSION, ADVISORY_ID, SUMMARY, SEVERITY,
            REFERENCE_URL, SOURCE_URL, SCANNED_AT)
         VALUES
           (source.ECOSYSTEM, source.PACKAGE_NAME, source.PACKAGE_VERSION, source.ADVISORY_ID,
            source.SUMMARY, source.SEVERITY, source.REFERENCE_URL, source.SOURCE_URL, source.SCANNED_AT)`,
        binds,
      );
    }
  });
  return rows.length;
}

export async function queryAdvisories(
  packages: Array<{ name: string; version: string }>,
): Promise<Advisory[]> {
  const unique = new Map(packages.map((pkg) => [`${pkg.name}\0${pkg.version}`, pkg]));
  const requested = [...unique.values()];
  if (requested.length === 0) return [];
  const table = tableName();
  const advisories: Advisory[] = [];

  await withConnection(async (connection) => {
    for (let offset = 0; offset < requested.length; offset += 100) {
      const batch = requested.slice(offset, offset + 100);
      const predicates = batch.map(() => "(PACKAGE_NAME = ? AND PACKAGE_VERSION = ?)").join(" OR ");
      const binds = ["npm", ...batch.flatMap((pkg) => [pkg.name, pkg.version])];
      const rows = await execute<SnowflakeRow>(
        connection,
        `SELECT ECOSYSTEM, PACKAGE_NAME, PACKAGE_VERSION, ADVISORY_ID, SUMMARY, SEVERITY,
                REFERENCE_URL, SOURCE_URL
         FROM ${table}
         WHERE ECOSYSTEM = ? AND (${predicates})`,
        binds,
      );
      for (const row of rows) {
        advisories.push({
          ecosystem: row.ECOSYSTEM,
          packageName: row.PACKAGE_NAME,
          packageVersion: row.PACKAGE_VERSION,
          id: row.ADVISORY_ID,
          summary: row.SUMMARY || "No advisory summary provided.",
          details: "",
          severity: row.SEVERITY || "UNKNOWN",
          references: row.REFERENCE_URL ? [row.REFERENCE_URL] : [],
          source: "Snowflake (OSV mirror)",
        });
      }
    }
  });
  return advisories;
}
