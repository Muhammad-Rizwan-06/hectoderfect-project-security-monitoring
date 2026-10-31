export interface LockfilePackage {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
}

export interface PackageLock {
  name?: string;
  lockfileVersion?: number;
  packages?: Record<string, LockfilePackage>;
}

export interface DependencyNode {
  lockfilePath: string;
  name: string;
  version: string;
  direct: boolean;
  dependencyPath: string[];
}

export interface Advisory {
  ecosystem: string;
  packageName: string;
  packageVersion: string;
  id: string;
  summary: string;
  details: string;
  severity: string;
  references: string[];
  source: string;
}

export interface Finding extends Advisory {
  direct: boolean;
  dependencyPath: string[];
  lockfilePath: string;
  sources: string[];
  explanation?: string;
}

export interface AuditReport {
  schemaVersion: 1;
  generatedAt: string;
  lockfile: string;
  dependencyCount: number;
  sources: string[];
  findings: Finding[];
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: { severity?: string };
  ecosystem_specific?: { severity?: string };
  references?: Array<{ url?: string }>;
}

export interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVulnerability[] }>;
}
