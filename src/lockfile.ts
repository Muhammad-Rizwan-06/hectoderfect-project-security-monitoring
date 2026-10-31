import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { DependencyNode, LockfilePackage, PackageLock } from "./types.js";

function packageNameFromPath(packagePath: string, metadata: LockfilePackage): string | undefined {
  if (metadata.name) return metadata.name;
  const parts = packagePath.split("/");
  const nodeModulesIndex = parts.lastIndexOf("node_modules");
  if (nodeModulesIndex < 0 || nodeModulesIndex + 1 >= parts.length) return undefined;
  const first = parts[nodeModulesIndex + 1];
  if (!first) return undefined;
  if (first.startsWith("@")) {
    const second = parts[nodeModulesIndex + 2];
    return second ? `${first}/${second}` : undefined;
  }
  return first;
}

function resolveDependencyPath(
  packagePath: string,
  dependencyKey: string,
  packages: Record<string, LockfilePackage>,
): string | undefined {
  const start = packagePath ? packagePath.split("/") : [];
  for (let length = start.length; length >= 0; length -= 1) {
    const candidate = [...start.slice(0, length), "node_modules", dependencyKey].join("/");
    if (Object.hasOwn(packages, candidate)) return candidate;
  }
  return undefined;
}

export async function readDependencyGraph(filePath: string): Promise<{
  lockfilePath: string;
  nodes: DependencyNode[];
}> {
  const absolutePath = resolve(filePath);
  let parsed: PackageLock;
  try {
    const raw: unknown = JSON.parse(await readFile(absolutePath, "utf8"));
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("Lockfile root must be a JSON object.");
    }
    parsed = raw as PackageLock;
  } catch (error) {
    throw new Error(`Could not read package lockfile "${absolutePath}": ${errorMessage(error)}`);
  }

  if (!parsed.packages || !Number.isInteger(parsed.lockfileVersion) || (parsed.lockfileVersion ?? 0) < 2) {
    throw new Error("Unsupported package-lock format. Generate a package-lock.json with npm (lockfileVersion 2 or 3).");
  }

  const packages = parsed.packages;
  const root = packages[""] ?? {};
  const shortestPaths = new Map<string, string[]>();
  const queue: Array<{ packagePath: string; dependencyPath: string[] }> = [];
  const rootKeys = new Set([
    ...Object.keys(root.dependencies ?? {}),
    ...Object.keys(root.devDependencies ?? {}),
    ...Object.keys(root.optionalDependencies ?? {}),
    ...Object.keys(root.peerDependencies ?? {}),
  ]);

  for (const key of rootKeys) {
    const childPath = resolveDependencyPath("", key, packages);
    if (childPath) queue.push({ packagePath: childPath, dependencyPath: [key] });
  }

  for (let queueIndex = 0; queueIndex < queue.length; queueIndex += 1) {
    const current = queue[queueIndex];
    if (!current) continue;
    const existing = shortestPaths.get(current.packagePath);
    if (existing && existing.length <= current.dependencyPath.length) continue;
    shortestPaths.set(current.packagePath, current.dependencyPath);
    const metadata = packages[current.packagePath];
    if (!metadata) continue;

    const dependencyKeys = new Set([
      ...Object.keys(metadata.dependencies ?? {}),
      ...Object.keys(metadata.devDependencies ?? {}),
      ...Object.keys(metadata.optionalDependencies ?? {}),
      ...Object.keys(metadata.peerDependencies ?? {}),
    ]);
    for (const key of dependencyKeys) {
      const childPath = resolveDependencyPath(current.packagePath, key, packages);
      if (childPath) {
        queue.push({
          packagePath: childPath,
          dependencyPath: [...current.dependencyPath, key],
        });
      } else if (
        !Object.hasOwn(metadata.optionalDependencies ?? {}, key) &&
        metadata.peerDependenciesMeta?.[key]?.optional !== true
      ) {
        throw new Error(
          `Lockfile dependency "${key}" required by "${current.packagePath}" has no installed package entry.`,
        );
      }
    }
  }

  // Some lockfiles omit root dependency metadata. Keep scans useful by identifying top-level installed packages.
  if (rootKeys.size === 0) {
    for (const packagePath of Object.keys(packages)) {
      if (/^node_modules\/(?:@[^/]+\/)?[^/]+$/.test(packagePath)) {
        const name = packageNameFromPath(packagePath, packages[packagePath] ?? {});
        if (name) shortestPaths.set(packagePath, [name]);
      }
    }
  }

  const nodes: DependencyNode[] = [];
  for (const [packagePath, dependencyPath] of shortestPaths) {
    const metadata = packages[packagePath];
    const name = metadata && packageNameFromPath(packagePath, metadata);
    if (!metadata || !name || !metadata.version) {
      throw new Error(`Lockfile package "${packagePath}" is missing a package name or version.`);
    }
    nodes.push({
      lockfilePath: packagePath,
      name,
      version: metadata.version,
      direct: dependencyPath.length === 1,
      dependencyPath,
    });
  }
  nodes.sort((left, right) =>
    left.name.localeCompare(right.name) || left.version.localeCompare(right.version) ||
    left.lockfilePath.localeCompare(right.lockfilePath),
  );
  return { lockfilePath: absolutePath, nodes };
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
