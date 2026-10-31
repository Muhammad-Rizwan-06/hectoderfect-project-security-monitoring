import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { readDependencyGraph } from "../src/lockfile.js";

const fixture = fileURLToPath(new URL("./fixtures/package-lock.json", import.meta.url));

test("reads direct and deeply nested npm dependencies with dependency paths", async () => {
  const graph = await readDependencyGraph(fixture);
  assert.equal(graph.nodes.length, 2);
  const alpha = graph.nodes.find((node) => node.name === "alpha");
  const beta = graph.nodes.find((node) => node.name === "beta");
  assert.equal(alpha?.direct, true);
  assert.deepEqual(alpha?.dependencyPath, ["alpha"]);
  assert.equal(beta?.direct, false);
  assert.deepEqual(beta?.dependencyPath, ["alpha", "beta"]);
});

test("rejects unsupported package-lock formats with an actionable message", async () => {
  await assert.rejects(
    readDependencyGraph(fileURLToPath(new URL("./fixtures/invalid-lock.json", import.meta.url))),
    /Unsupported package-lock format/,
  );
});
