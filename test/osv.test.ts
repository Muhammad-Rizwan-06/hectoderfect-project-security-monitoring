import assert from "node:assert/strict";
import { test } from "node:test";
import { queryOsv } from "../src/osv.js";
import type { DependencyNode } from "../src/types.js";

const packageNode: DependencyNode = {
  lockfilePath: "node_modules/example",
  name: "example",
  version: "1.2.3",
  direct: true,
  dependencyPath: ["example"],
};

test("maps OSV batch matches to package-version advisory records", async () => {
  let requestBody = "";
  const fetchMock: typeof fetch = async (_input, init) => {
    requestBody = String(init?.body);
    return new Response(JSON.stringify({
      results: [{
        vulns: [{
          id: "GHSA-test-1234",
          summary: "Example advisory",
          database_specific: { severity: "HIGH" },
          references: [{ url: "https://example.test/advisory" }],
        }],
      }],
    }), { status: 200 });
  };
  const advisories = await queryOsv([packageNode], fetchMock);
  assert.deepEqual(JSON.parse(requestBody), {
    queries: [{ package: { ecosystem: "npm", name: "example" }, version: "1.2.3" }],
  });
  assert.equal(advisories[0]?.packageName, "example");
  assert.equal(advisories[0]?.severity, "HIGH");
  assert.equal(advisories[0]?.id, "GHSA-test-1234");
});

test("reports upstream HTTP failures instead of returning an empty result", async () => {
  const fetchMock: typeof fetch = async () => new Response("rate limited", { status: 429 });
  await assert.rejects(queryOsv([packageNode], fetchMock), /OSV returned HTTP 429/);
});

test("does not make a network request for an empty dependency list", async () => {
  const fetchMock: typeof fetch = async () => {
    throw new Error("fetch should not be called");
  };
  assert.deepEqual(await queryOsv([], fetchMock), []);
});
