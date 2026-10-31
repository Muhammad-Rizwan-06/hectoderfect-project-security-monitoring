import assert from "node:assert/strict";
import { test } from "node:test";
import { explainFindings } from "../src/gemma.js";
import type { Finding } from "../src/types.js";

function finding(): Finding {
  return {
    ecosystem: "npm",
    packageName: "example",
    packageVersion: "1.2.3",
    id: "GHSA-test-1234",
    summary: "Example vulnerability",
    details: "A test advisory used only for the unit test.",
    severity: "HIGH",
    references: ["https://example.test/advisory"],
    source: "OSV",
    direct: false,
    dependencyPath: ["alpha", "example"],
    lockfilePath: "node_modules/alpha/node_modules/example",
    sources: ["OSV"],
  };
}

test("adds Gemma explanations while keeping API key out of request URL", async () => {
  const originalKey = process.env.GEMINI_API_KEY;
  const originalModel = process.env.GEMMA_MODEL;
  process.env.GEMINI_API_KEY = "test-key-not-a-real-secret";
  process.env.GEMMA_MODEL = "gemma-4-31b-it";
  try {
    let requestUrl = "";
    let requestInit: RequestInit | undefined;
    const fetchMock: typeof fetch = async (input, init) => {
      requestUrl = String(input);
      requestInit = init;
      return new Response(JSON.stringify({
        candidates: [{
          content: {
            parts: [{
              text: JSON.stringify({
                explanations: [{ index: 1, explanation: "This nested package has a known issue. Update it." }],
              }),
            }],
          },
        }],
      }), { status: 200 });
    };
    const results = [finding()];
    await explainFindings(results, fetchMock);
    assert.equal(requestUrl, "https://generativelanguage.googleapis.com/v1beta/models/gemma-4-31b-it:generateContent");
    assert.equal(new Headers(requestInit?.headers).get("x-goog-api-key"), "test-key-not-a-real-secret");
    assert.equal(results[0]?.explanation, "This nested package has a known issue. Update it.");
  } finally {
    if (originalKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = originalKey;
    if (originalModel === undefined) delete process.env.GEMMA_MODEL;
    else process.env.GEMMA_MODEL = originalModel;
  }
});

test("does not call Gemma when there are no findings", async () => {
  const fetchMock: typeof fetch = async () => {
    throw new Error("fetch should not be called");
  };
  await assert.doesNotReject(explainFindings([], fetchMock));
});

test("fails explicitly when the model returns malformed explanations", async () => {
  const originalKey = process.env.GEMINI_API_KEY;
  process.env.GEMINI_API_KEY = "test-key-not-a-real-secret";
  try {
    const fetchMock: typeof fetch = async () =>
      new Response(JSON.stringify({
        candidates: [{ content: { parts: [{ text: "not json" }] } }],
      }), { status: 200 });
    await assert.rejects(explainFindings([finding()], fetchMock), /invalid JSON/);
  } finally {
    if (originalKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = originalKey;
  }
});

test("rejects unsupported Gemma model names instead of silently substituting", async () => {
  const originalKey = process.env.GEMINI_API_KEY;
  const originalModel = process.env.GEMMA_MODEL;
  process.env.GEMINI_API_KEY = "test-key-not-a-real-secret";
  process.env.GEMMA_MODEL = "unknown-model";
  try {
    await assert.rejects(explainFindings([finding()]), /Unsupported GEMMA_MODEL/);
  } finally {
    if (originalKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = originalKey;
    if (originalModel === undefined) delete process.env.GEMMA_MODEL;
    else process.env.GEMMA_MODEL = originalModel;
  }
});
