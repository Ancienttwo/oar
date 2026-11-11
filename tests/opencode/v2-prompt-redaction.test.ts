import { expect, test } from "vitest";
import { prepareOpenCodeV2Prompts } from "../../packages/oar/src/runtimes/opencode/prompt-config-v2.js";
import type { ExecutableRunner } from "../../packages/oar/src/runtimes/opencode/prompt-config.js";

const release = { major: 2, minor: 3, patch: 2, version: "2.3.2" } as const;
const options = { cwd: process.cwd(), env: { XDG_DATA_HOME: process.cwd() }, systemPrompt: "replacement" };

function failedQuery(stderr: string): ExecutableRunner {
  return () => Promise.resolve({ ok: false, exitCode: 1, stdout: "", stderr });
}

test("OpenCode v2 agent query diagnostics redact registered credentials and token shapes after dropping a partial first line", async () => {
  const envCredential = "fixture-env-credential";
  const explicitCredentials = ["q7x", "/fixture/credential"];
  const partialLine = `${"x".repeat(8192)}partial-credential-fragment`;
  const query = failedQuery(`${partialLine}\nenv=${envCredential} short=q7x path=/fixture/credential\nprovider=sk-fixture012345678901 jwt=eyJfixture.payload.signature\n`);
  const stderr = "env=[redacted] short=[redacted] path=[redacted]\nprovider=[redacted] jwt=[redacted]\n";
  const error = prepareOpenCodeV2Prompts("opencode", release, { ...options, env: { ...options.env, TEST_TOKEN: envCredential } }, query, explicitCredentials);
  await expect(error).rejects.toMatchObject({
    message: `opencode debug agents failed while resolving the session's agents: exit code 1; signal none\nstderr (tail):\n${stderr}`,
    cause: { exitCode: 1, signal: null, stderr },
  });
});

test("OpenCode v2 agent query redacts a registered credential before bounding diagnostics", async () => {
  const credential = `fixture-${"x".repeat(8192)}`;
  const query = failedQuery(`agent query rejected ${credential}\n`);
  await expect(prepareOpenCodeV2Prompts("opencode", release, options, query, [credential])).rejects.toMatchObject({
    message: expect.stringContaining("stderr (tail):\nagent query rejected [redacted]\n"),
    cause: { stderr: "agent query rejected [redacted]\n" },
  });
});
