import { ChildProcess } from "node:child_process";
import { access } from "node:fs/promises";
import { PassThrough } from "node:stream";
import { expect, test, vi } from "vitest";
import { opencodeSession } from "../../packages/oar/src/runtimes/opencode/session.js";
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

const installation = { kind: "available", via: "executable", command: "opencode", version: release.version } as const;

test("OpenCode v2 forwards caller credentials and the filtered environment to the owned query", async () => {
  const credential = "/fixture/session-key";
  const spawnAcp = vi.fn(() => { throw new Error("unexpected ACP spawn"); });
  const dispose = vi.fn(async () => {});
  const spawnQuery = vi.fn(() => {
    const stderr = new PassThrough();
    const child = Object.assign(new ChildProcess(), { stderr });
    queueMicrotask(() => { stderr.end(Buffer.from(credential)); child.emit("close", 1); });
    return { child, spawned: Promise.resolve(), terminate: () => {}, dispose };
  });
  await expect(opencodeSession(spawnAcp, spawnQuery, installation, options, { credentialsForRedaction: [credential] })).rejects.toMatchObject({
    message: expect.stringContaining("stderr (tail):\n[redacted]"),
    cause: { stderr: "[redacted]" },
  });
  expect(spawnAcp).not.toHaveBeenCalled();
  expect(spawnQuery).toHaveBeenCalledExactlyOnceWith(installation.command, ["debug", "agents", "--standalone"], { cwd: options.cwd, env: options.env, shell: false });
  expect(dispose).toHaveBeenCalledOnce();
});

test("OpenCode v2 removes prepared instructions before surfacing a redacted ACP open error", async () => {
  const credential = "qx7";
  let file = "";
  const spawnQuery = vi.fn(() => { throw new Error("unexpected query spawn"); });
  const open = opencodeSession((_command, _args, { env }) => {
    const { instructions } = JSON.parse(env.OPENCODE_CONFIG_CONTENT ?? "{}");
    [file] = instructions;
    throw new Error(`native open failed: ${credential}`, { cause: { native: credential } });
  }, spawnQuery, installation, { cwd: options.cwd, env: options.env, appendSystemPrompt: "extra" }, { credentialsForRedaction: [credential] });
  await expect(open).rejects.toMatchObject({ message: "native open failed: [redacted]", cause: { native: "[redacted]" } });
  expect(file).toMatch(/instructions\.md$/u);
  await expect(access(file)).rejects.toMatchObject({ code: "ENOENT" });
  expect(spawnQuery).not.toHaveBeenCalled();
});
