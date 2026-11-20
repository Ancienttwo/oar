import { afterEach, expect, test, vi } from "vitest";
import { startAppServerClient } from "../packages/oar/src/runtimes/codex/app-server-client.js";
import { DSH_BRIDGE_PROTOCOL } from "../packages/oar/src/runtimes/dsh/bridge.js";
import { DSH_READY_TIMEOUT_MS, dshControl } from "../packages/oar/src/runtimes/dsh/control.js";
import { sessionCredentialRedactor } from "../packages/oar/src/shared/credential-redactor.js";
import { appendStartupStderr, reportedStderr } from "../packages/oar/src/shared/executable/reported-stderr.js";
import { fakeLineProcess } from "./fixtures/fake-line-process.js";

const credential = "/fixture/key";
const tokenShape = "sk-fixture012345678901";
const jwt = "eyJfixture.payload.signature";
const stderr = `credential=${credential} provider=${tokenShape} jwt=${jwt}`;
const safeStderr = "credential=[redacted] provider=[redacted] jwt=[redacted]";

function redactor() {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit(credential);
  return credentials;
}

function ownedChild() {
  const child = fakeLineProcess();
  return Object.assign(child, {
    exitError: () => new Error(stderr),
    writeAcknowledged: async (text: string): Promise<void> => { child.write(text); },
  });
}

afterEach(() => { vi.useRealTimers(); });

test("stderr strips the partial line before credential redaction and filters token shapes afterwards", () => {
  const credentials = redactor();
  const redact = vi.fn(credentials.redact);
  const observation = { stderr: `mid-line-fragment\n${stderr}`, stderrStartsMidLine: true } as const;
  expect(reportedStderr(observation, redact)).toBe(safeStderr);
  expect(redact).toHaveBeenCalledExactlyOnceWith(stderr);
  const failure = new Error("open failed", { cause: { code: "fixture" } });
  expect(appendStartupStderr(failure, observation, credentials.redact)).toBe(failure);
  expect(failure.message).toBe(`open failed\nstderr (tail):\n${safeStderr}`);
  expect(failure.cause).toEqual({ code: "fixture" });
});

test("DSH ready timeout sanitizes caller-owned stderr", async () => {
  vi.useFakeTimers();
  const child = ownedChild();
  const control = dshControl(child, () => {}, redactor().redact);
  const rejected = expect(control.ready).rejects.toThrow(safeStderr);
  await vi.advanceTimersByTimeAsync(DSH_READY_TIMEOUT_MS);
  await rejected;
  child.kill();
});

test.each(["command timeout", "exit"] as const)("DSH %s sanitizes caller-owned stderr", async (reason) => {
  vi.useFakeTimers();
  const child = ownedChild();
  const control = dshControl(child, () => {}, redactor().redact);
  child.emit(`${JSON.stringify({ type: "ready", protocol: DSH_BRIDGE_PROTOCOL })}\n`);
  await control.ready;
  const rejected = expect(control.request("open", {}, 5)).rejects.toThrow(safeStderr);
  if (reason === "exit") { child.end(1); }
  else { await vi.advanceTimersByTimeAsync(5); }
  await rejected;
});

test("Codex sanitizes caller-owned error messages, nested RPC error data and process exit", async () => {
  const child = ownedChild();
  const client = startAppServerClient(() => child, "codex", {}, {}, undefined, { redact: redactor().redact });
  const rpcFailure = expect(client.request("fixture", {})).rejects.toMatchObject({
    message: safeStderr,
    cause: { native: { message: safeStderr, data: { detail: safeStderr } } },
  });
  child.emit(`${JSON.stringify({ id: 1, error: { code: -1, message: stderr, data: { detail: stderr } } })}\n`);
  await rpcFailure;
  const exitFailure = expect(client.request("fixture", {})).rejects.toThrow(safeStderr);
  child.end(1);
  await exitFailure;
});
