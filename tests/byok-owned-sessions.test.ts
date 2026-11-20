import { expect, test, vi } from "vitest";
import { claudeProjectionProfile, initialClaudeProjection } from "../packages/oar/src/runtimes/claude/projection.js";
import { grokAccountUsage } from "../packages/oar/src/runtimes/grok/account-usage.js";
import { grokAuthStatus } from "../packages/oar/src/runtimes/grok/auth.js";
import { acpSession } from "../packages/oar/src/shared/acp/session.js";
import { sessionCredentialRedactor } from "../packages/oar/src/shared/credential-redactor.js";
import { asRecord, parseJson } from "../packages/oar/src/shared/json.js";
import { streamJsonSession } from "../packages/oar/src/shared/stream-json/session.js";
import { fakeLineProcess, type FakeLineProcess } from "./fixtures/fake-line-process.js";

function ownedChild(onWrite?: Parameters<typeof fakeLineProcess>[0]) {
  const child = fakeLineProcess(onWrite);
  return Object.assign(child, {
    observeDescendants: vi.fn(),
    writeAcknowledged: async (text: string): Promise<void> => { child.write(text); },
  });
}

function answer(child: FakeLineProcess, id: number, result: unknown): void {
  child.emit(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}

const cwd = process.cwd();
const env = { OAR_FIXTURE_ENV: "owned" };
const capabilities = { queue: { durable: false }, attribution: "opaque", images: false } as const;
const grok = { kind: "available", via: "executable", command: "grok", version: "1.0.70" } as const;

function unexpectedTerminal(): never { throw new Error("unexpected terminal spawn"); }

// Keep the first prompt open until both queue controls have been issued.
// oxlint-disable-next-line max-statements -- Assertions follow the wire order from open to both completed prompts.
test("caller-owned ACP withdraws input synchronously and drains the next retained input", async () => {
  const prompts: { id: number; text: unknown }[] = [];
  const child = ownedChild((line, process) => {
    const request = asRecord(parseJson(line));
    if (typeof request?.id !== "number") { return; }
    switch (request.method) {
      case "initialize": answer(process, request.id, { protocolVersion: 1, agentCapabilities: {}, authMethods: [] }); break;
      case "session/new": answer(process, request.id, { sessionId: "owned-session" }); break;
      case "session/prompt": {
        const prompt = asRecord(request.params)?.prompt;
        prompts.push({ id: request.id, text: Array.isArray(prompt) ? asRecord(prompt[0])?.text : undefined });
        break;
      }
      default: answer(process, request.id, {});
    }
  });
  const spawn = vi.fn(() => child);
  const session = await acpSession({ args: [], capabilities })(spawn, unexpectedTerminal, grok, { cwd, env });
  try {
    expect(spawn).toHaveBeenCalledExactlyOnceWith("grok", [], { cwd, env });
    await expect(session.prompt("hold")).resolves.toMatchObject({ response: { body: { kind: "accepted" } } });
    const inputId = "55555555-5555-4555-8555-555555555555";
    const [queued, withdrawn] = await Promise.all([session.queue("withdrawn", { inputId }), session.withdraw?.(inputId)]);
    expect(queued.response.body).toMatchObject({ kind: "accepted", queued: "adapter" });
    expect(withdrawn?.response.body.kind).toBe("accepted");
    await expect(session.queue("kept")).resolves.toMatchObject({ response: { body: { kind: "accepted" } } });
    expect(prompts.map(({ text }) => text)).toEqual(["hold"]);
    const [first] = prompts;
    if (first === undefined) { throw new Error("prompt was not written"); }
    answer(child, first.id, { stopReason: "end_turn" });
    await expect.poll(() => prompts.map(({ text }) => text)).toEqual(["hold", "kept"]);
    const [, second] = prompts;
    if (second === undefined) { throw new Error("queued prompt was not written"); }
    answer(child, second.id, { stopReason: "end_turn" });
  } finally { await session.dispose(); }
});

// oxlint-disable-next-line max-statements -- Inspect the same process and record stream before and after the reply.
test("caller-owned stream JSON waits for an explicit reply to a runtime request", async () => {
  const child = ownedChild();
  const captured: { respond?: (reply: Record<string, unknown>) => Promise<void> } = {};
  const session = await streamJsonSession(child, "owned-stream", sessionCredentialRedactor({}), {
    projection: claudeProjectionProfile,
    initial: initialClaudeProjection,
    capabilities,
    steer: false,
    consume: () => false,
    open: async () => {},
    exited: () => {},
    disposing: () => {},
  }, { onAppRequest: (_request, reply) => { captured.respond = reply; } });
  try {
    child.emit(`${JSON.stringify({ type: "control_request", request_id: "permission", request: { subtype: "can_use_tool", input: {} } })}\n`);
    expect(child.written).toEqual([]);
    expect(captured.respond).toBeTypeOf("function");
    const reply = { type: "control_response", response: { subtype: "success", request_id: "permission", response: { behavior: "deny" } } };
    await captured.respond?.(reply);
    expect(child.written).toEqual([`${JSON.stringify(reply)}\n`]);
    expect(session.records().at(-1)).toMatchObject({ kind: "response", requestId: "permission", body: { kind: "accepted", native: reply } });
  } finally { await session.dispose(); }
});

test.each([true, false])("Grok uses caller-owned readers for %s signed-out identity", async (signedOut) => {
  const child = ownedChild((line, process) => {
    const request = asRecord(parseJson(line));
    if (typeof request?.id !== "number") { return; }
    switch (request.method) {
      case "initialize": answer(process, request.id, { protocolVersion: 1, agentCapabilities: {}, authMethods: [] }); break;
      case "_x.ai/billing": answer(process, request.id, { config: { creditUsagePercent: 25 }, subscription_tier: "SuperGrok" }); break;
      case "_x.ai/auth/info": answer(process, request.id, { methodId: signedOut ? null : "cached_token", email: "fixture@example.test" }); break;
    }
  });
  const spawn = vi.fn(() => child);
  const run = vi.fn(async () => ({ ok: true, exitCode: 0, stdout: "You are not authenticated.", stderr: "" }));
  const options = { cwd, env, spawn, run, redact: (text: string): string => text, timeoutMs: 5000 };
  if (signedOut) {
    await expect(grokAuthStatus(grok, options)).resolves.toMatchObject({ kind: "logged_out", lastAccount: { email: "fixture@example.test" } });
    expect(run.mock.calls[0]).toEqual(["grok", ["models"], expect.objectContaining({ env })]);
  } else {
    await expect(grokAccountUsage(grok, options)).resolves.toMatchObject({ kind: "available", plan: "SuperGrok", email: "fixture@example.test" });
  }
  expect(spawn).toHaveBeenCalledExactlyOnceWith("grok", ["agent", "--always-approve", "--no-leader", "stdio"], { cwd, env });
  expect(child.killed()).toBe(true);
});
