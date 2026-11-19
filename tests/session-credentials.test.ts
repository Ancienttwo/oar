import { manualCompaction } from "../packages/oar/src/shared/manual-compaction.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { expect, test } from "vitest";
import { mcpCredentialRedactor } from "../packages/oar/src/shared/mcp-servers.js";
import { readEnvironmentCredential, rememberEnvironmentCredentials, sessionCredentialRedactor } from "../packages/oar/src/shared/credential-redactor.js";
import { withSessionCredentials } from "../packages/oar/src/shared/session-credentials.js";
import { dshOpenedFrame, foldDsh, initialDshProjection, redactDshRecord } from "../packages/oar/src/runtimes/dsh/projection.js";
import { dshSession } from "../packages/oar/src/runtimes/dsh/session.js";
import { redactCodexRecord } from "../packages/oar/src/runtimes/codex/session.js";
import { redactAcpRecord } from "../packages/oar/src/shared/acp/session.js";
import { createAcpConfigUpdates } from "../packages/oar/src/shared/acp/config-updates.js";
import { acpRequestTimeoutError } from "../packages/oar/src/shared/acp/errors.js";
import { createAcpTokenUsage, wholePromptTokenUsage } from "../packages/oar/src/shared/acp/token-usage.js";
import type { AcpSessionProfile } from "../packages/oar/src/shared/acp/profile.js";
import { grokSpontaneousTokens } from "../packages/oar/src/runtimes/grok/spontaneous-usage.js";
import { redactStreamJsonRecord } from "../packages/oar/src/shared/stream-json/session.js";
import { createSessionKernel } from "../packages/oar/src/shared/session-kernel.js";
import { RuntimeFailureError } from "../packages/oar/src/contracts/runtime-failure-error.js";
import type { RawEvent, RuntimeEventBody } from "../packages/oar/src/contracts/session.js";
import { fakeLineProcess } from "./fixtures/fake-line-process.js";

const secret = "sentinel-provider-secret";

test.each(["KEY", "APIKEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASSPHRASE", "CREDENTIAL", "CREDENTIALS", "COOKIE", "PWD", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "GITHUB_TOKEN", "MYSQL_PWD", "PGPASSWORD", "custom_apikey"])("redacts explicit credential %s", (name) => {
  const { redact } = sessionCredentialRedactor({ cwd: "/work", env: { [name]: secret } });
  expect(redact(`rejected ${secret}`)).toBe("rejected [redacted]");
});

test.each([
  ["SSH_AUTH_SOCK", "/run/user/1000/ssh-agent"], ["XAUTHORITY", "/home/user/.Xauthority"],
  ["GIT_AUTHOR_EMAIL", "author@example.test"], ["GIT_AUTHOR_NAME", "Example Author"],
  ["PASSWORD_STORE_DIR", "/home/user/.password-store"], ["GNUPG_PASSPHRASE_FILE", "/home/user/passphrase"],
  ["KEYTIMEOUT", "12345678"], ["AWS_ACCESS_KEY_ID", "public-access-id"],
  ["PATH", "/usr/local/bin:/usr/bin"], ["HOME", "/home/user"], ["PWD", "/workspace/project"], ["OLDPWD", "/workspace/previous"],
  ["API_KEY", "/etc/credentials/key"], ["AUTH_TOKEN", "~/credentials/token"], ["SECRET", String.raw`C:\credentials\key`],
  ["API_KEY", "short"], ["TOKEN", ""], ["TOKEN", null],
])("preserves noncredential or path %s=%s", (name, value) => {
  const { redact } = sessionCredentialRedactor({ cwd: "/work", env: { [name]: value } });
  const text = `diagnostic: ${String(value)}`;
  expect(redact(text)).toBe(text);
});

test("uses longest-first across env, MCP and SDK keys, and retains previous keys after a model change", () => {
  const { redact, add } = sessionCredentialRedactor({ cwd: "/work", env: { API_KEY: `${secret}-long` }, mcpServers: [{ name: "echo", command: "echo", env: { TOKEN: secret } }] });
  add(`${secret}-longer`);
  expect(redact(`${secret}-longer ${secret}-long ${secret}`)).toBe("[redacted] [redacted] [redacted]");
});

test("withholds an object whose credential-bearing key already contains the replacement marker", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "[redacted]" } });
  const key = "prefix[redacted]suffix";
  expect(credentials.redactValue({ [key]: "withhold-me" })).toBe("[redacted]");
  expect(credentials.redactValue(String.raw`{"prefix\u005bredacted]suffix":"withhold-me"}`, () => true)).toBe('"[redacted]"');
});

test("a native protocol exemption does not apply to an opaque alias of the same object", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit("type");
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const item = { type: "agentMessage", id: "m", text: "plain" };
  const frame = kernel.frame({ type: "item/completed", native: { item, opaque: item }, events: [] });
  expect(frame.body.native).toEqual({ item, opaque: "[redacted]" });
});

// oxlint-disable-next-line eslint/max-statements -- One stream, checked across control, live delivery and replay.
test("redacts before retention and delivery, while control receives original input and native data is unchanged", async () => {
  const { redactValue } = sessionCredentialRedactor({ cwd: "/work", env: { API_KEY: secret } });
  const kernel = createSessionKernel("session", redactValue);
  const live: RawEvent[] = [];
  kernel.rawEvents((record) => { live.push(record); });
  const result = await kernel.control({ kind: "prompt", input: secret }, (request) => {
    expect(request.body).toEqual({ kind: "prompt", input: secret });
    return { kind: "rejected", code: "error", reason: secret };
  });
  const native = { [secret]: { secret, path: "/workspace/safe-path" } };
  kernel.frame({ type: "native/error", native, events: [{ kind: "turn_ended", outcome: { kind: "failed", failure: "provider", reason: secret } }] });
  const replay: RawEvent[] = [];
  kernel.rawEvents((record) => { replay.push(record); }, { sessionId: "session", afterSeq: -1 });
  expect(live).toEqual(replay);
  expect(live).toEqual(kernel.records());
  for (const value of [result, live, replay, kernel.records()]) {
    expect(JSON.stringify(value)).not.toContain(secret);
    expect(inspect(value, { depth: null })).not.toContain(secret);
  }
  expect(live.at(-1)).toMatchObject({ body: { native: "[redacted]" } });
  expect(native[secret].secret).toBe(secret);
});

test("dsh projects the sanitized arguments, including escaped and nested values", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit("true");
  const text = String.raw`{"force":true,"id":9007199254740993,"nested":{"message":"tr\u0075e"}}`;
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const folded = foldDsh(initialDshProjection("root"), { type: "native", channel: "session/event", event: {
    type: "tool/call", data: { callId: "c", name: "demo", arguments: text },
  } });
  const frame = kernel.frame(folded.frame.body);
  const expected = '{"force":true,"id":9007199254740993,"nested":{"message":"[redacted]"}}';
  expect(frame.body.native).toMatchObject({ data: { arguments: expected } });
  expect(frame.body.events[0]).toMatchObject({ input: expected });
});

test("dsh redacts every duplicate JSON member and retains the other token bytes", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit(secret);
  const text = String.raw`{ "payload":"\u0073entinel-provider-secret", "payload":3e+1, "id":9007199254740993 }`;
  const expected = '{ "payload":"[redacted]", "payload":3e+1, "id":9007199254740993 }';
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const folded = foldDsh(initialDshProjection("root"), { type: "native", channel: "session/event", event: {
    type: "tool/call", data: { callId: "c", name: "demo", arguments: text },
  } });
  const frame = kernel.frame(folded.frame.body);
  expect(frame.body.native).toMatchObject({ data: { arguments: expected } });
  expect(frame.body.events[0]).toMatchObject({ input: expected });
});

test("dsh withholds encoded fragments from live and durable streams when credentials are known", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit(secret);
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const projection = initialDshProjection("root");
  const chunks = [String.raw`{"value":"\u00`, `73${secret.slice(1)}"}`].map(argumentsDelta => ({
    type: "chunk", chunk: { type: "tool-call-delta", id: "c", argumentsDelta },
  }));
  for (const native of chunks) {
    const folded = foldDsh(projection, { type: "native", channel: "agent/assistant-stream", frame: native });
    expect(kernel.frame(folded.frame.body).body).toMatchObject({
      native: { type: "chunk", chunk: { type: "tool-call-delta", id: "c" } }, events: [],
    });
  }
  const attempt = foldDsh(projection, { type: "native", channel: "session/event", event: {
    type: "assistant/attempt", data: { stream: chunks },
  } });
  kernel.frame(attempt.frame.body);
  expect(JSON.stringify(kernel.records())).not.toContain("argumentsDelta");
  expect(JSON.stringify(kernel.records())).not.toContain(secret.slice(1));
});

test("dsh decides stream chunk withholding before removing fragment fields", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit("argumentsDelta");
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const live: RawEvent[] = [];
  kernel.rawEvents(record => { live.push(record); });
  const projection = initialDshProjection("root");
  const chunk = { type: "tool-call-delta", id: "private-chunk-id", argumentsDelta: "part", annotation: "private-annotation" };
  const native = { type: "chunk", chunk };
  const streamed = foldDsh(projection, { type: "native", channel: "agent/assistant-stream", frame: native });
  expect(kernel.frame(streamed.frame.body).body).toMatchObject({ native: { type: "chunk", chunk: "[redacted]" }, events: [] });
  const attempt = foldDsh(projection, { type: "native", channel: "session/event", event: {
    type: "assistant/attempt", data: { stream: [native] },
  } });
  expect(kernel.frame(attempt.frame.body).body.native).toMatchObject({ data: { stream: [{ type: "chunk", chunk: "[redacted]" }] } });
  expect(live).toEqual(kernel.records());
  expect(JSON.stringify(live)).not.toMatch(/private-chunk-id|private-annotation/u);
});

test("dsh refuses an invalid model without encoding its credential into the opening diagnostic", async () => {
  const key = 'provider-"quoted"-credential';
  const failSpawn = () => { throw new Error("invalid model reached spawn"); };
  const attempt = dshSession(failSpawn, { kind: "available", via: "executable", command: "dsh" }, {
    cwd: "/work", model: key, launch: { directory: "/work", patches: [], env: { API_KEY: key } },
  });
  await expect(attempt).rejects.toThrow("DSH requires a model in provider/model form");
});

test("DSH opening refuses a private model mismatch without reporting the withheld model", async () => {
  const directory = await mkdtemp(join(tmpdir(), "oar-dsh-redaction-"));
  try {
    const child = fakeLineProcess((line, process) => {
      const request = JSON.parse(line);
      process.emit(`${JSON.stringify({ type: "response", id: request.id, result: {
        sessionId: request.sessionId, model: { provider: "p", model: "private-sibling", [secret]: true },
      } })}\n`);
    });
    const subscribe = child.onLine.bind(child);
    const open = dshSession(() => Object.assign(child, {
      observeDescendants() {},
      onLine(handler: (line: string) => void) {
        subscribe(handler);
        queueMicrotask(() => child.emit('{"type":"ready","protocol":1}\n'));
      },
    }), { kind: "available", via: "executable", command: "dsh" }, {
      cwd: directory, model: "p/m", launch: { directory, patches: [], env: { API_KEY: secret } },
    });
    await expect(open).rejects.toMatchObject({ name: "ModelConfirmationError", requested: "p/m", reported: null, message: "DSH did not apply model p/m" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("redacts an unknown dsh turn reason containing a quoted credential", () => {
  const key = 'fixture-"quoted"';
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const { frame } = foldDsh(initialDshProjection("root"), { type: "native", channel: "session/event", event: {
    type: "turn/end", data: { reason: { kind: key } },
  } });
  expect(kernel.frame(frame.body).body.events[0]).toMatchObject({
    kind: "turn_ended", outcome: { kind: "failed", reason: "DSH ended the turn with [redacted]" },
  });
});

test("redacts encoded arguments inside a native dsh assistant message", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit(secret);
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const frame = kernel.frame({ type: "session/event:assistant/message", events: [], native: {
    type: "assistant/message", data: { message: { content: [
      { type: "text", text: `echo ${secret}` },
      { type: "tool-call", arguments: JSON.stringify({ value: `prefix ${secret} suffix`, keep: true }) },
    ] } },
  } });
  expect(frame.body.native).toMatchObject({ data: { message: { content: [
    { type: "text", text: "echo [redacted]" },
    { type: "tool-call", arguments: '{"value":"prefix [redacted] suffix","keep":true}' },
  ] } } });
});

test.each([' { "id": 9007199254740993, "ratio": 3e+1 } ', 'true', 'null'])("keeps untouched encoded JSON bytes (%s)", (text) => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit("true");
  expect(credentials.redactValue({ arguments: text }, path => path[0] === "arguments")).toEqual({ arguments: text });
});

test("hides a credential-bearing key's containing object without changing the outer type", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit(secret);
  const value = { arguments: JSON.stringify({ safe: true, nested: { "[redacted]": 1, [secret]: 2 } }) };
  const sanitized = credentials.redactValue(value, path => path[0] === "arguments");
  expect(JSON.parse(sanitized.arguments)).toEqual({ safe: true, nested: "[redacted]" });
  expect(credentials.redactValue({ payload: { [secret]: true }, alive: true })).toEqual({ payload: "[redacted]", alive: true });
});

test("keeps dsh protocol discriminators and redacts the same strings inside message text", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "session/event:assistant/message", MCP_TOKEN: "turn_ended" } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const type = "session/event:assistant/message";
  const frame = kernel.frame({ type, native: { text: type }, events: [{ kind: "turn_ended", outcome: { kind: "failed", failure: "unknown", reason: "turn_ended" } }] });
  expect(frame.body).toEqual({ type, native: { text: "[redacted]" }, events: [{ kind: "turn_ended", outcome: { kind: "failed", failure: "unknown", reason: "[redacted]" } }] });
});

test.each(["credential", "image"] as const)("stream-json withholds encoded tool input fragments containing a split %s", (source) => {
  const credentials = sessionCredentialRedactor({});
  if (source === "image") credentials.addImage(secret);
  else credentials.addExplicit(secret);
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials));
  for (const delta of [secret.slice(0, 11), secret.slice(11)]) {
    const native = { type: "stream_event", event: { type: "content_block_delta", delta: { type: "input_json_delta", partial_json: delta } } };
    const frame = kernel.frame({ type: "stream_event", native, events: [{ kind: "tool_call_input_delta", callId: "tool-1", delta }] });
    expect(frame.body).toEqual({ type: "stream_event", native: { type: "stream_event", event: {
      type: "content_block_delta", delta: { type: "input_json_delta" },
    } }, events: [] });
  }
});

test.each(["claude", "acp", "codex"] as const)("%s sanitizes the native and JSON-encoded inputs consistently", (runtime) => {
  const key = 'provider-"quoted"-and-\\escaped-key';
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const input = { text: key, nested: { [key]: 1 }, keep: false };
  const expected = { text: "[redacted]", nested: "[redacted]", keep: false };
  const frame = {
    claude: { type: "assistant", native: { message: { content: [{ type: "tool_use", input }] } }, safe: { message: { content: [{ type: "tool_use", input: expected }] } }, redact: (record: RawEvent) => redactStreamJsonRecord(record, credentials) },
    acp: { type: "tool_call", native: { update: { sessionUpdate: "tool_call", rawInput: input } }, safe: { update: { sessionUpdate: "tool_call", rawInput: expected } }, redact: (record: RawEvent) => redactAcpRecord(record, credentials) },
    codex: { type: "item/started", native: { item: { type: "mcpToolCall", arguments: input } }, safe: { item: { type: "mcpToolCall", arguments: expected } }, redact: (record: RawEvent) => redactCodexRecord(record, credentials.redactValue) },
  }[runtime];
  const live = frame.redact({ kind: "frame", sessionId: "root", seq: 0, receivedAt: 0, agentPath: [], body: {
    type: frame.type, native: frame.native, events: [{ kind: "tool_call_started", callId: "t", tool: "demo", input: JSON.stringify(input) }],
  } });
  expect(live.body).toEqual({ type: frame.type, native: frame.safe, events: [{ kind: "tool_call_started", callId: "t", tool: "demo", input: JSON.stringify(expected) }] });
});

test("ACP withholds a split credential before observer buffering and flushes an unmatched suffix", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const pending = new Map<string, string>();
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials, undefined, pending));
  const type = "agent_message_chunk";
  const chunk = (text: string) => kernel.frame({ type, native: { update: { sessionUpdate: type, content: { type: "text", text } } },
    events: [{ kind: "text_delta", text }] });
  expect(chunk(`before ${secret.slice(0, 12)}`).body.events).toEqual([{ kind: "text_delta", text: "before " }]);
  expect(chunk(`${secret.slice(12)} after`).body).toMatchObject({ native: { update: { content: { text: "[redacted] after" } } },
    events: [{ kind: "text_delta", text: "[redacted] after" }] });
  expect(chunk("sentinel").body.events).toEqual([]);
  expect(kernel.frame({ type: "session/prompt", native: {}, events: [{ kind: "turn_ended", outcome: { kind: "completed" } }] }).body.events)
    .toEqual([{ kind: "text_delta", text: "sentinel" }, { kind: "turn_ended", outcome: { kind: "completed" } }]);
  expect(pending.size).toBe(0);
});

test("DSH keeps native context counters when a credential coincides with the context-window key", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "contextWindow" } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const events = [{ kind: "usage" as const, usage: { context: { tokens: 10, contextWindow: 1000, percent: 1 } } }];
  expect(kernel.frame({ type: "session/event:assistant/message", native: { opaque: { contextWindow: 1 } }, events }).body)
    .toEqual({ type: "session/event:assistant/message", native: { opaque: "[redacted]" }, events });
});

test("DSH redacts a credential split across text blocks in one durable message", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const original = [{ type: "text", text: `before ${secret.slice(0, 12)}` },
    { type: "text", text: `${secret.slice(12)} after` }];
  const native = { data: { message: { content: original } } };
  const frame = kernel.frame({ type: "session/event:assistant/message", native, events: [] });
  expect(frame.body.native).toEqual({ data: { message: { content: [{ type: "text", text: "before [redacted] after" }, { type: "text", text: "" }] } } });
});

test("Claude redacts split draft text before publishing either native or projected data", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const tails = { drafts: new Map<string, string>(), assistant: new Map<string, string>(), projected: new Map<string, string>(), messages: new Map<string, { id: unknown; published: boolean }>() };
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials, tails));
  const text = (chunk: string) => kernel.frame({ type: "stream_event", native: { type: "stream_event", event: {
    type: "content_block_delta", index: 0, delta: { type: "text_delta", text: chunk },
  } }, events: [{ kind: "text_delta", text: chunk }] });
  expect(text(secret.slice(0, 12)).body.events).toEqual([]);
  expect(text(secret.slice(12)).body.events).toEqual([{ kind: "text_delta", text: "[redacted]" }]);
  expect(JSON.stringify(kernel.records())).not.toContain(secret.slice(12));
});

test.each(["session/update", "opencode/session/child_update/after_answer"])("ACP withholds native-only child chunks on %s", method => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const childNotice = (type: string, params: Record<string, unknown>) => type === "opencode/session/child_update"
    ? { sessionId: "child", parent: "root", update: params.update as Record<string, unknown> } : null;
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials, childNotice, new Map()));
  for (const sessionUpdate of ["agent_message_chunk", "agent_thought_chunk"]) {
    for (const text of [secret.slice(0, 12), secret.slice(12)]) {
      const frame = kernel.frame({ type: method, native: { update: { sessionUpdate, content: { type: "text", text } } }, events: [] }, { sessionId: "child" });
      expect(frame.body.native).toEqual({ update: { sessionUpdate } });
    }
  }
});

test("ACP withholds incomplete reasoning from native and derived records", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials));
  const type = "agent_thought_chunk";
  for (const text of [secret.slice(0, 12), secret.slice(12)]) {
    const frame = kernel.frame({ type, native: { sessionId: "root", update: { sessionUpdate: type, content: { type: "text", text } } },
      events: [{ kind: "reasoning", content: { kind: "text", text } }],
    });
    expect(frame.body).toEqual({ type, native: { sessionId: "root", update: { sessionUpdate: type } }, events: [] });
  }
});

test("ACP flushes child text on its terminal lifecycle frame", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const pending = new Map([["child", "sentinel"]]);
  const childNotice = () => ({ sessionId: "child", parent: "root", update: null });
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials, childNotice, pending));
  const frame = kernel.frame({ type: "opencode/session/child_update", native: {}, events: [{ kind: "task_ended", taskId: "child", status: "completed" }] });
  expect(frame.body.events[0]).toEqual({ kind: "text_delta", text: "sentinel", byokChildId: "child" });
  expect(pending.size).toBe(0);
});

test("protocol keys keep native dsh arguments and Codex terminal evidence readable", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "arguments", MCP_TOKEN: "threadId" } });
  const dsh = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const { frame } = foldDsh(initialDshProjection("root"), { type: "native", channel: "session/event", event: {
    type: "tool/call", data: { callId: "c", name: "demo", arguments: '{"keep":true,"opaque":{"arguments":1}}' },
  } });
  expect(dsh.frame(frame.body).body.native).toMatchObject({ data: { arguments: '{"keep":true,"opaque":"[redacted]"}' } });
  const codex = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const native = { threadId: "root", turn: { id: "t", status: "completed" }, opaque: { threadId: "safe" } };
  expect(codex.frame({ type: "turn/completed", native, events: [] }).body.native).toEqual({ ...native, opaque: "[redacted]" });
  const item = { type: "mcpToolCall", id: "tool", arguments: { arguments: "opaque" } };
  expect(codex.frame({ type: "item/started", native: { item }, events: [] }).body.native)
    .toEqual({ item: { ...item, arguments: "[redacted]" } });
});

test("redacts ACP progress before formatting and truncating its structured output", () => {
  const key = 'provider-"quoted"-and-\\escaped-key';
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials));
  const rawOutput = { message: key, padding: "x".repeat(10_000) };
  const type = "tool_call_update";
  const frame = kernel.frame({ type, native: { update: { sessionUpdate: type, rawOutput } }, events: [
    { kind: "tool_call_progress", callId: "t", output: JSON.stringify(rawOutput).slice(0, 10_000) + "…" },
  ] });
  expect(frame.body.events[0]).toMatchObject({ output: JSON.stringify({ ...rawOutput, message: "[redacted]" }).slice(0, 10_000) + "…" });
  expect(frame.body.native).toMatchObject({ update: { rawOutput: { message: "[redacted]" } } });
});

test("ACP progress redacts joined output and holds credential prefixes across updates", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit("line-one\nline-two");
  credentials.addExplicit("fixture-token");
  credentials.addExplicit("token");
  credentials.addExplicit("red");
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials, undefined, undefined, tails));
  const tails = new Map<string, string>();
  const type = "tool_call_update";
  const progress = (rawOutput: unknown, callId: string) => kernel.frame({ type, native: { update: { sessionUpdate: type, toolCallId: callId, rawOutput } },
    events: [{ kind: "tool_call_progress", callId }] });
  const joined = progress([{ text: "line-one" }, { text: "line-two" }], "joined");
  expect(joined.body.events[0]).toMatchObject({ output: "[redacted]" });
  expect(joined.body.native).toEqual({ update: { sessionUpdate: type, toolCallId: "joined" } });
  const first = progress("before fixture-", "streamed");
  const second = progress("token after!", "streamed");
  expect(first.body.events[0]).toMatchObject({ output: "before " });
  expect(second.body.events[0]).toMatchObject({ output: "[redacted] after!" });
  expect(JSON.stringify(kernel.records())).not.toMatch(/line-one|line-two|fixture-/u);
  const opening = kernel.frame({ type: "tool_call", native: { update: {
    sessionUpdate: "tool_call", toolCallId: "opening", status: "in_progress", rawOutput: "fixture-",
  } }, events: [{ kind: "tool_call_started", callId: "opening", tool: "demo" }] });
  const continued = progress("token", "opening");
  expect(opening.body.native).not.toHaveProperty("update.rawOutput");
  expect(continued.body.native).not.toHaveProperty("update.rawOutput");
  expect(continued.body.events).toEqual([{ kind: "tool_call_progress", callId: "opening", output: "[redacted]" }]);
  expect(progress("red", "only-once").body.events).toEqual([{ kind: "tool_call_progress", callId: "only-once", output: "[redacted]" }]);
  progress("done fixture-", "unmatched");
  const ended = kernel.frame({ type, native: { update: { sessionUpdate: type, toolCallId: "unmatched", status: "completed" } },
    events: [{ kind: "tool_call_ended", callId: "unmatched" }] });
  expect(ended.body.events).toEqual([{ kind: "tool_call_progress", callId: "unmatched", output: "fixture-" },
    { kind: "tool_call_ended", callId: "unmatched" }]);
});

test("ACP keeps the JSON syntax of an already sanitized structured progress value", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit('"');
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials, undefined, undefined, new Map()));
  const type = "tool_call_update";
  const update = { sessionUpdate: type, toolCallId: "tool", rawOutput: { count: 2 } };
  const frame = kernel.frame({ type, native: { update }, events: [{ kind: "tool_call_progress", callId: "tool", output: JSON.stringify(update.rawOutput) }] });
  expect(frame.body.native).toEqual({ update });
  expect(frame.body.events).toEqual([{ kind: "tool_call_progress", callId: "tool", output: '{"count":2}' }]);
});

test("native-only ACP child progress withholds split credential fragments", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "fixture-token" } });
  const child = (_method: string, params: Record<string, unknown>) => ({
    sessionId: "child", parent: "root", update: params.update as Record<string, unknown>,
  });
  const tails = new Map<string, string>();
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials, child, undefined, tails));
  for (const rawOutput of ["fixture-", "token"]) {
    const frame = kernel.frame({ type: "opencode/session/child_update/after_answer", native: {
      update: { sessionUpdate: "tool_call_update", toolCallId: "call", status: "in_progress", rawOutput },
    }, events: [] }, { sessionId: "child" });
    expect(frame.body.native).toMatchObject({ update: { toolCallId: "call" } });
    expect(frame.body.native).not.toHaveProperty("update.rawOutput");
    expect(frame.body.events).toEqual([]);
  }
});

test("ACP withholds incomplete user text and tool argument chunks but preserves complete sanitized input", () => {
  const key = 'fixture-"quoted"-token';
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials));
  const live: RawEvent[] = [];
  kernel.rawEvents(record => { live.push(record); });
  for (const text of [key.slice(0, 11), key.slice(11)]) {
    const update = { sessionUpdate: "user_message_chunk", content: { type: "text", text } };
    const frame = kernel.frame({ type: "session/update", native: { sessionId: "child", update }, events: [] }, { sessionId: "child" });
    expect(frame.body.native).toEqual({ sessionId: "child", update: { sessionUpdate: "user_message_chunk" } });
  }
  const args = JSON.stringify({ value: key, keep: true });
  const type = "tool_call_update";
  const tool = { sessionUpdate: type, toolCallId: "tool", status: "in_progress" };
  for (const text of [args.slice(0, 18), args.slice(18)]) {
    const frame = kernel.frame({ type, native: { update: { ...tool, content: [{ type: "content", content: { type: "text", text } }] } }, events: [] });
    expect(frame.body.native).toEqual({ update: tool });
  }
  const complete = kernel.frame({ type, native: { update: { ...tool, rawInput: { value: key, keep: true } } },
    events: [{ kind: "tool_call_input", callId: "tool", input: args }] });
  expect(complete.body.native).toEqual({ update: { ...tool, rawInput: { value: "[redacted]", keep: true } } });
  expect(complete.body.events).toEqual([{ kind: "tool_call_input", callId: "tool", input: '{"value":"[redacted]","keep":true}' }]);
  expect(live).toEqual(kernel.records());
});

test.each(["claude", "codex", "dsh"] as const)("%s sanitizes native and projected joined user text", runtime => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "fixture-token" } });
  const content = [{ type: "text", text: "private sibling", "fixture-token": true },
    { type: "text", text: "before fixture-" }, { type: "text", text: "token after" }];
  const data = { content };
  const records = {
    claude: { type: "user", native: { type: "user", message: data, isReplay: true }, path: "message.content",
      redact: (record: RawEvent) => redactStreamJsonRecord(record, credentials) },
    codex: { type: "item/started", native: { item: { ...data, type: "userMessage" } }, path: "item.content",
      redact: (record: RawEvent) => redactCodexRecord(record, credentials.redactValue) },
    dsh: { type: "session/event:user/message", native: { data }, path: "data.content",
      redact: (record: RawEvent) => redactDshRecord(record, credentials) },
  };
  const { path, redact, ...frame } = records[runtime];
  const kernel = createSessionKernel("root", redact);
  const live: RawEvent[] = [];
  kernel.rawEvents(record => { live.push(record); });
  const events = [{ kind: "user_message" as const, evidence: "turn_item" as const, input: "private siblingbefore fixture-token after" }];
  const safe = kernel.frame({ ...frame, events });
  const expected = ["[redacted]", { type: "text", text: "before [redacted] after" }, { type: "text", text: "" }];
  expect(safe.body.native).toHaveProperty(path, expected);
  expect(safe.body.events).toEqual([{ ...events[0], input: "before [redacted] after" }]);
  if (runtime === "codex") {
    expect(kernel.frame({ ...frame, type: "item/completed", events: [] }).body.native).toHaveProperty(path, expected);
  }
  expect(live).toEqual(kernel.records());
});

test("Codex does not derive settings events from a withheld native map", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const native = { threadSettings: { [secret]: true, model: "private sibling" } };
  const frame = kernel.frame({ type: "thread/settings/updated", native, events: [{ kind: "model", model: "private sibling" }] });
  expect(frame.body).toEqual({ type: "thread/settings/updated", native: { threadSettings: "[redacted]" }, events: [] });
});

test.each(["thread/start", "thread/resume", "thread/fork", "session/new", "usage_update"])("%s omits views of an opaque metadata map", type => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit("_meta");
  const acp = type === "usage_update" || type === "session/new";
  const kernel = createSessionKernel("root", record => acp ? redactAcpRecord(record, credentials) : redactCodexRecord(record, credentials.redactValue));
  const events: RuntimeEventBody[] = type === "usage_update" ? [{ kind: "usage", usage: { context: { tokens: 37, contextWindow: 100, percent: 37 } } }]
    : [{ kind: "model", model: "fixture-model" }];
  const fixture = (extra: Record<string, unknown>) => type === "usage_update"
    ? { update: { sessionUpdate: type, used: 37, size: 100, ...extra } }
    : { model: "fixture-model", models: { currentModelId: "fixture-model" }, ...extra };
  expect(kernel.frame({ type, native: fixture({}), events }).body.events).toEqual(events);
  expect(kernel.frame({ type, native: fixture({ _meta: {} }), events }).body.events).toEqual([]);
});

test("ACP prompt accounting excludes a withheld report from subsequent totals", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit("privateUsage");
  const profile = { promptTokenUsage: wholePromptTokenUsage, spontaneousTokenUsage: grokSpontaneousTokens } as AcpSessionProfile;
  const usage = createAcpTokenUsage(profile, undefined, credentials.redactValue);
  expect(usage.prompt({ usage: { privateUsage: true, totalTokens: 100, inputTokens: 98, outputTokens: 2 } })).toBeNull();
  expect(usage.extension("_x.ai/session_notification", { _meta: { eventId: "withheld" }, update: {
    sessionUpdate: "turn_completed", prompt_id: "native", usage: { privateUsage: true, inputTokens: 37, outputTokens: 5 },
  } }, true)).toBeNull();
  expect(usage.prompt({ usage: { totalTokens: 10, inputTokens: 8, outputTokens: 2 } })).toMatchObject({ kind: "usage", usage: { tokens: { input: 8, output: 2 } } });
});

test("Codex and DSH preserve terminal classification without exposing a withheld reason or anchor", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit("_meta");
  const codex = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const codexEnd = codex.frame({ type: "turn/completed", native: { turn: { _meta: true, id: "private anchor", status: "completed" } },
    events: [{ kind: "turn_ended", outcome: { kind: "completed" }, forkAnchor: "private anchor" }] }, { spanId: "private anchor" });
  const codexStart = codex.frame({ type: "turn/started", native: { turn: { _meta: true, id: "private anchor" } },
    events: [{ kind: "turn_active" }] }, { spanId: "private anchor" });
  expect(codexStart).not.toHaveProperty("spanId");
  expect(codexStart.body.events).toEqual([{ kind: "turn_active" }]);
  expect(codexEnd).not.toHaveProperty("spanId");
  expect(codexEnd.body.events).toEqual([{ kind: "turn_ended", outcome: { kind: "completed" } }]);
  const dsh = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const reason = { kind: "error", error: { _meta: true, code: "SERVER", message: "private failure" } };
  const { frame } = foldDsh(initialDshProjection("root"), { type: "native", channel: "session/event", event: { type: "turn/end", data: { reason } } });
  expect(dsh.frame(frame.body).body.events).toEqual([{ kind: "turn_ended", outcome: {
    kind: "failed", failure: "provider", reason: "DSH reported a failed turn",
  } }]);
});

test("ACP configuration updates do not publish values from withheld rows", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials));
  const type = "config_option_update";
  const row = { id: "model", type: "select", currentValue: "fixture-model" };
  const events: RuntimeEventBody[] = [{ kind: "model", model: "fixture-model" }];
  const frame = (configOption: unknown) => kernel.frame({ type, native: { update: { sessionUpdate: type, configOptions: [configOption] } }, events });
  expect(frame(row).body.events).toEqual(events);
  expect(frame({ ...row, [secret]: true }).body.events).toEqual([]);
});

test("ACP config confirmation compares private values and omits withheld diagnostic fields", async () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const updates = createAcpConfigUpdates(credentials.redactValue);
  const publish = (value: string) => updates.observe({ sessionId: "root", update: { sessionUpdate: "config_option_update", configOptions: [
    { id: "model", currentValue: value, [secret]: true },
  ] } });
  await expect(updates.confirm("root", "model", "expected", async wait => {
    publish("expected");
    await wait(new AbortController().signal);
    return "confirmed";
  })).resolves.toBe("confirmed");
  const error = await updates.confirm("root", "model", "expected", async () => {
    publish("private sibling");
    throw acpRequestTimeoutError("session/set_config_option", 1);
  }).catch(reason => reason);
  expect(error).toMatchObject({ message: "ACP config_option_update did not confirm requested model", reported: null });
});

test("DSH withholds model, job and queue identities from opaque records", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const base = initialDshProjection("root");
  const native = (type: string, data: unknown) => ({ type: "native", channel: "session/event", event: { type, data } });
  const model = { [secret]: true, provider: "sample", model: "private sibling" };
  expect(kernel.frame(dshOpenedFrame({ model })).body.events).toEqual([]);
  expect(kernel.frame(foldDsh(base, native("request/header", { header: { config: model } })).frame.body).body.events).toEqual([]);
  const job = native("job/registered", { [secret]: true, jobId: "private job", owner: "root", label: "private label" });
  expect(kernel.frame(foldDsh(base, job).frame.body).body.events).toEqual([]);
  const splice = (inserted: unknown[], removedCount: number) => native("agent/inbox/spliced", { inserted, removedCount, start: 0 });
  const queued = foldDsh(base, splice([{ id: "private input", [secret]: true }, { id: "public input" }], 0), credentials);
  const claimed = foldDsh(queued.state, splice([], 2), credentials);
  expect(kernel.frame(claimed.frame.body).body.events).toEqual([{ kind: "turn_active", inputId: "public input" }]);
});

test("DSH discards events and state changes from a withheld event data map", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const live: RawEvent[] = [];
  kernel.rawEvents(record => { live.push(record); });
  const base = initialDshProjection("root");
  const event = (type: string, data: Record<string, unknown>) => ({ type: "native", channel: "session/event", event: { type, data } });
  const cases = [
    event("subagent/catalog", { childId: "private-child", [secret]: true }),
    event("compaction/end", { compactionId: "private-compaction", error: "private-error", [secret]: true }),
    event("user/message", { id: "private-input", source: { kind: "user" }, content: "private-input-text", [secret]: true }),
  ];
  for (const message of cases) {
    const folded = foldDsh(base, message, credentials);
    expect(folded.state.links).toEqual(base.links);
    expect(folded.frame.body.events).toEqual([]);
    expect(kernel.frame(foldDsh(base, message).frame.body).body.events).toEqual([]);
  }
  const splice = (data: Record<string, unknown>) => event("agent/inbox/spliced", data);
  const queued = foldDsh(base, splice({ start: 0, removedCount: 0, inserted: [{ id: "first" }, { id: "second" }] }), credentials);
  const withheld = foldDsh(queued.state, splice({ start: 1, removedCount: 1, outcome: "canceled", [secret]: true }), credentials);
  expect(withheld.state).toEqual(queued.state);
  expect(kernel.frame(withheld.frame.body).body.events).toEqual([]);
  const claim = foldDsh(withheld.state, splice({ start: 1, removedCount: 1, inserted: [] }), credentials);
  expect(kernel.frame(claim.frame.body).body.events).toEqual([{ kind: "turn_active", inputId: "second" }]);
  expect(kernel.graph().edges).toEqual([]);
  expect(live).toEqual(kernel.records());
  expect(JSON.stringify(live)).not.toContain("private-");
});

test("DSH never accounts for withheld usage or emits a withheld goal", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const base = initialDshProjection("root");
  const message = (usage: unknown) => ({ type: "native", channel: "session/event", event: { type: "assistant/message", data: { usage } } });
  const opaque = message({ inputTokens: 37, outputTokens: 5, [secret]: true });
  const first = foldDsh(base, opaque, credentials);
  expect(kernel.frame(first.frame.body).body.events).toEqual([]);
  expect(kernel.frame(foldDsh(base, opaque).frame.body).body.events).toEqual([]);
  const next = foldDsh(first.state, message({ inputTokens: 2, outputTokens: 1 }), credentials);
  expect(kernel.frame(next.frame.body).body.events).toEqual([{ kind: "usage", usage: { tokens: { input: 2, output: 1 } } }]);
  const goal = foldDsh(next.state, { type: "native", channel: "session/event", event: { type: "goal/change", data: {
    version: 1, cleared: {}, goal: { objective: "private sibling", phase: "active", [secret]: true },
  } } }, credentials);
  expect(kernel.frame(goal.frame.body).body.events).toEqual([]);
});

test("Codex omits goal and usage projections when their source objects are withheld", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const live: RawEvent[] = [];
  kernel.rawEvents(record => { live.push(record); });
  const goal = { objective: "fixture sibling", status: "active" };
  const goalFrame = (nativeGoal: unknown) => kernel.frame({ type: "thread/goal/updated", native: { goal: nativeGoal },
    events: [{ kind: "goal_changed", goal }] });
  const usage = { context: { tokens: 17, contextWindow: null, percent: null }, tokens: { input: 17, output: 4 } };
  const usageFrame = (extension: Record<string, unknown>) => kernel.frame({ type: "thread/tokenUsage/updated", native: {
    tokenUsage: { total: { inputTokens: 17, outputTokens: 4, ...extension } },
  }, events: [{ kind: "usage", usage }] });
  expect(goalFrame({ ...goal, [secret]: true }).body.events).toEqual([]);
  expect(usageFrame({ [secret]: true }).body.events).toEqual([]);
  expect(goalFrame(goal).body.events).toEqual([{ kind: "goal_changed", goal }]);
  expect(usageFrame({}).body.events).toEqual([{ kind: "usage", usage }]);
  const fromSpan = (fields: Record<string, unknown>) => kernel.frame({ type: "thread/tokenUsage/updated", native: { turnId: "test-span", ...fields }, events: [] }, { spanId: "test-span" });
  expect(fromSpan({ [secret]: true })).not.toHaveProperty("spanId");
  expect(fromSpan({})).toHaveProperty("spanId", "test-span");
  expect(live).toEqual(kernel.records());
});

test("Codex raw reasoning retains safe neighboring text and redacts joined content", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit("fixture-token");
  credentials.addExplicit("line-one\nline-two");
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const item = { type: "reasoning", summary: [
    { type: "summary_text", text: "private sibling", "fixture-token": true }, { type: "summary_text", text: "public" },
    { type: "summary_text", text: "line-one" },
  ], content: [{ type: "reasoning_text", text: "line-two" }] };
  const frame = kernel.frame({ type: "rawResponseItem/completed", native: { item }, events: [
    { kind: "reasoning", content: { kind: "text", text: "private sibling\npublic\nline-one\nline-two" } },
  ] });
  expect(frame.body.events).toEqual([{ kind: "reasoning", content: { kind: "text", text: "public\n[redacted]" } }]);
  expect(JSON.stringify(kernel.records())).not.toMatch(/line-one|line-two|private sibling/u);
});

test("Codex decodes raw function arguments and omits withheld user message text", () => {
  const key = 'fixture-"quoted"-token';
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const live: RawEvent[] = [];
  kernel.rawEvents(record => { live.push(record); });
  const args = JSON.stringify({ value: key, keep: true });
  const raw = kernel.frame({ type: "rawResponseItem/completed", native: { item: { type: "function_call", arguments: args } }, events: [] });
  expect(raw.body.native).toEqual({ item: { type: "function_call", arguments: '{"value":"[redacted]","keep":true}' } });
  const user = kernel.frame({ type: "item/started", native: { item: { type: "userMessage", id: "m", content: [
    { type: "text", text: "private sibling", [key]: true }, { type: "text", text: "allowed" },
  ] } }, events: [{ kind: "user_message", input: "private siblingallowed", evidence: "turn_item" }] });
  expect(user.body.events).toEqual([{ kind: "user_message", input: "allowed", evidence: "turn_item" }]);
  expect(live).toEqual(kernel.records());
  expect(JSON.stringify(live)).not.toContain("private sibling");
});

test("Codex protects joined user text in native replies, thread events, and raw message items", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "fixture-token" } });
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const live: RawEvent[] = [];
  kernel.rawEvents(record => { live.push(record); });
  const textBlocks = (type: string) => [{ type, text: "before fixture-" }, { type, text: "token after" }];
  const expected = (type: string) => [{ type, text: "before [redacted] after" }, { type, text: "" }];
  const turn = { id: "turn", items: [{ type: "userMessage", content: textBlocks("text") }] };
  const request = kernel.request("toRuntime", { kind: "prompt", input: "hello" });
  const response = kernel.respond(request.id, { kind: "accepted", native: { turn } });
  const thread = kernel.frame({ type: "thread/started", native: { thread: { turns: [turn] } }, events: [] });
  const raw = kernel.frame({ type: "rawResponseItem/completed", native: { item: { type: "message", role: "user", content: textBlocks("input_text") } }, events: [] });
  expect(response.body).toHaveProperty("native.turn.items.0.content", expected("text"));
  expect(thread.body.native).toHaveProperty("thread.turns.0.items.0.content", expected("text"));
  expect(raw.body.native).toHaveProperty("item.content", expected("input_text"));
  expect(live).toEqual(kernel.records());
});

test("DSH builds a recorded user message from surviving text blocks", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const { frame } = foldDsh(initialDshProjection("root"), { type: "native", channel: "session/event", event: {
    type: "user/message", data: { id: "m", source: { kind: "user" }, content: [
      { type: "text", text: "private sibling", [secret]: true }, { type: "text", text: "allowed" },
    ] },
  } });
  const safe = kernel.frame(frame.body);
  expect(safe.body.events).toEqual([expect.objectContaining({ kind: "user_message", input: "allowed" })]);
  expect(JSON.stringify(kernel.records())).not.toContain("private sibling");
});

test.each(["content", "rawOutput"] as const)("redacts ACP terminal %s before truncating text", (source) => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials));
  const prefix = "x".repeat(10_001 - secret.length);
  const text = prefix + secret;
  const update = { sessionUpdate: "tool_call_update", status: "completed",
    ...(source === "content" ? { content: [{ type: "content", content: { type: "text", text } }] } : { rawOutput: text }),
  };
  const frame = kernel.frame({ type: "tool_call_update", native: { update }, events: [
    { kind: "tool_call_ended", callId: "t", content: [{ type: "text", text: text.slice(0, 10_000) + "…" }] },
  ] });
  expect(frame.body.events[0]).toMatchObject({ content: [{ type: "text", text: prefix + "[redacted]" }] });
});

test.each(["is_error", "fast_mode_state", "structured_output"])("Claude keeps authoritative result fields when %s is a protected value", key => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials));
  const native = { type: "result", subtype: "success", is_error: false, [key]: false, result: key, opaque: { [key]: true } };
  const frame = kernel.frame({ type: "result/success", native, events: [{ kind: "turn_ended", outcome: { kind: "completed" } }] });
  expect(frame.body.native).toEqual({ ...native, result: "[redacted]", opaque: "[redacted]" });
  expect(frame.body.events).toEqual([{ kind: "turn_ended", outcome: { kind: "completed" } }]);
});

test("keeps Claude tool-result identities and provider context fields at their protocol paths", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "tool_use_id", MCP_TOKEN: "contextWindow" } });
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials));
  const result = { type: "result", is_error: false, modelUsage: { synthetic: { contextWindow: 200_000 } }, structured_output: { contextWindow: 1 } };
  expect(kernel.frame({ type: "result", native: result, events: [] }).body.native).toEqual({ ...result, structured_output: "[redacted]" });
  const native = { type: "user", parent_tool_use_id: null, message: { content: [{ type: "tool_result", tool_use_id: "t", content: "ok" }] }, extension: { tool_use_id: "opaque" } };
  expect(kernel.frame({ type: "user", native, events: [] }).body.native).toEqual({ ...native, extension: "[redacted]" });
  const assistant = { type: "assistant", parent_tool_use_id: null, message: { content: [{ type: "tool_use", id: "t", name: " Read", input: {} }] } };
  const usage = { kind: "usage" as const, usage: { context: { tokens: 41, contextWindow: 200_000, percent: 0 } } };
  expect(kernel.frame({ type: "assistant", native: assistant, events: [usage] }).body).toEqual({ type: "assistant", native: assistant, events: [usage] });
});

test("uses only the owning Codex item fields for protocol key protection", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "aggregatedOutput" } });
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const item = { type: "commandExecution", id: "tool", aggregatedOutput: "normal" };
  expect(kernel.frame({ type: "item/completed", native: { item }, events: [] }).body.native).toEqual({ item });
  expect(kernel.frame({ type: "item/completed", native: { item: { ...item, type: "vendor/item" } }, events: [] }).body.native)
    .toEqual({ item: "[redacted]" });
});

test("withholds a Codex usage field at the wrong notification path", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "tokenUsage" } });
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const native = { threadId: "root", tokenUsage: { total: { inputTokens: 7 } } };
  expect(kernel.frame({ type: "thread/tokenUsage/updated", native, events: [] }).body.native).toEqual(native);
  expect(kernel.frame({ type: "item/agentMessage/delta", native: { ...native, delta: "opaque" }, events: [] }).body.native).toBe("[redacted]");
});

test("Claude preserves native token counters and withholds coinciding opaque keys", () => {
  const key = "cache_read_input_tokens";
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials));
  const native = { type: "result", is_error: false, usage: { input_tokens: 9, [key]: 2, output_tokens: 3 }, structured_output: { [key]: 0 } };
  expect(kernel.frame({ type: "result", native, events: [] }).body.native).toEqual({ ...native, structured_output: "[redacted]" });
});

test("redacts repeated self-overlapping credentials before retaining streamed text", () => {
  const key = "ab".repeat(10);
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  let pending = "";
  let live = "";
  for (let i = 0; i < 32; i++) {
    const redacted = credentials.redactChunk(pending + "ab");
    live += redacted.ready;
    pending = redacted.pending;
    expect(pending.length).toBeLessThan(key.length);
  }
  expect(live + credentials.redact(pending)).toBe(credentials.redact("ab".repeat(32)));
  expect(live).toBe("[redacted]".repeat(3));
});

test("holds an entire shorter credential until an overlapping longer match can be determined", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "fixture-token", MCP_TOKEN: "fixture-token-private" } });
  const first = credentials.redactChunk("say fixture-token");
  expect(first).toEqual({ ready: "say ", pending: "fixture-token" });
  expect(credentials.redactChunk(first.pending + "-private")).toEqual({ ready: "[redacted]", pending: "" });
});

test.each([['say fi', 'nal', 'say final'], ['say fi', 'xture-token', 'say [redacted]']])("Claude projected deltas reconcile %s with the assistant snapshot", (draft, remainder, expected) => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "fixture-token", MCP_TOKEN: "api_message_id" } });
  const tails = { drafts: new Map<string, string>(), assistant: new Map<string, string>(), projected: new Map<string, string>(), messages: new Map() };
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials, tails));
  kernel.frame({ type: "assistant", native: { type: "assistant", message: { id: "prior", content: [{ type: "text", text: "Earlier." }] } }, events: [] });
  const native = { type: "stream_event", api_message_id: "m", event: { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: draft } } };
  expect(kernel.frame({ type: "stream_event", native, events: [{ kind: "text_delta", text: draft }] }).body.native)
    .toMatchObject({ api_message_id: "m", event: { delta: { text: "say " } } });
  kernel.frame({ type: "assistant", native: { type: "assistant", message: { id: "m", content: [{ type: "text", text: draft + remainder }] } },
    events: [{ kind: "text_delta", text: remainder }] });
  const text = kernel.records().flatMap(record => record.kind === "frame"
    ? record.body.events.flatMap(event => event.kind === "text_delta" ? [event.text] : []) : []);
  expect(text.join("")).toBe(expected);
});

test("Claude keeps split thinking fragments out of retained events and redacts initial text plus deltas", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const tails = { drafts: new Map<string, string>(), assistant: new Map<string, string>(), projected: new Map<string, string>(), messages: new Map() };
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials, tails));
  const chunk = (event: unknown, projected: RuntimeEventBody) =>
    kernel.frame({ type: "stream_event", native: { type: "stream_event", event }, events: [projected] });
  const first = secret.slice(0, 12);
  const second = secret.slice(12);
  for (const thinking of [first, second]) expect(chunk({ type: "content_block_delta", index: 1, delta: { type: "thinking_delta", thinking } },
    { kind: "reasoning", content: { kind: "text", text: thinking } }).body.events).toEqual([]);
  expect(chunk({ type: "content_block_start", index: 0, content_block: { type: "text", text: first } }, { kind: "text_delta", text: first }).body.events).toEqual([]);
  expect(chunk({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: second } }, { kind: "text_delta", text: second }).body.events)
    .toEqual([{ kind: "text_delta", text: "[redacted]" }]);
  expect(JSON.stringify(kernel.records())).not.toContain(second);
});

test("Claude applies one stream replacement across text blocks and withholds partial reasoning snapshots", () => {
  const key = "fixture-token";
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key, MCP_TOKEN: "prefix[redacted]suffix-xyz" } });
  const tails = { drafts: new Map<string, string>(), assistant: new Map<string, string>(), projected: new Map<string, string>(), messages: new Map() };
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials, tails));
  const delta = (index: number, text: string) => kernel.frame({ type: "stream_event", native: { type: "stream_event", event: {
    type: "content_block_delta", index, delta: { type: "text_delta", text },
  } }, events: [{ kind: "text_delta", text }] });
  expect(delta(0, "prefixfixture-").body.native).toMatchObject({ event: { delta: { text: "prefix" } } });
  const second = delta(1, "tokensuffix-xyz");
  const sibling = kernel.frame({ type: "stream_event", native: { type: "stream_event", event: {
    type: "content_block_delta", index: 1, delta: { type: "text_delta", text: "ordinary" }, content_block: { text: key },
  } }, events: [{ kind: "text_delta", text: "ordinary" }] });
  expect(sibling.body.native).toMatchObject({ event: { content_block: { text: "[redacted]" } } });
  expect(second.body.native).toMatchObject({ event: { delta: { text: "[redacted]suffix-xyz" } } });
  expect(second.body.events).toEqual([{ kind: "text_delta", text: "[redacted]suffix-xyz" }]);
  const thinking = { type: "assistant", message: { id: "m", content: [{ type: "thinking", thinking: key }] } };
  expect(kernel.frame({ type: "assistant", native: thinking, events: [{ kind: "reasoning", content: { kind: "text", text: "token" } }] }).body)
    .toEqual({ type: "assistant", native: { type: "assistant", message: { id: "m", content: [{ type: "thinking" }] } }, events: [] });
});

test("Codex redacts a credential reconstructed by formatting a tool error", () => {
  const key = "error: fixture-marker";
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const native = { item: { type: "mcpToolCall", id: "tool", error: { message: "fixture-marker", extra: key } } };
  const frame = kernel.frame({ type: "item/completed", native, events: [
    { kind: "tool_call_ended", callId: "tool", content: [{ type: "text", text: key }] },
  ] });
  expect(frame.body.events).toEqual([{ kind: "tool_call_ended", callId: "tool", content: [{ type: "text", text: "[redacted]" }] }]);
});

test.each(["claude", "acp", "dsh", "codex"] as const)("%s withholds tool payloads derived from an opaque native object", runtime => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const sibling = "private-tool-sibling";
  const start = { kind: "tool_call_started" as const, callId: "c", tool: "demo", input: JSON.stringify({ sibling }) };
  const blocks = { type: "tool_use", id: "c", name: "demo", input: { sibling }, [secret]: true };
  const frames = {
    claude: { type: "assistant", native: { type: "assistant", message: { content: [blocks] } }, events: [start],
      redact: (record: RawEvent) => redactStreamJsonRecord(record, credentials) },
    acp: { type: "tool_call", native: { update: { sessionUpdate: "tool_call", toolCallId: "c", rawInput: { sibling }, [secret]: true } }, events: [start],
      redact: (record: RawEvent) => redactAcpRecord(record, credentials) },
    dsh: { type: "session/event:tool/call", native: { data: { callId: "c", name: sibling, arguments: JSON.stringify({ sibling }), [secret]: true } }, events: [{ ...start, tool: sibling }],
      redact: (record: RawEvent) => redactDshRecord(record, credentials) },
    codex: { type: "item/completed", native: { item: { id: "c", type: "mcpToolCall", result: { content: [{ type: "text", text: sibling }], [secret]: true } } },
      events: [{ kind: "tool_call_ended" as const, callId: "c", content: [{ type: "text" as const, text: sibling }] }],
      redact: (record: RawEvent) => redactCodexRecord(record, credentials.redactValue) },
  };
  const { redact, ...frame } = frames[runtime];
  const kernel = createSessionKernel("root", redact);
  const live: RawEvent[] = [];
  kernel.rawEvents(record => { live.push(record); });
  kernel.frame(frame);
  expect(live).toEqual(kernel.records());
  expect(JSON.stringify(live)).toContain("[redacted]");
  expect(JSON.stringify(live)).not.toContain(sibling);
});

test.each(["claude", "dsh"] as const)("%s projects surviving tool result blocks after native withholding", runtime => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const block = { type: "text" as const, text: "private sibling", [secret]: true };
  const allowed = { type: "text" as const, text: "adjacent clean result" };
  const content = [block, allowed];
  const source = runtime === "claude"
    ? { type: "user", native: { type: "user", message: { content: [{ type: "tool_result", tool_use_id: "c", content }] } } }
    : { type: "session/event:tool/result", native: { data: { message: { toolCallId: "c", content } } } };
  const kernel = createSessionKernel("root", record => runtime === "claude" ? redactStreamJsonRecord(record, credentials) : redactDshRecord(record, credentials));
  const frame = kernel.frame({ ...source, events: [{ kind: "tool_call_ended", callId: "c", content: [{ type: "text", text: block.text }, allowed] }] });
  expect(frame.body.events).toEqual([{ kind: "tool_call_ended", callId: "c", content: [{ type: "other", value: "[redacted]" }, allowed] }]);
  expect(JSON.stringify(kernel.records())).not.toContain(block.text);
});

test("ACP omits an exit code derived from an opaque raw output object", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials));
  const type = "tool_call_update";
  const allowed = { type: "text" as const, text: "safe ACP output" };
  const frame = kernel.frame({ type, native: { update: { sessionUpdate: type, status: "completed", rawOutput: { [secret]: true, exit_code: 37 },
    content: [{ type: "content", content: allowed }] } }, events: [{ kind: "tool_call_ended", callId: "c", exitCode: 37, content: [allowed] }] });
  expect(frame.body.events).toEqual([{ kind: "tool_call_ended", callId: "c", content: [allowed] }]);
});

test("ACP preserves a native withheld content object and omits its derived text", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials, undefined, new Map()));
  const type = "agent_message_chunk";
  const content = { type: "text", text: "visible sibling", [secret]: "private" };
  const frame = kernel.frame({ type, native: { update: { sessionUpdate: type, content } }, events: [{ kind: "text_delta", text: content.text }] });
  expect(frame.body).toEqual({ type, native: { update: { sessionUpdate: type, content: "[redacted]" } }, events: [] });
});

test("DSH assembled text is redacted exactly once", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret, MCP_TOKEN: "prefix[redacted]suffix-xyz" } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  const native = { data: { message: { content: [
    { type: "text", text: `prefix${secret}suffix-xyz` },
    { type: "text", text: "PRIVATE-SIBLING", [secret]: true },
  ] } } };
  expect(kernel.frame({ type: "session/event:assistant/message", native, events: [] }).body.native).toEqual({
    data: { message: { content: [{ type: "text", text: "prefix[redacted]suffix-xyz" }, "[redacted]"] } },
  });
});

test("Claude never buffers a withheld text block for a later record", () => {
  const key = "fixture-token";
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const tails = { drafts: new Map<string, string>(), assistant: new Map<string, string>(), projected: new Map<string, string>(), messages: new Map() };
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials, tails));
  const text = "fixture-";
  const events = [{ kind: "text_delta" as const, text }];
  const draft = kernel.frame({ type: "stream_event", native: { type: "stream_event", event: {
    type: "content_block_delta", index: 0, delta: { type: "text_delta", text, [key]: true },
  } }, events });
  expect(draft.body).toMatchObject({ native: { event: { delta: "[redacted]" } }, events: [] });
  const snapshot = kernel.frame({ type: "assistant", native: { type: "assistant", message: { id: "m", content: [
    { type: "text", text, [key]: true },
  ] } }, events });
  expect(snapshot.body).toMatchObject({ native: { message: { content: ["[redacted]"] } }, events: [] });
  const result = kernel.frame({ type: "result/success", native: { type: "result", subtype: "success" }, events: [] });
  expect(result.body.events).toEqual([]);
  expect(result.body).not.toHaveProperty("byokTextTail");
});

test("Claude elides a sanitized result fallback under retainedBytes", () => {
  const name = "custom_extension";
  const credentials = sessionCredentialRedactor({ env: { API_KEY: name } });
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials), 64);
  kernel.frame({ type: "result/success", native: { type: "result", subtype: "success", is_error: false,
    [name]: name, structured_output: "x".repeat(256),
  }, events: [] });
  kernel.frame({ type: "system", native: {}, events: [] });
  expect(kernel.records()[0]?.body).toMatchObject({ elided: true, native: null });
  expect(kernel.records()[0]?.body).not.toHaveProperty("byokResult");
});

test("Claude retains terminal evidence when an unknown native key is withheld", () => {
  const secretKey = "custom_extension";
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secretKey } });
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials));
  const native = { type: "result", subtype: "success", is_error: false, [secretKey]: secretKey, result: secretKey };
  expect(kernel.frame({ type: "result/success", native, events: [] }).body).toMatchObject({ native: "[redacted]",
    byokResult: { type: "result", subtype: "success", is_error: false, result: "[redacted]" } });
});

test("DSH withholds text and reasoning fragments while retaining attempt metadata", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: secret } });
  const kernel = createSessionKernel("root", record => redactDshRecord(record, credentials));
  for (const [index, type] of ["text-delta", "reasoning-delta"].entries()) {
    for (const fragment of [secret.slice(0, 12), secret.slice(12)]) {
      const { frame } = foldDsh(initialDshProjection("root"), { type: "native", channel: "agent/assistant-stream", frame: {
        attemptId: `attempt-${index}`, chunk: { type, text: fragment },
      } });
      expect(kernel.frame(frame.body).body).toEqual({ type: "agent/assistant-stream",
        native: { attemptId: `attempt-${index}`, chunk: { type } }, events: [] });
    }
  }
});

test("redacts a reserved Claude event enum in opaque result data", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "content_block_start" } });
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials));
  const native = { event: { type: "content_block_start" } };
  expect(kernel.frame({ type: "result", native: { ...native, type: "result" }, events: [] }).body.native)
    .toEqual({ type: "result", event: { type: "[redacted]" } });
  expect(kernel.frame({ type: "stream_event", native: { ...native, type: "stream_event" }, events: [] }).body.native)
    .toEqual({ ...native, type: "stream_event" });
});

test("redacts a reserved Codex item enum in opaque notifications", () => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: "commandExecution" } });
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const native = { item: { type: "commandExecution" } };
  expect(kernel.frame({ type: "vendor/custom", native, events: [] }).body.native).toEqual({ item: { type: "[redacted]" } });
  expect(kernel.frame({ type: "item/started", native, events: [] }).body.native).toEqual(native);
});

test("ACP keeps tool status at the protocol boundary and redacts opaque extension status", () => {
  const credentials = sessionCredentialRedactor({ env: { MCP_TOKEN: "completed" } });
  const kernel = createSessionKernel("root", record => redactAcpRecord(record, credentials));
  const update = { sessionUpdate: "tool_call_update", status: "completed", rawOutput: { status: "completed" } };
  expect(kernel.frame({ type: "tool_call_update", native: { update }, events: [] }).body.native)
    .toEqual({ update: { ...update, rawOutput: { status: "[redacted]" } } });
  expect(kernel.frame({ type: "vendor/custom", native: { update }, events: [] }).body.native)
    .toEqual({ update: { ...update, status: "[redacted]", rawOutput: { status: "[redacted]" } } });
});

test.each(["error_during_execution", "aborted_streaming", "aborted_tools"])("Claude preserves authoritative result enum %s and redacts it in prose", (key) => {
  const credentials = sessionCredentialRedactor({ env: { API_KEY: key } });
  const kernel = createSessionKernel("root", record => redactStreamJsonRecord(record, credentials));
  const native = { type: "result", subtype: "error_during_execution", terminal_reason: key === "aborted_tools" ? key : "aborted_streaming", result: key };
  expect(kernel.frame({ type: "result/error_during_execution", native, events: [] }).body.native)
    .toEqual({ ...native, result: "[redacted]" });
});

test.each(["completed", "interrupted", "failed"])("Codex preserves the authoritative turn status %s and redacts coincident content", (status) => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit(status);
  const kernel = createSessionKernel("root", record => redactCodexRecord(record, credentials.redactValue));
  const native = { turn: { status, error: { message: status } } };
  expect(kernel.frame({ type: "turn/completed", native, events: [] }).body.native)
    .toEqual({ turn: { status, error: { message: "[redacted]" } } });
});

test("redacts ACP extension metadata before retention and observer delivery", () => {
  const credentials = sessionCredentialRedactor({});
  credentials.addExplicit(secret);
  const kernel = createSessionKernel("session", credentials.redactValue);
  const live: RawEvent[] = [];
  kernel.rawEvents(record => { live.push(record); });
  kernel.frame({ type: "tool_call_update", events: [], native: { update: { _meta: { extension: { status: secret } } } } });
  const native = { update: { _meta: { extension: { status: "[redacted]" } } } };
  expect(kernel.records()).toEqual([expect.objectContaining({ body: expect.objectContaining({ native }) })]);
  expect(live).toEqual(kernel.records());
});

test("opening failures redact frozen native Error fields and cause data while preserving their class", async () => {
  const native: RuntimeFailureError = Object.freeze(new RuntimeFailureError("auth", secret, { cause: { message: secret, nested: [secret] } }));
  const open = withSessionCredentials(async () => { throw native; });
  const failure: unknown = await open({ kind: "available", via: "bundled" }, { cwd: "/work", env: { API_KEY: secret } }).catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(RuntimeFailureError);
  expect(failure).toMatchObject({ failure: "auth", reason: "[redacted]", cause: { message: "[redacted]", nested: ["[redacted]"] } });
  expect(failure instanceof Error ? failure.stack : undefined).toContain("[redacted]");
  expect(inspect(failure, { depth: null })).not.toContain(secret);
  expect(JSON.stringify(failure)).not.toContain(secret);
  expect(native.message).toBe(secret);
});

test("errors from later session methods use the same redactor", async () => {
  const open = withSessionCredentials(async (_installation, _options, credentials) => {
    const kernel = credentials.kernel("session");
    return credentials.seal({
      id: kernel.sessionId,
      capabilities: { queue: { durable: false }, attribution: "attributed", images: false },
      prompt: async () => { throw new Error(secret, { cause: { detail: secret } }); },
      // oxlint-disable-next-line typescript/only-throw-error -- Native APIs can throw a string; exercise that error boundary too.
      queue: async () => { throw secret; },
      stopTask: async () => { throw new Error(secret, { cause: { detail: secret } }); },
      abort: async () => kernel.control({ kind: "abort" }, () => ({ kind: "accepted" })),
      dispose: async () => { throw new Error(secret); },
      rawEvents: (observer, cursor) => kernel.rawEvents(observer, cursor),
      records: () => kernel.records(),
      graph: () => kernel.graph(),
    });
  });
  const session = await open({ kind: "available", via: "bundled" }, { cwd: "/work", env: { API_KEY: secret } });
  await expect(session.prompt("hello")).rejects.toMatchObject({ message: "[redacted]", cause: { detail: "[redacted]" } });
  await expect(session.queue("hello")).rejects.toBe("[redacted]");
  await expect(session.stopTask?.("child")).rejects.toMatchObject({ message: "[redacted]", cause: { detail: "[redacted]" } });
  await expect(session.dispose()).rejects.toThrow("[redacted]");
});


test.each([{}, { API_KEY: secret }])("retains unmatched frame objects without copying (env %j)", (env) => {
  const { redactValue } = sessionCredentialRedactor({ cwd: "/work", env });
  const kernel = createSessionKernel("session", redactValue);
  const body = { type: "tool/output", native: { output: "ordinary output", nested: ["unchanged"] }, events: [] };
  const frame = kernel.frame(body);
  expect(frame.body).toBe(body);
  expect(kernel.records()[0]).toBe(frame);
  expect(redactValue(frame)).toBe(frame);
});

test("a key learned after opening enables redaction for subsequent records", () => {
  const { redactValue, add } = sessionCredentialRedactor({ cwd: "/work" });
  const kernel = createSessionKernel("session", redactValue);
  const body = { type: "native/error", native: { message: secret }, events: [] };
  expect(kernel.frame(body).body).toBe(body);
  add(secret);
  expect(kernel.frame(body).body.native).toEqual({ message: "[redacted]" });
  expect(body.native.message).toBe(secret);
});


test.each(["ollama", "EMPTY", "none", "x", "/path/to/credential", "~/credential", String.raw`C:\credentials\key`])("ignores short or path-shaped SDK key %s", (key) => {
  const { add, redactValue } = sessionCredentialRedactor({ cwd: "/work" });
  add(key);
  const native = { model: `${key}/model`, text: `provider ${key}` };
  expect(redactValue(native)).toBe(native);
});


test("MCP ordinary env and headers remain unchanged in records and error text", () => {
  const servers = [
    { name: "local", command: "echo", env: { DEBUG: "true", LOG_LEVEL: "debug", NODE_ENV: "production", TOKEN: "short", SECRET: "/path/to/secret" } },
    { name: "remote", type: "http" as const, url: "http://localhost", headers: { "Content-Type": "application/json" } },
  ];
  const { redactValue } = sessionCredentialRedactor({ cwd: "/work", mcpServers: servers });
  const kernel = createSessionKernel("session", redactValue);
  const body = { type: "tool/output", native: { text: "debug is true in production, application/json, short, /path/to/secret" }, events: [] };
  expect(kernel.frame(body).body).toBe(body);
  expect(mcpCredentialRedactor(servers)(body.native.text)).toBe(body.native.text);
});

test.each(["Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "Api-Key", "X-Service-Token", "x-custom-secret"])("MCP credential header %s uses shared record and error redaction", (name) => {
  const servers = [{ name: "remote", type: "http" as const, url: "http://localhost", headers: { [name]: secret } }];
  const { redactValue } = sessionCredentialRedactor({ mcpServers: servers });
  expect(redactValue({ text: secret })).toEqual({ text: "[redacted]" });
  expect(mcpCredentialRedactor(servers)(secret)).toBe("[redacted]");
});

test.each(["Bearer", "Basic", "Token"])("MCP Authorization %s protects its complete value and bare credential", (scheme) => {
  const value = `${scheme} ${secret}`;
  const servers = [{ name: "remote", type: "http" as const, url: "http://localhost", headers: { Authorization: value } }];
  const { redactValue } = sessionCredentialRedactor({ mcpServers: servers });
  const native = { full: value, bare: secret, ordinary: "application/json" };
  expect(redactValue(native)).toEqual({ full: "[redacted]", bare: "[redacted]", ordinary: "application/json" });
  expect(mcpCredentialRedactor(servers)(`${value}; ${secret}`)).toBe("[redacted]; [redacted]");
});


test.each([false, true])("env connection strings protect full URLs and encoded/decoded passwords (MCP=%s)", (mcp) => {
  const encoded = "oar%3Along-password%2Ffor-db";
  const decoded = "oar:long-password/for-db";
  const env = { DATABASE_URL: `postgres://user:${encoded}@localhost/db`, MONGODB_URI: `mongodb+srv://user:${secret}@localhost/db`, REDIS_URL: `redis://:${secret}@localhost:6379`, PUBLIC_URL: "http://localhost:3000" };
  const options = mcp ? { mcpServers: [{ name: "db", command: "echo", env }] } : { env };
  const { redactValue } = sessionCredentialRedactor(options);
  expect(redactValue({ urls: Object.values(env), encoded, decoded, password: secret })).toEqual({ urls: ["[redacted]", "[redacted]", "[redacted]", "http://localhost:3000"], encoded: "[redacted]", decoded: "[redacted]", password: "[redacted]" });
});

test("connection URLs with short passwords redact only the whole URL", () => {
  const url = "postgres://user:pass@localhost/db";
  const { redact } = sessionCredentialRedactor({ env: { DATABASE_URL: url } });
  expect(redact(`${url}; tests pass`)).toBe("[redacted]; tests pass");
});

test("readEnvironmentCredential registers inherited runtime credentials with case-insensitive Windows lookup and URL rules", () => {
  const redactor = sessionCredentialRedactor({});
  expect(readEnvironmentCredential({ qoder_personal_access_token: secret }, "QODER_PERSONAL_ACCESS_TOKEN", redactor, "win32")).toBe(secret);
  rememberEnvironmentCredentials(redactor, { CURSOR_API_KEY: "short", SERVICE_URL: `https://user:${secret}-db@example.test/api` }, ["CURSOR_API_KEY", "SERVICE_URL"]);
  expect(redactor.redact(`seen ${secret} and ${secret}-db and short`)).toBe("seen [redacted] and [redacted] and short");
});


test.each(["create", "refusal", "observation"] as const)("compact %s reasons use the session record redactor", async (mode) => {
  const open = withSessionCredentials(async (_installation, _options, credentials) => {
    const kernel = credentials.kernel("session");
    const compaction = manualCompaction(kernel, { busy: () => false, busyReason: "busy", create: () => {
      if (mode === "create") { throw new Error(secret); }
      return { start: (_request, reply) => {
        if (mode === "refusal") { reply({ kind: "rejected", code: "runtime_refused", reason: secret }); }
        else { reply({ kind: "accepted" }); throw new Error(secret); }
      }, observe: () => null };
    } });
    return credentials.seal({
      id: kernel.sessionId, capabilities: { queue: { durable: false }, attribution: "none", images: false }, compact: compaction.compact,
      prompt: async (input) => kernel.control({ kind: "prompt", input }, () => ({ kind: "accepted" })),
      queue: async (input) => kernel.control({ kind: "queue", input }, () => ({ kind: "accepted" })),
      abort: async () => kernel.control({ kind: "abort" }, () => ({ kind: "accepted" })),
      dispose: async () => { kernel.request("toRuntime", { kind: "dispose" }); },
      rawEvents: (observer, cursor) => kernel.rawEvents(observer, cursor), records: () => kernel.records(), graph: () => kernel.graph(),
    });
  });
  const session = await open({ kind: "available", via: "bundled" }, { cwd: "/work", env: { API_KEY: secret } });
  try {
    const result = await session.compact?.();
    expect(result).toMatchObject({ kind: mode === "observation" ? "unconfirmed" : "rejected", reason: "[redacted]" });
    expect(JSON.stringify({ result, records: session.records() })).not.toContain(secret);
    if (result?.kind === "rejected" && result.response.body.kind === "rejected") { expect(result.reason).toBe(result.response.body.reason); }
  } finally { await session.dispose(); }
});
