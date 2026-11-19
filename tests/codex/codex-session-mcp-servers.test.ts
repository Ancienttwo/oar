import { afterEach, expect, test, vi } from "vitest";
import type { McpServer, Session } from "../../packages/oar/src/contracts/session.js";
import { codexThreadOpen } from "../../packages/oar/src/runtimes/codex/open.js";
import { codexSession } from "../../packages/oar/src/runtimes/codex/session.js";
import { asRecord } from "../../packages/oar/src/shared/json.js";
import { fakeLineProcess, type FakeLineProcess } from "../fixtures/fake-line-process.js";

const spawnLineProcess = vi.fn<(command: string, args: readonly string[]) => FakeLineProcess>();

const installation = { kind: "available", via: "executable", command: "codex", version: "0.160.1" } as const;

const STDIO_TOKEN = "stdio-secret-value";
const HEADER = "Bearer header-secret-value";
const echo: McpServer = { name: "echo", command: "/usr/bin/node", args: ["echo.mjs"], env: { OAR_ECHO_TOKEN: STDIO_TOKEN } };
const remote: McpServer = { name: "remote.v2", type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: HEADER } };

afterEach(() => {
  spawnLineProcess.mockReset();
});

test("thread/start and thread/resume both carry the servers as one mcp_servers config table", () => {
  const start = codexThreadOpen({ cwd: "/work", effort: "low", mcpServers: [echo, remote, { name: "bare", command: "bare-server" }] });
  expect(start.params.config).toMatchInlineSnapshot(`
    {
      "mcp_servers": {
        "bare": {
          "args": [],
          "command": "bare-server",
          "enabled": true,
        },
        "echo": {
          "args": [
            "echo.mjs",
          ],
          "command": "/usr/bin/node",
          "enabled": true,
          "env": {
            "OAR_ECHO_TOKEN": "stdio-secret-value",
          },
        },
        "remote.v2": {
          "enabled": true,
          "http_headers": {
            "Authorization": "Bearer header-secret-value",
          },
          "url": "http://127.0.0.1:9/mcp",
        },
      },
      "model_reasoning_effort": "low",
    }
  `);
  // A resume takes no effort override (open.ts) but the servers again.
  const resume = codexThreadOpen({ cwd: "/work", resume: "thread-1", effort: "low", mcpServers: [echo] });
  expect(resume.method).toBe("thread/resume");
  expect(Object.keys(asRecord(resume.params.config) ?? {})).toEqual(["mcp_servers"]);
  // None given, or an empty list: no config at all.
  expect(codexThreadOpen({ cwd: "/work", mcpServers: [] }).params).not.toHaveProperty("config");
  expect(codexThreadOpen({ cwd: "/work", resume: "thread-1" }).params).not.toHaveProperty("config");
});

test("a name codex would refuse to start, or one given twice, fails the open before codex starts", async () => {
  await expect(codexSession(spawnLineProcess, installation, { cwd: "/work", env: {}, mcpServers: [{ name: "my server", command: "x" }] })).rejects.toThrowErrorMatchingInlineSnapshot(`[Error: codex MCP server names must match ^[\\w:@/.-]+$]`);
  await expect(codexSession(spawnLineProcess, installation, { cwd: "/work", env: {}, mcpServers: [echo, echo] })).rejects.toThrowErrorMatchingInlineSnapshot(`[Error: mcpServers names "echo" twice; names are unique within a session]`);
  expect(spawnLineProcess).not.toHaveBeenCalled();
});

test("an open failure never carries an env or header value, however codex words it", async () => {
  const fake = fakeLineProcess((text, process) => {
    const message = asRecord(JSON.parse(text));
    if (typeof message?.id !== "number") {
      return;
    }
    const reply = message.method === "initialize"
      ? { result: {} }
      : { error: { code: -32_600, message: `bad config: env ${STDIO_TOKEN}, header ${HEADER}` } };
    process.emit(`${JSON.stringify({ id: message.id, ...reply })}\n`);
  });
  spawnLineProcess.mockReturnValue(fake);
  await expect(codexSession(spawnLineProcess, installation, { cwd: "/work", env: {}, mcpServers: [echo, remote] })).rejects.toThrowErrorMatchingInlineSnapshot(`[Error: codex thread/start failed: bad config: env [redacted], header [redacted]]`);
});

test("a withheld open reply can reject a model mismatch without disclosing the reported model", async () => {
  const fake = fakeLineProcess((text, process) => {
    const message = asRecord(JSON.parse(text));
    if (typeof message?.id !== "number") return;
    const result = message.method === "initialize" ? {} : { thread: { id: "thread" }, model: "private-sibling", [STDIO_TOKEN]: true };
    process.emit(`${JSON.stringify({ id: message.id, result })}\n`);
  });
  spawnLineProcess.mockReturnValue(fake);
  await expect(codexSession(spawnLineProcess, installation, { cwd: "/work", env: {}, mcpServers: [echo], model: "requested" })).rejects.toMatchObject({
    name: "ModelConfirmationError", requested: "requested", reported: null,
    message: "codex thread/start did not confirm requested model requested",
  });
});

test("nor does a codex exit, whose stderr tail the error carries", async () => {
  const fake = fakeLineProcess((text, process) => {
    const message = asRecord(JSON.parse(text));
    if (message?.method === "initialize") {
      process.emitStderr(`failed to start server with ${STDIO_TOKEN}\n`);
      process.end(1);
    }
  });
  spawnLineProcess.mockReturnValue(Object.assign(fake, {
    exitError: () => new Error(fake.diagnostics().stderr ?? "app-server exited"),
  }));
  const opening = codexSession(spawnLineProcess, installation, { cwd: "/work", env: {}, mcpServers: [echo] });
  await expect(opening).rejects.toThrow(/\[redacted\]/u);
  await expect(opening).rejects.not.toThrow(STDIO_TOKEN);
});

test("Codex isolates draft tails by thread and sanitizes a completed suffix once", async () => {
  const fake = fakeLineProcess((text, process) => {
    const request = asRecord(JSON.parse(text));
    if (typeof request?.id !== "number") return;
    const result = request.method === "thread/start" ? { thread: { id: "root" } } : {};
    process.emit(`${JSON.stringify({ id: request.id, result })}\n`);
  });
  spawnLineProcess.mockReturnValue(fake);
  const session = await codexSession(spawnLineProcess, installation, { cwd: "/work", env: {
    API_KEY: "fixture-token", LONG_TOKEN: "fixture-token-long", MARKER_SECRET: "redacted", TOKEN: "[redacted]",
  } });
  const notify = (method: string, params: Record<string, unknown>) => fake.emit(`${JSON.stringify({ method, params })}\n`);
  try {
    notify("turn/started", { threadId: "root", turn: { id: "turn" } });
    notify("item/agentMessage/delta", { threadId: "root", turnId: "turn", itemId: "root-item", delta: "say fixture-token" });
    notify("item/completed", { threadId: "root", turnId: "old-turn", item: { id: "root-item", type: "agentMessage", text: "prior result" } });
    notify("item/completed", { threadId: "root", turnId: "turn", item: { id: "root-item", type: "agentMessage", text: "say fixture-token" } });
    notify("item/agentMessage/delta", { threadId: "root", turnId: "turn", itemId: "opaque", delta: "hidden fix", "[redacted]": "secret sibling" });
    notify("item/agentMessage/delta", { threadId: "root", turnId: "turn", itemId: "opaque", delta: "ation" });
    notify("item/started", { threadId: "root", turnId: "turn", item: {
      id: "mcp", type: "mcpToolCall", server: "sample", tool: "lookup", arguments: { text: "private-tool-sibling" }, "[redacted]": true,
    } });
    notify("item/started", { threadId: "root", turnId: "turn", item: {
      id: "command", type: "commandExecution", command: "private-command-sibling", "[redacted]": true,
    } });
    notify("item/agentMessage/delta", { threadId: "child", turnId: "child-turn", itemId: "child-item", delta: "say fix" });
    notify("error", { threadId: "root", willRetry: true, error: { "[redacted]": true, message: "private-debug-sibling" } });
    notify("account/rateLimits/updated", { rateLimits: { limitId: "codex", primary: { usedPercent: 100, resetsAt: 1_800_000_000, "[redacted]": true } } });
    notify("turn/completed", { threadId: "root", turn: { id: "turn", status: "failed", error: { codexErrorInfo: "usageLimitExceeded" }, items: [{ type: "userMessage", content: [
      { type: "text", text: "joined fixture-" }, { type: "text", text: "token" },
    ] }] } });
    notify("turn/completed", { threadId: "child", turn: { id: "old-child-turn", status: "completed" } });
    notify("item/completed", { threadId: "child", turnId: "old-child-turn", item: { id: "child-item", type: "agentMessage", text: "prior result" } });
    notify("item/agentMessage/delta", { threadId: "child", turnId: "child-turn", itemId: "child-item", delta: "ation" });
    notify("item/completed", { threadId: "child", turnId: "child-turn", item: { id: "child-item", type: "agentMessage", text: "say fixation" } });
    const records = session.records();
    const root = records.flatMap(record => record.kind === "frame" && record.sessionId === "root"
      ? record.body.events.flatMap(event => event.kind === "text_delta" ? [event.text] : []) : []);
    const child = records.flatMap(record => record.kind === "frame" && record.sessionId === "child" && record.body.type === "item/agentMessage/delta"
      && record.body.events.length === 0 ? [asRecord(record.body.native)?.delta] : []);
    expect(root).toEqual(["say ", "[redacted]", "ation"]);
    expect(JSON.stringify(records)).not.toMatch(/hidden|private-tool-sibling|private-command-sibling|private-debug-sibling|joined fixture-/u);
    expect(records).toContainEqual(expect.objectContaining({ body: expect.objectContaining({ type: "error", events: [{ kind: "retry", attempt: 1 }] }) }));
    expect(JSON.stringify(records)).not.toContain("resetsAt");
    expect(records).toContainEqual(expect.objectContaining({ body: expect.objectContaining({ type: "turn/completed", native: expect.objectContaining({
      turn: expect.objectContaining({ items: [{ type: "userMessage", content: [{ type: "text", text: "joined [redacted]" }, { type: "text", text: "" }] }] }),
    }) }) }));
    expect(child.join("")).toBe("say fixation");
  } finally { await session.dispose(); }
});

test("withheld Codex notifications add no graph node or tool call identifiers", async () => {
  const fake = fakeLineProcess((text, process) => {
    const request = asRecord(JSON.parse(text));
    if (typeof request?.id !== "number") return;
    const result = request.method === "thread/start" ? { thread: { id: "root" } } : {};
    process.emit(`${JSON.stringify({ id: request.id, result })}\n`);
  });
  spawnLineProcess.mockReturnValue(fake);
  const live: ReturnType<Session["records"]>[number][] = [];
  const session = await codexSession(spawnLineProcess, installation, { cwd: "/work", env: {}, mcpServers: [echo] }, 1_000, {
    onRecord: record => { live.push(record); },
  });
  const notify = (method: string, params: Record<string, unknown>) => fake.emit(`${JSON.stringify({ method, params })}\n`);
  try {
    notify("item/commandExecution/outputDelta", { threadId: "private-thread", turnId: "private-turn", itemId: "private-item", delta: "part", [STDIO_TOKEN]: true });
    expect(session.graph().nodes).toEqual([{ id: "root" }]);
    expect(session.records().at(-1)).toMatchObject({ sessionId: "root", body: { native: "[redacted]", events: [], byokRoot: false } });
    expect(JSON.stringify(live)).not.toContain("private-");
    notify("item/commandExecution/outputDelta", { threadId: "visible-thread", turnId: "visible-turn", itemId: "visible-item", delta: "part" });
    expect(session.graph().nodes.map(node => node.id)).toContain("visible-thread");
    expect(session.records().at(-1)).toMatchObject({ sessionId: "visible-thread", spanId: "visible-turn", body: {
      events: [{ kind: "tool_call_progress", callId: "visible-item" }],
    } });
    expect(live).toEqual(session.records());
  } finally { await session.dispose(); }
});

test.each([
  { effort: "low", hidden: true, message: "codex thread/settings/update did not confirm requested effort high" },
  { effort: "low", hidden: false, message: "codex thread/settings/update left effort low although high was requested" },
  { effort: "high", hidden: true, message: null },
])("Codex checks requested resume effort against $effort with hidden settings $hidden", async ({ effort, hidden, message }) => {
  const fake = fakeLineProcess((text, process) => {
    const request = asRecord(JSON.parse(text));
    if (typeof request?.id !== "number") return;
    const result = request.method === "thread/resume" ? { thread: { id: "root" }, reasoningEffort: "medium" } : {};
    process.emit(`${JSON.stringify({ id: request.id, result })}\n`);
    if (request.method === "thread/settings/update") {
      const threadSettings = hidden ? { reasoningEffort: effort, [STDIO_TOKEN]: true } : { reasoningEffort: effort };
      process.emit(`${JSON.stringify({ method: "thread/settings/updated", params: { threadId: "root", threadSettings } })}\n`);
    }
  });
  spawnLineProcess.mockReturnValue(fake);
  const opening = codexSession(spawnLineProcess, installation, { cwd: "/work", env: {}, mcpServers: [echo], resume: "root", effort: "high" });
  if (message === null) {
    const session = await opening;
    try {
      expect(session.records()).toContainEqual(expect.objectContaining({ body: expect.objectContaining({
        type: "thread/settings/updated", native: { threadId: "root", threadSettings: "[redacted]" }, events: [],
      }) }));
    } finally { await session.dispose(); }
  } else {
    await expect(opening).rejects.toMatchObject({ name: "UnsupportedOptionError", option: "effort", message });
  }
});

const privateUserConfigValue = "private-user-config-env-sentinel";

function expectPrivateConfig(session: Session, sent: readonly Record<string, unknown>[], method: string): void {
  const open = sent.find((message) => message.method === method);
  expect(asRecord(open?.params)?.config).toEqual({ mcp_servers: { saved: { disabled_tools: ["already", "echo"] } } });
  expect(JSON.stringify(sent)).not.toContain(privateUserConfigValue);
  expect(JSON.stringify(session.records())).not.toContain(privateUserConfigValue);
  expect(session.records().filter((record) => record.kind === "frame").map((record) => record.body.type)).toEqual([method]);
}

test.each([undefined, "saved-thread"])("config/read credentials stay private across an open hook, resume=%s", async (resume) => {
  const sent: Record<string, unknown>[] = [];
  const fake = fakeLineProcess((text, process) => {
    const message = asRecord(JSON.parse(text));
    if (typeof message?.id !== "number") { return; }
    sent.push(message);
    let result: Record<string, unknown> = {};
    if (message.method === "config/read") {
      result = { config: { mcp_servers: { saved: { command: "private-server", env: { PRIVATE_TOKEN: privateUserConfigValue }, disabled_tools: ["already"] } } } };
    } else if (message.method !== "initialize") {
      result = { thread: { id: "saved-thread" }, model: "gpt-5.5" };
    }
    process.emit(`${JSON.stringify({ id: message.id, result })}\n`);
  });
  spawnLineProcess.mockReturnValue(fake);
  const session = await codexSession(spawnLineProcess, installation, { cwd: "/work", env: {}, ...(resume === undefined ? {} : { resume }) }, 1_000, {
    beforeOpen: async (request, params) => {
      const reply = await request("config/read", {});
      const saved = asRecord(asRecord(asRecord(reply.config)?.mcp_servers)?.saved);
      return { ...params, config: { mcp_servers: { saved: { disabled_tools: [...(saved?.disabled_tools as string[]), "echo"] } } } };
    },
  });
  try {
    expectPrivateConfig(session, sent, resume === undefined ? "thread/start" : "thread/resume");
  } finally { await session.dispose(); }
  expect(JSON.stringify(session.records())).not.toContain(privateUserConfigValue);
});
