import { runInNewContext } from "node:vm";
import { expect, test, vi } from "vitest";
import { dshGoalSource } from "../../packages/oar/src/runtimes/dsh/bridge-goal.js";

const create = vi.fn(() => undefined);
const write = vi.fn();
const goals = {
  get: () => undefined,
  create,
  edit: vi.fn(),
  pause: vi.fn(),
  resume: vi.fn(),
  complete: vi.fn(),
  clear: vi.fn(),
};

test("DSH goalSet refuses an empty native observation and records the readback", () => {
  const source = `${dshGoalSource}\ngoalCommands;`;
  const agent = { session: { id: "fixture-session" } };
  const { goalSet }: { goalSet(request: { sessionId: string; options: { objective: string; status: string } }): unknown } = runInNewContext(source, {
    ctx: { get: () => goals },
    requireMethod: (service: object, method: string) => { expect(Reflect.get(service, method)).toBeTypeOf("function"); },
    owned: () => ({ agent }),
    write,
    refusal: (code: string, message: string) => Object.assign(new Error(message), { code }),
  });
  expect(() => goalSet({ sessionId: agent.session.id, options: { objective: "fixture goal", status: "active" } })).toThrow(expect.objectContaining({
    code: "runtime_refused", message: "DSH did not report a valid goal observation",
  }));
  expect(create).toHaveBeenCalledExactlyOnceWith(agent, { objective: "fixture goal" });
  expect(goals.resume).not.toHaveBeenCalled();
  expect(write).toHaveBeenCalledExactlyOnceWith({ type: "native", channel: "goal/read", operation: "set", sessionId: agent.session.id, goal: null });
});
