// BYOK change: Adapt OAR #1205 to the caller-owned native request hook (Apache-2.0).
import { asRecord, parseJson, type JsonRecord } from "../../shared/json.js";

const REDACTED = "[redacted]";

function scrubOutputJson(raw: string, secretIds: ReadonlySet<string>): string | undefined {
  const answers = asRecord(asRecord(parseJson(raw))?.answers);
  if (answers === null) return undefined;
  const entries: [string, { answers: string[] }][] = [];
  for (const [id, entry] of Object.entries(answers)) {
    const values = asRecord(entry)?.answers;
    if (!Array.isArray(values) || !values.every((value): value is string => typeof value === "string")) return undefined;
    entries.push([id, { answers: secretIds.has(id) ? values.map(() => REDACTED) : values }]);
  }
  return JSON.stringify({ answers: Object.fromEntries(entries) });
}

function scrubOutput(output: unknown, secretIds: ReadonlySet<string>): unknown {
  if (typeof output === "string") return scrubOutputJson(output, secretIds) ?? REDACTED;
  if (!Array.isArray(output) || output.length === 0) return REDACTED;
  const parts: JsonRecord[] = [];
  for (const part of output) {
    const record = asRecord(part);
    if (record === null || (record.type !== "input_text" && record.type !== "output_text") || typeof record.text !== "string") return REDACTED;
    const text = scrubOutputJson(record.text, secretIds);
    if (text === undefined) return REDACTED;
    parts.push({ type: record.type, text });
  }
  return parts;
}

export function createCodexSecretAnswers(addCredential: (value: string) => void) {
  const pending = new Map<string, ReadonlySet<string>>();
  return {
    recordAnswer(params: JsonRecord, freeTextAnswers?: ReadonlyMap<string, string>): void {
      const { itemId, questions } = params;
      if (typeof itemId !== "string" || itemId === "" || !Array.isArray(questions)) return;
      const secretIds = new Set<string>();
      for (const question of questions) {
        const native = asRecord(question);
        if (native?.isSecret !== true || typeof native.id !== "string") continue;
        secretIds.add(native.id);
        const freeText = freeTextAnswers?.get(native.id);
        if (freeText !== undefined && freeText !== "") addCredential(freeText);
      }
      if (secretIds.size !== 0) pending.set(itemId, secretIds);
    },
    scrubNotification(method: string, params: JsonRecord): JsonRecord {
      if (method !== "rawResponseItem/completed" || pending.size === 0) return params;
      const item = asRecord(params.item);
      if (item?.type !== "function_call_output" || typeof item.call_id !== "string") return params;
      const secretIds = pending.get(item.call_id);
      if (secretIds === undefined) return params;
      pending.delete(item.call_id);
      return { ...params, item: { ...item, output: scrubOutput(item.output, secretIds) } };
    },
    clear(): void { pending.clear(); },
  };
}
