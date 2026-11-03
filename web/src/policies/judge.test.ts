import { describe, expect, it } from "vitest";
import type { PolicyRule, PolicySpec } from "./api";
import { criterionError, judgeActions, parseWhole, ruleWeakened, sectionErrors, sectionFromFields, sectionWeakened } from "./judge";
import { localDiff } from "./localDiff";

const jr = (j: Partial<NonNullable<PolicyRule["judge"]>> = {}, r: Partial<PolicyRule> = {}): PolicyRule => ({
  id: "no-refunds",
  detector: "judge.llm",
  action: "log",
  severity: "medium",
  judge: { kind: "business", criterion: "Ассистент не обещает возврат денег.", ...j },
  ...r,
});
const spec = (rules: PolicyRule[], judge?: PolicySpec["judge"]): PolicySpec => ({ name: "P", mode: "enforce", rules, ...(judge ? { judge } : {}) });
const section = { provider: "local-llm", model: "qwen3", max_calls_per_minute: 60, max_tokens_per_hour: 200000 };

describe("пределы judge.llm", () => {
  it("критерий: длина в символах, без переводов строки", () => {
    expect(criterionError("коротко")).toMatch(/от 10 до 1000/);
    expect(criterionError("Ассистент не обещает возврат денег.")).toBeUndefined();
    expect(criterionError("Первая строка правила.\nВторая строка")).toMatch(/управляющих символов/);
    expect(criterionError("а".repeat(1001))).toMatch(/1001/);
    expect(criterionError("😀".repeat(10))).toBeUndefined();
  });

  it("целые числа: пусто — по умолчанию, неверное — null", () => {
    expect(parseWhole("", 1, 10)).toBeUndefined();
    expect(parseWhole(" 5 ", 1, 10)).toBe(5);
    expect(parseWhole("0", 1, 10)).toBeNull();
    expect(parseWhole("11", 1, 10)).toBeNull();
    expect(parseWhole("1,5", 1, 10)).toBeNull();
    expect(parseWhole("-1", 1, 10)).toBeNull();
  });

  it("раздел: ошибки по полям и сбор из строк", () => {
    expect(sectionErrors({ provider: "Local LLM", model: "m", calls: "", tokens: "" }).provider).toBeDefined();
    expect(sectionErrors({ provider: "local-llm", model: "модель с пробелом", calls: "", tokens: "" }).model).toBeDefined();
    expect(sectionErrors({ provider: "local-llm", model: "m", calls: "6001", tokens: "999" })).toMatchObject({ calls: expect.any(String), tokens: expect.any(String) });
    expect(sectionErrors({ provider: "local-llm", model: "qwen3:14b", calls: "60", tokens: "200000" })).toEqual({});
    expect(sectionFromFields({ provider: "", model: "", calls: "5", tokens: "" })).toBeUndefined();
    expect(sectionFromFields({ provider: " local-llm ", model: "qwen3", calls: "", tokens: "5000" })).toEqual({ provider: "local-llm", model: "qwen3", max_tokens_per_hour: 5000 });
  });

  it("действия: block только в режиме sync, маскировать нельзя", () => {
    expect(judgeActions(jr())).toEqual(["allow", "log"]);
    expect(judgeActions(jr({ mode: "sync" }))).toEqual(["allow", "log", "block"]);
  });
});

describe("ослабление judge при сравнении версий (как на сервере)", () => {
  it("раздел: другой оценщик, меньший бюджет, удаление", () => {
    expect(sectionWeakened(undefined, section)).toBe(false);
    expect(sectionWeakened(section, undefined)).toBe(true);
    expect(sectionWeakened(section, { ...section, model: "other" })).toBe(true);
    expect(sectionWeakened(section, { ...section, provider: "other" })).toBe(true);
    expect(sectionWeakened(section, { ...section, max_calls_per_minute: 30 })).toBe(true);
    expect(sectionWeakened(section, { ...section, max_calls_per_minute: 100 })).toBe(false);
    // Пусто равно значению по умолчанию.
    expect(sectionWeakened({ provider: "p", model: "m" }, { provider: "p", model: "m", max_calls_per_minute: 60, max_tokens_per_hour: 200000 })).toBe(false);
  });

  it("правило: критерий, вид, sync → async, срок короче, отказ block → allow", () => {
    const a = jr({ mode: "sync", timeout_ms: 5000, on_failure: "block" }).judge;
    expect(ruleWeakened(a, a)).toBe(false);
    expect(ruleWeakened(a, { ...a!, criterion: "Другое правило для проверки." })).toBe(true);
    expect(ruleWeakened(a, { ...a!, kind: "content" })).toBe(true);
    expect(ruleWeakened(a, { kind: "business", criterion: a!.criterion })).toBe(true);
    expect(ruleWeakened(a, { ...a!, timeout_ms: 1000 })).toBe(true);
    expect(ruleWeakened(a, { ...a!, timeout_ms: 8000 })).toBe(false);
    expect(ruleWeakened(a, { ...a!, on_failure: "allow" })).toBe(true);
    expect(ruleWeakened(undefined, a)).toBe(false);
  });

  it("локальные различия: поле judge, признак ослабления и правило", () => {
    const before = spec([jr({ mode: "sync", on_failure: "block" }, { action: "block" })], section);
    const same = localDiff(before, before);
    expect(same.fields).toEqual([]);
    expect(same.weakening).toBe(false);

    const afterModel = localDiff(before, spec(before.rules, { ...section, model: "other" }));
    expect(afterModel.fields).toEqual([{ field: "judge", before: "local-llm/qwen3 calls=60 tokens=200000", after: "local-llm/other calls=60 tokens=200000" }]);
    expect(afterModel.weakening_reasons).toEqual([{ kind: "judge_weakened" }]);

    const toAsync = localDiff(before, spec([jr({}, { action: "log" })], section));
    expect(toAsync.rules_changed).toHaveLength(1);
    expect(toAsync.weakening_reasons.map((r) => r.kind)).toEqual(expect.arrayContaining(["judge_weakened", "action_weakened"]));
    expect(toAsync.weakening_reasons.find((r) => r.kind === "judge_weakened")).toEqual({ kind: "judge_weakened", rule: "no-refunds" });

    const stronger = localDiff(spec([jr()], section), spec([jr({ mode: "sync", timeout_ms: 8000 })], section));
    expect(stronger.weakening).toBe(false);
  });
});
