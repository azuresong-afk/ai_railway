import type { components } from "../api/schema";
import type { PolicyRule, PolicySpec } from "./api";

type S = components["schemas"];
export type PolicyJudge = S["PolicyJudge"];
export type PolicyJudgeRule = S["PolicyJudgeRule"];

// Пределы judge.llm — как в API и в internal/policy/judge.go (ADR-0030, раздел 2).
export const judgeLimits = {
  rules: 16,
  criterionMin: 10,
  criterionMax: 1000,
  timeoutMin: 500,
  timeoutMax: 30000,
  timeoutDefault: 5000,
  callsMax: 6000,
  callsDefault: 60,
  tokensMin: 1000,
  tokensMax: 100_000_000,
  tokensDefault: 200_000,
  modelMax: 128,
};

export const judgeDetector = "judge.llm";
const slugPattern = /^[a-z0-9][a-z0-9-]{0,62}$/;
const modelPattern = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;
// Управляющие символы и символы форматирования (в том числе перевод строки): критерий — одна строка.
const isForbiddenChar = (c: number) =>
  c < 0x20 || (c >= 0x7f && c <= 0x9f) || (c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2060 && c <= 0x2064) || c === 0xfeff;
const hasForbiddenChars = (text: string) => [...text].some((ch) => isForbiddenChar(ch.codePointAt(0) ?? 0));

export const isJudgeRule = (r: PolicyRule) => r.detector === judgeDetector;

export const kindText: Record<PolicyJudgeRule["kind"], string> = {
  business: "Бизнес-правило (DM-19)",
  content: "Недопустимый контент (DM-18)",
};
export const modeText = { async: "После ответа приложению (async)", sync: "До решения (sync)" } as const;
export const failureText = { allow: "Пропустить, отметить «не проверено»", block: "Заблокировать (в режиме «Защита»)" } as const;

// Действия правила judge.llm: у находки нет позиций, поэтому маскировать нечего; блокировать можно только до решения.
export function judgeActions(r: PolicyRule): PolicyRule["action"][] {
  return r.judge?.mode === "sync" ? ["allow", "log", "block"] : ["allow", "log"];
}

// Число из поля ввода: пустая строка — «по умолчанию» (undefined), неверное значение — null.
export function parseWhole(v: string, min: number, max: number): number | undefined | null {
  const t = v.trim();
  if (t === "") return undefined;
  if (!/^\d+$/.test(t)) return null;
  const n = Number(t);
  return n >= min && n <= max ? n : null;
}

export function criterionError(text: string): string | undefined {
  const t = text.trim();
  if (hasForbiddenChars(text)) return "В критерии не должно быть управляющих символов и переводов строки: напишите правило одним абзацем.";
  const n = [...t].length;
  if (n < judgeLimits.criterionMin || n > judgeLimits.criterionMax) {
    return `Критерий — от ${judgeLimits.criterionMin} до ${judgeLimits.criterionMax} символов, сейчас ${n}. Опишите, что именно запрещено.`;
  }
  return undefined;
}

export interface JudgeSectionErrors {
  provider?: string;
  model?: string;
  calls?: string;
  tokens?: string;
}

// Ошибки раздела judge (поля — строки ввода).
export function sectionErrors(f: { provider: string; model: string; calls: string; tokens: string }): JudgeSectionErrors {
  const e: JudgeSectionErrors = {};
  if (!slugPattern.test(f.provider.trim())) e.provider = "Укажите краткое имя (slug) провайдера: латиница в нижнем регистре, цифры и «-».";
  const m = f.model.trim();
  if (m.length > judgeLimits.modelMax || !modelPattern.test(m)) e.model = `Имя модели у провайдера: до ${judgeLimits.modelMax} символов, без пробелов.`;
  if (parseWhole(f.calls, 1, judgeLimits.callsMax) === null) e.calls = `Целое число от 1 до ${judgeLimits.callsMax} или пусто (${judgeLimits.callsDefault}).`;
  if (parseWhole(f.tokens, judgeLimits.tokensMin, judgeLimits.tokensMax) === null) {
    e.tokens = `Целое число от ${judgeLimits.tokensMin} до ${judgeLimits.tokensMax} или пусто (${judgeLimits.tokensDefault}).`;
  }
  return e;
}

// Раздел judge из строк ввода; undefined — раздел не заполнен.
export function sectionFromFields(f: { provider: string; model: string; calls: string; tokens: string }): PolicyJudge | undefined {
  if (f.provider.trim() === "" && f.model.trim() === "") return undefined;
  const calls = parseWhole(f.calls, 1, judgeLimits.callsMax);
  const tokens = parseWhole(f.tokens, judgeLimits.tokensMin, judgeLimits.tokensMax);
  return {
    provider: f.provider.trim(),
    model: f.model.trim(),
    ...(typeof calls === "number" ? { max_calls_per_minute: calls } : {}),
    ...(typeof tokens === "number" ? { max_tokens_per_hour: tokens } : {}),
  };
}

// Ослабление judge при сравнении версий — те же причины, что у сервера (internal/policy/versions/diff.go, judge_weakened).
const limit = (v: number | undefined, def: number) => (v === undefined || v === 0 ? def : v);

export function sectionWeakened(a: PolicySpec["judge"], b: PolicySpec["judge"]): boolean {
  if (!a) return false;
  if (!b) return true;
  return (
    a.provider !== b.provider ||
    a.model !== b.model ||
    limit(b.max_calls_per_minute, judgeLimits.callsDefault) < limit(a.max_calls_per_minute, judgeLimits.callsDefault) ||
    limit(b.max_tokens_per_hour, judgeLimits.tokensDefault) < limit(a.max_tokens_per_hour, judgeLimits.tokensDefault)
  );
}

export function ruleWeakened(a: PolicyJudgeRule | undefined, b: PolicyJudgeRule | undefined): boolean {
  if (!a || !b) return a !== undefined;
  const sync = (j: PolicyJudgeRule) => j.mode === "sync";
  const timeout = (j: PolicyJudgeRule) => (j.timeout_ms ? j.timeout_ms : judgeLimits.timeoutDefault);
  return (
    a.criterion !== b.criterion ||
    a.kind !== b.kind ||
    (sync(a) && !sync(b)) ||
    (sync(a) && sync(b) && (timeout(b) < timeout(a) || (a.on_failure === "block" && b.on_failure !== "block")))
  );
}

// Раздел одной строкой для списка различий — как на сервере.
export const sectionText = (j: PolicySpec["judge"]): string =>
  j ? `${j.provider}/${j.model} calls=${j.max_calls_per_minute ?? 0} tokens=${j.max_tokens_per_hour ?? 0}` : "";
