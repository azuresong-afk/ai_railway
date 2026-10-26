import type { PolicyDiff, PolicyRule, PolicySpec } from "./api";

type Reason = PolicyDiff["weakening_reasons"][number];

// Строгость действия: чем больше, тем жёстче защита.
const strength: Record<PolicyRule["action"], number> = { allow: 0, log: 1, redact: 2, pseudonymize: 3, block: 4 };

const same = (a: PolicyRule, b: PolicyRule): boolean => JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));
const sorted = (r: PolicyRule): [string, unknown][] => Object.entries(r).sort(([a], [b]) => (a < b ? -1 : 1));

// Сравнение двух содержимых политики в браузере (Н46): правила, режим и общие поля. Признак ослабления — предварительная
// оценка консоли по тем же причинам, что у сервера; окончательное решение за сервером, он потребует пароль или код.
// Исключения здесь не сравниваются: их меняет отдельный экран.
export function localDiff(before: PolicySpec, after: PolicySpec): PolicyDiff {
  const fields: PolicyDiff["fields"] = [];
  const text = (s: PolicySpec) =>
    new Map<PolicyDiff["fields"][number]["field"], string>([
      ["name", s.name],
      ["mode", s.mode],
      ["non_text", s.non_text ?? ""],
      ["response_check", s.response_check ?? ""],
      ["block_message", s.block_message ?? ""],
    ]);
  const bt = text(before);
  const at = text(after);
  for (const [f, b] of bt) {
    const a = at.get(f) ?? "";
    if (a !== b) fields.push({ field: f, before: b, after: a });
  }
  const byId = new Map(before.rules.map((r) => [r.id, r]));
  const afterIds = new Set(after.rules.map((r) => r.id));
  const rules_added = after.rules.filter((r) => !byId.has(r.id));
  const rules_removed = before.rules.filter((r) => !afterIds.has(r.id));
  const rules_changed: PolicyDiff["rules_changed"] = [];
  const reasons: Reason[] = [];
  if (before.mode === "enforce" && after.mode === "monitor") reasons.push({ kind: "mode_monitor" });
  for (const r of rules_removed) reasons.push({ kind: "rule_removed", rule: r.id });
  for (const a of after.rules) {
    const b = byId.get(a.id);
    if (!b || same(a, b)) continue;
    const am = new Map(Object.entries(a));
    const bm = new Map(Object.entries(b));
    const keys = [...new Set([...am.keys(), ...bm.keys()])].filter((k) => JSON.stringify(am.get(k)) !== JSON.stringify(bm.get(k)));
    rules_changed.push({ id: a.id, fields: keys, before: b, after: a });
    if (strength[a.action] < strength[b.action]) reasons.push({ kind: "action_weakened", rule: a.id });
    if (a.threshold !== undefined && b.threshold !== undefined && a.threshold > b.threshold) reasons.push({ kind: "threshold_raised", rule: a.id });
    if (a.detector !== b.detector) reasons.push({ kind: "detector_changed", rule: a.id });
  }
  const order = (s: PolicySpec) => s.rules.filter((r) => byId.has(r.id) && afterIds.has(r.id)).map((r) => r.id).join("\u0000");
  const beforeOrder = before.rules.filter((r) => afterIds.has(r.id)).map((r) => r.id).join("\u0000");
  return {
    from: 0,
    to: 0,
    fields,
    rules_added,
    rules_removed,
    rules_changed,
    reordered: beforeOrder !== order(after),
    weakening: reasons.length > 0,
    weakening_reasons: reasons,
    exceptions_added: [],
    exceptions_removed: [],
    exceptions_changed: [],
  };
}
