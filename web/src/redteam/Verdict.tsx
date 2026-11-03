import { type Decision, ShapeIcon, type Severity } from "../ui/icons";
import type { Verdict as V } from "./api";
import { verdictTitle } from "./format";

// Цвет и форма значка у каждого итога свои (ТЗ 6.2: смысл не только цветом).
const shape = new Map<V, { kind: Severity | Decision; color: string }>([
  ["succeeded", { kind: "critical", color: "text-sev-critical" }],
  ["blocked", { kind: "blocked", color: "text-[var(--c-dec-blocked)]" }],
  ["defended", { kind: "allowed", color: "text-[var(--c-dec-allowed)]" }],
  ["unchecked", { kind: "medium", color: "text-sev-medium" }],
  ["error", { kind: "high", color: "text-sev-high" }],
  ["skipped", { kind: "info", color: "text-sev-info" }],
]);

export function VerdictBadge({ verdict }: { verdict: V }) {
  const s = shape.get(verdict);
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm">
      {s && (
        <span className={s.color}>
          <ShapeIcon kind={s.kind} />
        </span>
      )}
      {verdictTitle.get(verdict) ?? verdict}
    </span>
  );
}
