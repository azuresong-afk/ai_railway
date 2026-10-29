import { type Decision, ShapeIcon, type Severity } from "../ui/icons";
import type { Risk, ToolStatus } from "./api";

const base = "inline-flex items-center gap-1.5 rounded-control border border-line bg-surface px-2 py-0.5 text-xs font-medium text-fg";

export const riskLabel = new Map<Risk, string>([
  ["low", "Низкий"],
  ["medium", "Средний"],
  ["high", "Высокий"],
  ["critical", "Критический"],
]);
export const riskOrder: Risk[] = ["low", "medium", "high", "critical"];

export const statusLabel = new Map<ToolStatus, string>([
  ["new", "Новый"],
  ["approved", "Одобрен"],
  ["changed", "Описание изменилось"],
  ["suspicious", "Подозрительный"],
  ["revoked", "Одобрение снято"],
]);

// Форма значка и цвет: подпись рядом несёт смысл, цвет — дополнение (ТЗ 6.2).
const statusShape = new Map<ToolStatus, { kind: Severity | Decision; color: string }>([
  ["new", { kind: "info", color: "text-sev-info" }],
  ["approved", { kind: "allowed", color: "text-[var(--c-dec-allowed)]" }],
  ["changed", { kind: "medium", color: "text-sev-medium" }],
  ["suspicious", { kind: "critical", color: "text-sev-critical" }],
  ["revoked", { kind: "blocked", color: "text-[var(--c-dec-blocked)]" }],
]);

export function StatusBadge({ status }: { status: ToolStatus }) {
  const s = statusShape.get(status)!;
  return (
    <span className={base}>
      <span className={s.color}>
        <ShapeIcon kind={s.kind} />
      </span>
      {statusLabel.get(status)}
    </span>
  );
}

const riskColor = new Map<Risk, string>([
  ["low", "text-sev-low"],
  ["medium", "text-sev-medium"],
  ["high", "text-sev-high"],
  ["critical", "text-sev-critical"],
]);

export function RiskBadge({ risk }: { risk: Risk }) {
  return (
    <span className={base}>
      <span className={riskColor.get(risk)}>
        <ShapeIcon kind={risk} />
      </span>
      {riskLabel.get(risk)}
    </span>
  );
}
