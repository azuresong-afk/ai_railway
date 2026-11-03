import { type Decision, type Severity, ShapeIcon } from "../ui/icons";
import type { Model, ScanReport } from "./api";
import { statusTitle, verdictTitle } from "./format";

const base =
  "inline-flex items-center gap-1.5 rounded-control border border-line bg-surface px-2 py-0.5 text-xs font-medium text-fg";

// Метка: значок своей формы и подпись, цвет — дополнение (ТЗ 6.2).
function Mark({ shape, color, children }: { shape: Severity | Decision; color: string; children: string }) {
  return (
    <span className={base}>
      <span className={color}>
        <ShapeIcon kind={shape} />
      </span>
      {children}
    </span>
  );
}

// Состояние модели: «Запрещена» — модель исключена из пакета шлюзов (задача 5.22).
export function ModelStatus({ status }: { status: Model["status"] }) {
  return status === "blocked" ? (
    <Mark shape="blocked" color="text-[var(--c-dec-blocked)]">
      {statusTitle.get(status)!}
    </Mark>
  ) : (
    <Mark shape="allowed" color="text-[var(--c-dec-allowed)]">
      {statusTitle.get(status)!}
    </Mark>
  );
}

// Итог отчёта сканера: замечаний нет, предупреждения, запрет.
export function Verdict({ verdict }: { verdict: ScanReport["verdict"] }) {
  const m = new Map<ScanReport["verdict"], [Decision | Severity, string]>([
    ["ok", ["allowed", "text-[var(--c-dec-allowed)]"]],
    ["warn", ["medium", "text-sev-medium"]],
    ["block", ["blocked", "text-[var(--c-dec-blocked)]"]],
  ]);
  const [shape, color] = m.get(verdict)!;
  return (
    <Mark shape={shape} color={color}>
      {verdictTitle.get(verdict)!}
    </Mark>
  );
}
