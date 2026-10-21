import { type Decision, decisionLabel, type Severity, severityLabel, ShapeIcon } from "./icons";

const sevColor = new Map<Severity, string>([
  ["critical", "text-sev-critical"],
  ["high", "text-sev-high"],
  ["medium", "text-sev-medium"],
  ["low", "text-sev-low"],
  ["info", "text-sev-info"],
]);

const decColor = new Map<Decision, string>([
  ["allowed", "text-[var(--c-dec-allowed)]"],
  ["masked", "text-[var(--c-dec-masked)]"],
  ["blocked", "text-[var(--c-dec-blocked)]"],
  ["would_block", "text-[var(--c-dec-would-block)]"],
]);

const base =
  "inline-flex items-center gap-1.5 rounded-control border border-line bg-surface px-2 py-0.5 text-xs font-medium text-fg";

// Метка серьёзности: значок своей формы цветом уровня и подпись цветом текста (контраст 4,5:1).
export function SeverityBadge({ level }: { level: Severity }) {
  return (
    <span className={base}>
      <span className={sevColor.get(level)}>
        <ShapeIcon kind={level} />
      </span>
      {severityLabel.get(level)}
    </span>
  );
}

// Метка решения политики: форма и подпись, цвет — дополнение.
export function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span className={base}>
      <span className={decColor.get(decision)}>
        <ShapeIcon kind={decision} />
      </span>
      {decisionLabel.get(decision)}
    </span>
  );
}
