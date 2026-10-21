import type { ReactElement, SVGProps } from "react";

// Значки серьёзности и решений: у каждого уровня своя форма, цвет не единственный носитель смысла
// (ТЗ 6.2, 6.10). Значок декоративный: смысл несёт подпись рядом (aria-hidden).

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Decision = "allowed" | "masked" | "blocked" | "would_block";

export const severityLabel = new Map<Severity, string>([
  ["critical", "Критическая"],
  ["high", "Высокая"],
  ["medium", "Средняя"],
  ["low", "Низкая"],
  ["info", "Информация"],
]);

export const decisionLabel = new Map<Decision, string>([
  ["allowed", "Пропущен"],
  ["masked", "Замаскирован"],
  ["blocked", "Заблокирован"],
  ["would_block", "Заблокировал бы"],
]);

type P = SVGProps<SVGSVGElement>;

function Svg({ children, ...p }: P) {
  return (
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false" {...p}>
      {children}
    </svg>
  );
}

const shapes = new Map<Severity | Decision, ReactElement>([
  // Критическая: ромб с восклицательным знаком
  [
    "critical",
    (
    <>
      <path d="M8 1 15 8 8 15 1 8Z" fill="currentColor" />
      <path d="M8 4.5v4M8 10.5v1" stroke="var(--c-surface)" strokeWidth="1.6" strokeLinecap="round" />
    </>
    ),
  ],
  // Высокая: треугольник
  [
    "high",
    (
    <>
      <path d="M8 1.5 15 14H1Z" fill="currentColor" />
      <path d="M8 6v4M8 11.5v.5" stroke="var(--c-surface)" strokeWidth="1.6" strokeLinecap="round" />
    </>
    ),
  ],
  // Средняя: круг с чертой
  [
    "medium",
    (
    <>
      <circle cx="8" cy="8" r="7" fill="currentColor" />
      <path d="M4.5 8h7" stroke="var(--c-surface)" strokeWidth="1.8" strokeLinecap="round" />
    </>
    ),
  ],
  // Низкая: квадрат с точкой
  [
    "low",
    (
    <>
      <rect x="1.5" y="1.5" width="13" height="13" rx="2" fill="currentColor" />
      <circle cx="8" cy="8" r="1.8" fill="var(--c-surface)" />
    </>
    ),
  ],
  // Информация: контурный круг с «i»
  [
    "info",
    (
    <>
      <circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <path d="M8 7.2v4M8 4.6v.4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </>
    ),
  ],
  // Пропущен: галочка в круге
  [
    "allowed",
    (
    <>
      <circle cx="8" cy="8" r="7" fill="currentColor" />
      <path d="m4.8 8.2 2.3 2.3 4.2-4.6" fill="none" stroke="var(--c-surface)" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </>
    ),
  ],
  // Замаскирован: закрашенная полоса в рамке
  [
    "masked",
    (
    <>
      <rect x="1.5" y="3.5" width="13" height="9" rx="1.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="4" y="6.5" width="8" height="3" fill="currentColor" />
    </>
    ),
  ],
  // Заблокирован: круг с перечёркиванием
  [
    "blocked",
    (
    <>
      <circle cx="8" cy="8" r="7" fill="currentColor" />
      <path d="M4.5 4.5l7 7" stroke="var(--c-surface)" strokeWidth="1.8" strokeLinecap="round" />
    </>
    ),
  ],
  // «Заблокировал бы»: пунктирный круг с перечёркиванием
  [
    "would_block",
    (
    <>
      <circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="2.4 1.8" />
      <path d="M5 5l6 6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </>
    ),
  ],
]);

export function ShapeIcon({ kind, ...p }: { kind: Severity | Decision } & P) {
  return <Svg {...p}>{shapes.get(kind)}</Svg>;
}
