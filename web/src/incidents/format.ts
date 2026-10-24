import type { IncidentCard, IncidentResolution, IncidentStage, IncidentStatus } from "./api";

export const statusText: Record<IncidentStatus, string> = {
  new: "Новый",
  in_progress: "В работе",
  contained: "Локализован",
  closed: "Закрыт",
};

// Порядок колонок доски и разрешённые переходы (API: POST /incidents/{id}/status).
export const statusOrder: IncidentStatus[] = ["new", "in_progress", "contained", "closed"];
type Target = Exclude<IncidentStatus, "new">;
// Подпись кнопки говорит, что произойдёт (ТЗ 6.7).
export const transitionButton = new Map<Target, string>([
  ["in_progress", "Взять в работу"],
  ["contained", "Отметить локализованным"],
  ["closed", "Закрыть инцидент"],
]);
export const transitions: Record<IncidentStatus, Target[]> = {
  new: ["in_progress", "closed"],
  in_progress: ["contained", "closed"],
  contained: ["closed"],
  closed: [],
};

export const resolutionText: Record<IncidentResolution, string> = {
  resolved: "Устранён",
  false_positive: "Ложное срабатывание",
  risk_accepted: "Риск принят",
};

export const sourceText = new Map<string, string>([
  ["manual", "Вручную"],
  ["alert", "Из оповещения"],
  ["auto", "Автоматически"],
  ["reopen", "Повторное открытие"],
]);

export const stageText = new Map<IncidentStage, string>([
  ["intake", "Приём сообщения"],
  ["triage", "Сбор первичных сведений"],
  ["containment", "Локализация"],
  ["investigation", "Сбор сведений для расследования"],
]);

export const alertStatusText = { new: "Новое", in_progress: "В работе", closed: "Закрыто" } as const;

type Kind = IncidentCard["timeline"][number]["kind"];
const kindText: Record<Kind, string> = {
  created: "Инцидент создан",
  status_changed: "Статус изменён",
  assigned: "Назначен ответственный",
  comment_added: "Добавлен комментарий",
  stage_completed: "Этап реагирования отмечен",
  alert_linked: "Добавлено оповещение",
  alert_triggered: "Оповещение сработало снова",
  reopened: "Инцидент открыт повторно",
};

const s = (v: unknown): string => (typeof v === "string" ? v : "");

// Строка хронологии: подробности читаются только как текст из известных ключей (состав в схеме не закреплён).
export function timelineLine(e: IncidentCard["timeline"][number]): string {
  const d = e.details;
  const base = kindText[e.kind] ?? e.kind;
  switch (e.kind) {
    case "status_changed": {
      const from = statusText[s(d.from) as IncidentStatus] ?? s(d.from);
      const to = statusText[s(d.to) as IncidentStatus] ?? s(d.to);
      const res = resolutionText[s(d.resolution) as IncidentResolution];
      return `${base}: ${from} → ${to}${res ? ` (${res})` : ""}${s(d.comment) ? ` — ${s(d.comment)}` : ""}`;
    }
    case "stage_completed": {
      const st = stageText.get(s(d.stage) as IncidentStage);
      return st ? `${base}: ${st}` : base;
    }
    default:
      return base;
  }
}

// Срок реакции: «осталось» или «просрочено» словами, не только цветом.
export function reactionText(i: { reaction_due_at: string; overdue: boolean; reacted_at?: string | undefined; status: IncidentStatus }, now: number): string {
  if (i.reacted_at) return Date.parse(i.reacted_at) <= Date.parse(i.reaction_due_at) ? "Реакция в срок" : "Реакция с опозданием";
  if (i.status !== "new") return "—";
  const left = Date.parse(i.reaction_due_at) - now;
  if (i.overdue || left <= 0) return "Срок реакции истёк";
  const h = Math.floor(left / 3_600_000);
  if (h >= 48) return `Осталось ${Math.floor(h / 24)} сут.`;
  if (h >= 1) return `Осталось ${h} ч`;
  return `Осталось ${Math.max(1, Math.floor(left / 60_000))} мин`;
}
