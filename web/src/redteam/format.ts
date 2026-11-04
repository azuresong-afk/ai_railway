import type { Run, Schedule, Verdict } from "./api";

export const verdictOrder: Verdict[] = ["succeeded", "blocked", "defended", "unchecked", "error", "skipped"];

export const verdictTitle = new Map<Verdict, string>([
  ["succeeded", "Атака удалась"],
  ["blocked", "Заблокировано защитой"],
  ["defended", "Отражено"],
  ["unchecked", "Не проверено"],
  ["error", "Ошибка"],
  ["skipped", "Пропущено"],
]);

export const statusTitle = new Map<Run["status"], string>([
  ["queued", "в очереди"],
  ["running", "идёт"],
  ["done", "завершён"],
  ["failed", "не удался"],
  ["cancelled", "отменён"],
]);

export const reasonTitle = new Map<string, string>([
  ["interrupted", "сервер был перезапущен"],
  ["deadline", "истёк срок запуска"],
  ["key_not_delivered", "шлюз не принял ключ запуска"],
  ["no_scenarios", "нет сценариев"],
  ["internal", "внутренняя ошибка"],
]);

export const errorTitle = new Map<string, string>([
  ["blocked_address", "адрес запрещён правилом адресов"],
  ["dial", "нет соединения"],
  ["timeout", "срок запроса истёк"],
  ["redirect", "перенаправление (не выполняется)"],
  ["http_status", "ответ с кодом ошибки"],
  ["too_large", "ответ больше 1 МиБ"],
  ["bad_response", "ответ не по пути из цели"],
  ["request", "запрос не построен"],
]);

export const conditionTitle = new Map<string, string>([
  ["canary", "канарейка"],
  ["contains", "маркер в ответе"],
  ["findings", "находка детектора"],
  ["judge", "оценщик"],
]);

export const frequencyTitle = new Map<Schedule["frequency"], string>([
  ["daily", "ежедневно"],
  ["weekly", "еженедельно"],
  ["monthly", "ежемесячно"],
]);

export const weekdayTitle = ["", "понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"];

export function scheduleWhen(s: Pick<Schedule, "frequency" | "weekday" | "day" | "at">): string {
  switch (s.frequency) {
    case "weekly":
      return `еженедельно, ${weekdayTitle[s.weekday ?? 0] ?? ""}, ${s.at}`;
    case "monthly":
      return `ежемесячно, ${s.day}-го числа, ${s.at}`;
    default:
      return `ежедневно, ${s.at}`;
  }
}

export const scheduleStatusTitle = new Map<string, string>([
  ["started", "запуск начат"],
  ["busy", "цель или сервер заняты"],
  ["missed", "срок пропущен (сервер был выключен)"],
  ["no_scenarios", "нет сценариев"],
  ["gateway_not_configured", "адрес шлюза не задан"],
  ["needs_secret", "цели нужен секретный заголовок"],
  ["target_invalid", "цель не найдена или изменена"],
  ["error", "ошибка (см. журнал сервера)"],
]);

export const langTitle = new Map([
  ["ru", "русский"],
  ["en", "английский"],
]);

// Доля удавшихся атак среди проверенных сценариев (удалась, заблокирована, отражена), %, с запятой (ТЗ 6.7).
export function succeededShare(counts: Record<string, number>): string | undefined {
  const evaluated = countOf(counts, "succeeded") + countOf(counts, "blocked") + countOf(counts, "defended");
  if (evaluated === 0) return undefined;
  return ((countOf(counts, "succeeded") * 100) / evaluated).toFixed(1).replace(".", ",");
}

// Число сценариев с итогом v; ключи приходят с сервера, поэтому поиск по списку пар, а не по свойству.
export function countOf(counts: Record<string, number>, v: string): number {
  return Object.entries(counts).find(([k]) => k === v)?.[1] ?? 0;
}
