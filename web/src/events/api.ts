import { ApiError, csrfToken, request } from "../api/client";
import type { components } from "../api/schema";

export type Event = components["schemas"]["Event"];
export type EventPage = components["schemas"]["EventPage"];
export type EventContent = components["schemas"]["EventContent"];
export type SavedFilter = components["schemas"]["SavedFilter"];

export const pageSize = 200;

export interface Query {
  from: string;
  to: string;
  filter: string;
}

function qs(q: Query, extra: Record<string, string> = {}): string {
  const p = new URLSearchParams({ from: q.from, to: q.to, limit: String(pageSize), ...extra });
  if (q.filter) p.set("filter", q.filter);
  return p.toString();
}

export const eventsApi = {
  list: (q: Query, cursor: string | undefined, signal?: AbortSignal) =>
    request<EventPage>("GET", `/api/v1/events?${qs(q, cursor ? { cursor } : {})}`, undefined, signal),
  get: (id: string, signal?: AbortSignal) =>
    request<Event>("GET", `/api/v1/events/${encodeURIComponent(id)}`, undefined, signal),
  // Содержимое запрашивается только по кнопке и с причиной (УПД.7).
  content: (id: string, reason: string) =>
    request<EventContent>("POST", `/api/v1/events/${encodeURIComponent(id)}/content`, { reason }),
  filters: (signal?: AbortSignal) =>
    request<{ items: SavedFilter[] }>("GET", "/api/v1/events/filters", undefined, signal),
  saveFilter: (name: string, filter: string) => request<SavedFilter>("POST", "/api/v1/events/filters", { name, filter }),
  deleteFilter: (id: string) => request<void>("DELETE", `/api/v1/events/filters/${encodeURIComponent(id)}`),

  // Выгрузка: файл приходит ответом сервера, консоль только сохраняет его (Blob без интерпретации).
  async export(q: Query, format: "csv" | "json"): Promise<{ blob: Blob; rows: number | null; name: string }> {
    const body: Record<string, string> = { format, from: q.from, to: q.to };
    if (q.filter) body.filter = q.filter;
    const resp = await fetch("/api/v1/events/export", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
      credentials: "same-origin",
      cache: "no-store",
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      let p: { code?: string; detail?: string } = {};
      try {
        p = (await resp.json()) as typeof p;
      } catch {
        // тело не Problem Details
      }
      throw new ApiError(resp.status, p.code ?? "internal_error", p.detail ?? "Запрос не выполнен.");
    }
    const rows = resp.headers.get("X-Export-Rows");
    const stamp = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "");
    return { blob: await resp.blob(), rows: rows === null ? null : Number(rows), name: `events-${stamp}.${format}` };
  },
};

// Понятный текст ошибки по статусу и коду (ТЗ 6.7: что случилось и как исправить).
export function describeError(e: unknown, what: "list" | "content" | "export" | "filters"): string {
  if (!(e instanceof ApiError)) return "Нет связи с сервером. Проверьте сеть и повторите.";
  switch (e.status) {
    case 400:
    case 422:
      if (what === "export") return "Выгрузка больше 100 000 строк. Сузьте период или добавьте условие.";
      return e.detail;
    case 403:
      return what === "content"
        ? "Нет права смотреть содержимое. Обратитесь к администратору безопасности."
        : "Нет права на это действие. Обратитесь к администратору.";
    case 404:
      return what === "content"
        ? "Содержимое не сохранено: режим хранения не включал его или срок хранения истёк."
        : "Запись не найдена. Возможно, она удалена по сроку хранения.";
    case 409:
      return "Фильтр с таким именем уже есть. Выберите другое имя.";
    case 413:
    case 415:
      return "Запрос отклонён сервером. Обновите страницу и повторите.";
    case 429:
      return "Слишком много запросов. Подождите минуту и повторите.";
    case 503:
      return what === "content"
        ? "Содержимое не выдано: не удалось записать обращение в журнал аудита. Повторите позже."
        : "Сервер временно недоступен. Повторите позже.";
    default:
      return "Не удалось выполнить запрос. Повторите или обратитесь к администратору.";
  }
}
