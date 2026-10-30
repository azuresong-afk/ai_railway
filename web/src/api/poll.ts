import type { QueryClient, QueryKey } from "@tanstack/react-query";

// Повторный запрос уже загруженных данных (опрос по таймеру, возврат на вкладку) — фоновый: сессию по
// бездействию продлевают только действия пользователя (УПД.10). Первая загрузка экрана или нового фильтра —
// действие пользователя.
export function isRefetch(qc: QueryClient, key: QueryKey): boolean {
  return (qc.getQueryState(key)?.dataUpdatedAt ?? 0) > 0;
}
