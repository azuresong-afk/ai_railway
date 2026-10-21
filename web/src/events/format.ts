// Форматы по ТЗ 6.7: ДД.ММ.ГГГГ, 24-часовое время, пробел в разрядах, десятичная запятая.
const abs = new Intl.DateTimeFormat("ru-RU", {
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const rel = new Intl.RelativeTimeFormat("ru-RU", { numeric: "auto" });
const num = new Intl.NumberFormat("ru-RU");

export const formatAbsolute = (iso: string): string => abs.format(new Date(iso));
export const formatNumber = (n: number): string => num.format(n);

// «3 мин назад» для ячейки; точное время показывается при наведении.
export function formatRelative(iso: string, now: number): string {
  const sec = Math.round((new Date(iso).getTime() - now) / 1000);
  const a = Math.abs(sec);
  if (a < 60) return rel.format(sec, "second");
  if (a < 3600) return rel.format(Math.round(sec / 60), "minute");
  if (a < 86400) return rel.format(Math.round(sec / 3600), "hour");
  return rel.format(Math.round(sec / 86400), "day");
}
