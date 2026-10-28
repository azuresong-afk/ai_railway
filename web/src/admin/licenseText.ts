import type { LicenseInfo } from "./api";

// Тексты лицензии для вкладки «Лицензия» и баннера консоли (ADR-0026, пп. 4, 5).

// Даты лицензии — календарные дни UTC: показываются без времени и без сдвига часового пояса.
const day = new Intl.DateTimeFormat("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric", timeZone: "UTC" });
export const formatDay = (iso: string | undefined): string => (iso ? day.format(new Date(iso)) : "—");

export const stateTitles: Record<LicenseInfo["state"], string> = {
  none: "Пилот по договору",
  active: "Действует",
  expiring: "Скоро истекает",
  grace: "Льготный период",
  restricted: "Изменения запрещены",
  invalid: "Не прошла проверку",
};

export const moduleTitles = new Map<LicenseInfo["modules"][number], string>([
  ["agents", "Агенты и MCP"],
  ["shadow_ai", "Теневой ИИ"],
  ["compliance", "Соответствие"],
  ["ml", "ML-детекторы"],
]);

export const typeTitle = (t: LicenseInfo["type"]): string => (t === "pilot" ? "Пилотная" : t === "commercial" ? "Коммерческая" : "—");

export type Notice = { kind: "info" | "warning" | "error"; text: string };

// Сообщение для баннера консоли; null — баннер не нужен.
export function licenseNotice(l: LicenseInfo): Notice | null {
  const until = formatDay(l.valid_until);
  switch (l.state) {
    case "expiring":
      return {
        kind: (l.days_left ?? 0) <= 7 ? "warning" : "info",
        text: `Срок лицензии № ${l.number} заканчивается ${until} (осталось суток: ${l.days_left ?? 0}). Запросите новую лицензию у производителя.`,
      };
    case "grace":
      return {
        kind: "warning",
        text:
          `Срок лицензии № ${l.number} истёк ${until}. Идёт льготный период до ${formatDay(l.grace_until)} ` +
          `(осталось суток: ${l.grace_days_left ?? 0}): после него изменения конфигурации будут запрещены. Трафик и защита работают.`,
      };
    case "restricted":
      return {
        kind: "error",
        text:
          `Льготный период лицензии № ${l.number} закончился: изменения конфигурации запрещены. ` +
          "Трафик, защита, просмотр и выгрузки работают. Загрузите новую лицензию в разделе «Администрирование → Лицензия».",
      };
    case "invalid":
      return {
        kind: "error",
        text:
          `Лицензия № ${l.number} не прошла проверку подписи: изменения конфигурации запрещены. ` +
          "Загрузите действующую лицензию в разделе «Администрирование → Лицензия».",
      };
  }
  if (l.clock_behind) {
    return { kind: "warning", text: "Часы сервера отстают от времени, которое уже видела лицензия. Проверьте синхронизацию времени." };
  }
  return null;
}
