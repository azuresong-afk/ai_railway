const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
const num = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 1 });

// Размер в двоичных единицах с русскими обозначениями.
export function formatBytes(n: number): string {
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${num.format(v)} ${units.at(i)}`;
}

export const syncText = new Map([
  ["synchronized", "Синхронизировано"],
  ["unsynchronized", "Не синхронизировано"],
  ["unknown", "Состояние неизвестно"],
]);

export const gatewayText = new Map([
  ["online", "На связи"],
  ["offline", "Нет связи"],
  ["pending", "Ожидает регистрации"],
  ["revoked", "Отозван"],
]);

export const triggerText = new Map([
  ["startup", "при запуске"],
  ["periodic", "по расписанию"],
  ["manual", "по команде"],
]);

export const reasonText = new Map([
  ["ok", "Нарушений нет"],
  ["manifest_missing", "Манифест не найден"],
  ["manifest_invalid", "Манифест повреждён"],
  ["signature_invalid", "Подпись манифеста неверна"],
  ["files_mismatch", "Файлы не совпадают с манифестом"],
]);

export const problemText = new Map([
  ["modified", "изменён"],
  ["size", "другой размер"],
  ["missing", "отсутствует"],
  ["extra", "лишний файл"],
  ["not_regular", "не обычный файл"],
  ["unreadable", "не читается"],
  ["no_entry", "нет в манифесте"],
  ["changed", "изменился"],
]);

export const chainReasonText = new Map([
  ["ok", "цепочка цела"],
  ["hash_mismatch", "хеш записи не совпал"],
  ["prev_mismatch", "нарушена связь с предыдущей записью"],
  ["gap", "пропущены записи"],
  ["head_missing", "нет головы цепочки"],
  ["tail_truncated", "после контрольной точки нет записей"],
  ["rewritten", "журнал изменён после прошлой проверки"],
  ["alg_mismatch", "другой алгоритм хеширования"],
  ["invalid_record", "запись повреждена"],
  ["checkpoint_invalid", "контрольная точка неверна"],
  ["anchor_forged", "опорная точка подделана"],
]);
