// Язык фильтров событий (ADR-0015): условия через `and`, операторы `=`, `!=`, `in (…)`, `not in (…)`.
// Консоль собирает строку из «чипов» и разбирает сохранённую строку обратно в чипы;
// проверку значений и лимитов выполняет сервер.

export interface FieldInfo {
  id: string;
  title: string;
  bool?: boolean;
  // Подсказки значений (необязательные: поле принимает и свой текст).
  options?: { value: string; title: string }[];
}

const yesNo = [
  { value: "true", title: "да" },
  { value: "false", title: "нет" },
];

export const fields: FieldInfo[] = [
  {
    id: "type",
    title: "Тип",
    options: [
      { value: "gateway_request", title: "Запрос через шлюз" },
      { value: "check", title: "Проверка (Check API)" },
      { value: "auth_failure", title: "Отказ в доступе" },
    ],
  },
  { id: "app", title: "Приложение" },
  { id: "env", title: "Окружение" },
  { id: "user", title: "Пользователь (псевдоним)" },
  { id: "provider", title: "Провайдер" },
  { id: "model", title: "Модель" },
  { id: "source", title: "Источник текста" },
  {
    id: "policy_mode",
    title: "Режим политики",
    options: [
      { value: "monitor", title: "Наблюдение" },
      { value: "enforce", title: "Применение" },
    ],
  },
  { id: "action", title: "Действие" },
  { id: "rule", title: "Правило" },
  {
    id: "severity",
    title: "Серьёзность",
    options: [
      { value: "critical", title: "Критическая" },
      { value: "high", title: "Высокая" },
      { value: "medium", title: "Средняя" },
      { value: "low", title: "Низкая" },
      { value: "info", title: "Информация" },
    ],
  },
  {
    id: "storage",
    title: "Хранение содержимого",
    options: [
      { value: "none", title: "не хранится" },
      { value: "masked", title: "замаскировано" },
      { value: "full", title: "полностью" },
    ],
  },
  { id: "gateway", title: "Шлюз (ID)" },
  { id: "threat", title: "Угроза (строка матрицы, DM-NN)" },
  { id: "detector", title: "Детектор" },
  { id: "stream", title: "Потоковый ответ", bool: true, options: yesNo },
  { id: "non_text_unchecked", title: "Нетекстовое не проверено", bool: true, options: yesNo },
  { id: "has_content", title: "Есть содержимое", bool: true, options: yesNo },
];

const byId = new Map(fields.map((f) => [f.id, f]));

export const fieldTitle = (id: string): string => byId.get(id)?.title ?? id;

export function valueTitle(field: string, value: string): string {
  return byId.get(field)?.options?.find((o) => o.value === value)?.title ?? value;
}

// Чип: одно условие. Несколько значений означают `in (…)`.
export interface Chip {
  field: string;
  negate: boolean;
  values: string[];
}

export function chipKey(c: Chip): string {
  return `${c.field}|${c.negate ? "!" : "="}|${c.values.join(",")}`;
}

const quote = (v: string) => `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

function chipToString(c: Chip): string {
  const bool = byId.get(c.field)?.bool === true;
  const lit = (v: string) => (bool ? v : quote(v));
  if (c.values.length === 1) return `${c.field} ${c.negate ? "!=" : "="} ${lit(c.values[0]!)}`;
  return `${c.field} ${c.negate ? "not in" : "in"} (${c.values.map(lit).join(", ")})`;
}

export function buildFilter(chips: Chip[]): string {
  return chips.map(chipToString).join(" and ");
}

// Разбор строки фильтра в чипы. null — строка не разобрана (тогда консоль показывает её целиком).
export function parseFilter(src: string): Chip[] | null {
  const s = src.trim();
  if (s === "") return [];
  const chips: Chip[] = [];
  let pos = 0;
  const ws = () => {
    while (pos < s.length && /\s/.test(s.charAt(pos))) pos++;
  };
  const word = (): string => {
    const m = /^[a-z_]+/.exec(s.slice(pos));
    if (!m) return "";
    pos += m[0].length;
    return m[0];
  };
  const value = (): string | null => {
    if (s.charAt(pos) === '"') {
      pos++;
      let out = "";
      while (pos < s.length) {
        const c = s.charAt(pos);
        if (c === '"') {
          pos++;
          return out;
        }
        if (c === "\\") {
          const n = s.charAt(pos + 1);
          if (n !== '"' && n !== "\\") return null;
          out += n;
          pos += 2;
          continue;
        }
        out += c;
        pos++;
      }
      return null;
    }
    const w = word();
    return w === "true" || w === "false" ? w : null;
  };
  for (;;) {
    ws();
    const field = word();
    if (!byId.has(field)) return null;
    ws();
    let negate = false;
    let list = false;
    if (s.startsWith("!=", pos)) {
      negate = true;
      pos += 2;
    } else if (s.charAt(pos) === "=") {
      pos++;
    } else {
      const w = word();
      if (w === "not") {
        negate = true;
        ws();
        if (word() !== "in") return null;
      } else if (w !== "in") {
        return null;
      }
      list = true;
    }
    ws();
    const values: string[] = [];
    if (list) {
      if (s.charAt(pos) !== "(") return null;
      pos++;
      for (;;) {
        ws();
        const v = value();
        if (v === null) return null;
        values.push(v);
        ws();
        if (s.charAt(pos) === ",") {
          pos++;
          continue;
        }
        if (s.charAt(pos) === ")") {
          pos++;
          break;
        }
        return null;
      }
    } else {
      const v = value();
      if (v === null) return null;
      values.push(v);
    }
    chips.push({ field, negate, values });
    ws();
    if (pos >= s.length) return chips;
    if (word() !== "and") return null;
  }
}
