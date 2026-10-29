/* eslint-disable security/detect-object-injection -- индексы только числовые, внутри циклов по длине массивов; недоверенных ключей нет */
// Построчная разница двух описаний инструмента. Описание пришло от MCP-сервера: оно только превращается в текст,
// ни в какой вид разметки не разбирается.
export type DiffKind = "same" | "add" | "del";
export interface DiffRow {
  kind: DiffKind;
  text: string;
}

// Ключи сортируются, чтобы порядок полей в ответе не создавал ложных отличий.
function sorted(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sorted);
  if (v && typeof v === "object") {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, x]) => [k, sorted(x)]),
    );
  }
  return v;
}

export function descriptorLines(d: unknown): string[] {
  return JSON.stringify(sorted(d), null, 2).split("\n");
}

// Предел произведения длин: описание не больше нескольких КиБ, но защита от раздутого ответа нужна.
const maxCells = 4_000_000;

export function diffLines(oldLines: string[], newLines: string[]): DiffRow[] {
  const n = oldLines.length;
  const m = newLines.length;
  if (n * m > maxCells) {
    return [...oldLines.map((text) => ({ kind: "del" as const, text })), ...newLines.map((text) => ({ kind: "add" as const, text }))];
  }
  // Длина наибольшей общей подпоследовательности суффиксов.
  const w = m + 1;
  const t = new Uint32Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      t[i * w + j] = oldLines[i] === newLines[j] ? t[(i + 1) * w + j + 1]! + 1 : Math.max(t[(i + 1) * w + j]!, t[i * w + j + 1]!);
    }
  }
  const out: DiffRow[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (oldLines[i] === newLines[j]) {
      out.push({ kind: "same", text: oldLines[i]! });
      i++;
      j++;
    } else if (t[(i + 1) * w + j]! >= t[i * w + j + 1]!) {
      out.push({ kind: "del", text: oldLines[i++]! });
    } else {
      out.push({ kind: "add", text: newLines[j++]! });
    }
  }
  while (i < n) out.push({ kind: "del", text: oldLines[i++]! });
  while (j < m) out.push({ kind: "add", text: newLines[j++]! });
  return out;
}
