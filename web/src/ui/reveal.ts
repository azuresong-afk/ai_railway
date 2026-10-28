// Управляющие символы направления текста и невидимые символы (4В20 ревью 4.r2). В аргументах вызова и описаниях
// инструментов они меняют видимый порядок символов или прячут их: дежурный одобрил бы не то, что видит. Перед показом
// каждый такой символ заменяется видимым маркером с его кодом. Диапазоны заданы кодами, а не символами: в исходном
// тексте таких символов нет.
const ranges: readonly (readonly [number, number])[] = [
  [0x200b, 0x200f], // нулевой ширины и метки направления LRM, RLM
  [0x202a, 0x202e], // встраивание и переопределение направления
  [0x2066, 0x2069], // изоляция направления
  [0xfeff, 0xfeff], // неразрывный пробел нулевой ширины (BOM)
];

function hiddenCode(cp: number): boolean {
  return ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
}

// Текст с видимыми маркерами вместо скрытых символов.
export function revealInvisible(s: string): string {
  let out = "";
  for (const c of s) {
    const cp = c.codePointAt(0) ?? 0;
    out += hiddenCode(cp) ? `⟦U+${cp.toString(16).toUpperCase().padStart(4, "0")}⟧` : c;
  }
  return out;
}

// В тексте есть скрытые символы.
export function hasInvisible(s: string): boolean {
  for (const c of s) {
    if (hiddenCode(c.codePointAt(0) ?? 0)) return true;
  }
  return false;
}
