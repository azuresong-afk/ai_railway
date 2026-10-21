import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Контраст токенов по WCAG 2.1 (ТЗ 6.2, 6.8): текст >= 4,5:1, значки и границы полей >= 3:1.
const css = readFileSync("src/design/tokens.css", "utf8"); // тесты запускаются из web/

type Tokens = Map<string, string>;

function block(selector: string): Tokens {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`нет блока ${selector}`);
  const body = css.slice(css.indexOf("{", start) + 1, css.indexOf("}", start));
  return new Map([...body.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((m) => [m[1]!, m[2]!.trim()] as const));
}

function get(t: Tokens, k: string): string {
  const v = t.get(k);
  if (!v) throw new Error(`нет токена ${k}`);
  return v;
}

const light = block(":root");
const dark: Tokens = new Map([...light, ...block(':root[data-theme="dark"]')]);
const darkAuto: Tokens = new Map([...light, ...block(':root:not([data-theme="light"])')]);

function lum(hex: string): number {
  const h = hex.replace("#", "");
  const [r, g, b] = [0, 2, 4].map((i) => {
    const c = parseInt(h.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(a: string, b: string): number {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p) as [number, number];
  return (x + 0.05) / (y + 0.05);
}

const themes: [string, Tokens][] = [
  ["светлая", light],
  ["тёмная", dark],
];

describe.each(themes)("%s тема", (_name, t) => {
  it.each(["--c-text", "--c-text-muted", "--c-accent"])("текст %s на surface и bg >= 4,5", (k) => {
    expect(ratio(get(t, k), get(t, "--c-surface"))).toBeGreaterThanOrEqual(4.5);
    expect(ratio(get(t, k), get(t, "--c-bg"))).toBeGreaterThanOrEqual(4.5);
  });
  it("текст на кнопке accent >= 4,5", () => {
    expect(ratio(get(t, "--c-on-accent"), get(t, "--c-accent"))).toBeGreaterThanOrEqual(4.5);
  });
  it("граница поля >= 3 на surface", () => {
    expect(ratio(get(t, "--c-border-strong"), get(t, "--c-surface"))).toBeGreaterThanOrEqual(3);
  });
  it.each([...light.keys()].filter((k) => k.startsWith("--c-sev-") || k.startsWith("--c-dec-")))(
    "значок %s >= 3 на surface",
    (k) => {
      expect(ratio(get(t, k), get(t, "--c-surface"))).toBeGreaterThanOrEqual(3);
    },
  );
});

// Оттенок (0–360°) и насыщенность по HSL.
function hueSat(hex: string): [number, number] {
  const h = hex.replace("#", "");
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255) as [number, number, number];
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const d = max - min;
  const l = (max + min) / 2;
  const s = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));
  let hue = 0;
  if (d > 0) {
    if (max === r) hue = ((g - b) / d) % 6;
    else if (max === g) hue = (b - r) / d + 2;
    else hue = (r - g) / d + 4;
  }
  return [(hue * 60 + 360) % 360, s];
}

// Цветные значки серьёзности и решений не сливаются с акцентом: оттенки расходятся не меньше чем на 30°.
// Серые (насыщенность < 0,25, например «Информация») отличаются от акцента насыщенностью.
describe.each(themes)("%s тема: значки отличимы от акцента", (_name, t) => {
  const [accentHue] = hueSat(get(t, "--c-accent"));
  it.each([...light.keys()].filter((k) => k.startsWith("--c-sev-") || k.startsWith("--c-dec-")))("%s", (k) => {
    const [hue, sat] = hueSat(get(t, k));
    if (sat < 0.25) return;
    const diff = Math.min(Math.abs(hue - accentHue), 360 - Math.abs(hue - accentHue));
    expect(diff).toBeGreaterThanOrEqual(30);
  });
});

it("тёмная тема по prefers-color-scheme совпадает с data-theme=dark", () => {
  expect(darkAuto).toEqual(dark);
});
