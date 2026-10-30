import { describe, expect, it } from "vitest";
import { hasInvisible, revealInvisible } from "./reveal";

const ch = (cp: number) => String.fromCodePoint(cp);

// 4В20 ревью 4.r2: управляющие символы направления и невидимые символы показываются маркером.
describe("revealInvisible", () => {
  it("заменяет управляющие символы направления и невидимые символы", () => {
    const s = `/tmp/${ch(0x202e)}txt.exe${ch(0x2066)}a${ch(0x2069)}${ch(0x200b)}b${ch(0xfeff)}${ch(0x200f)}`;
    expect(revealInvisible(s)).toBe("/tmp/⟦U+202E⟧txt.exe⟦U+2066⟧a⟦U+2069⟧⟦U+200B⟧b⟦U+FEFF⟧⟦U+200F⟧");
    expect(hasInvisible(s)).toBe(true);
  });
  // 4Н35 ревью 4.r4: путь с теговыми символами не выглядит безобидным.
  it("заменяет мягкий перенос, ALM, U+2060–2064 и теговые символы", () => {
    const s = `/tmp/a${ch(0xe0072)}${ch(0xe006d)}b${ch(0x00ad)}c${ch(0x061c)}d${ch(0x2060)}${ch(0x2064)}${ch(0xe0000)}${ch(0xe007f)}`;
    expect(revealInvisible(s)).toBe("/tmp/a⟦U+E0072⟧⟦U+E006D⟧b⟦U+00AD⟧c⟦U+061C⟧d⟦U+2060⟧⟦U+2064⟧⟦U+E0000⟧⟦U+E007F⟧");
    expect(hasInvisible(s)).toBe(true);
    const near = `${ch(0x00ac)}${ch(0x00ae)}${ch(0x061b)}${ch(0x061d)}${ch(0x205f)}${ch(0xdffff)}${ch(0xe0080)}`;
    expect(revealInvisible(near)).toBe(near);
    expect(hasInvisible(near)).toBe(false);
  });
  it("соседние символы вне диапазонов и обычный текст не меняются", () => {
    const s = `{"path": "/home/иванов/отчёт.txt"}\n${ch(0x200a)}${ch(0x2010)}${ch(0x2065)}${ch(0x206a)}`;
    expect(revealInvisible(s)).toBe(s);
    expect(hasInvisible(s)).toBe(false);
  });
});
