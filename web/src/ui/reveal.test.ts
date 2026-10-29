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
  it("соседние символы вне диапазонов и обычный текст не меняются", () => {
    const s = `{"path": "/home/иванов/отчёт.txt"}\n${ch(0x200a)}${ch(0x2010)}${ch(0x2065)}${ch(0x206a)}`;
    expect(revealInvisible(s)).toBe(s);
    expect(hasInvisible(s)).toBe(false);
  });
});
