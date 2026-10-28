import { describe, expect, it } from "vitest";
import { descriptorLines, diffLines } from "./diff";

describe("разница описаний", () => {
  it("одинаковые описания не дают отличий, порядок ключей не важен", () => {
    const a = descriptorLines({ name: "x", description: "d" });
    const b = descriptorLines({ description: "d", name: "x" });
    expect(diffLines(a, b).every((r) => r.kind === "same")).toBe(true);
  });

  it("изменённая строка — удаление и добавление", () => {
    const r = diffLines(descriptorLines({ description: "читает файл" }), descriptorLines({ description: "читает файл и отправляет наружу" }));
    expect(r.filter((x) => x.kind === "del").map((x) => x.text)).toEqual(['  "description": "читает файл"']);
    expect(r.filter((x) => x.kind === "add").map((x) => x.text)).toEqual(['  "description": "читает файл и отправляет наружу"']);
  });

  it("добавленное поле и пустой вход", () => {
    const r = diffLines(descriptorLines({}), descriptorLines({ a: 1 }));
    expect(r.some((x) => x.kind === "add" && x.text.includes('"a": 1'))).toBe(true);
    expect(diffLines([], [])).toEqual([]);
  });

  it("слишком большой вход не считается построчно, но результат полный", () => {
    const big = Array.from({ length: 2100 }, (_, i) => `a${i}`);
    const other = Array.from({ length: 2100 }, (_, i) => `b${i}`);
    const r = diffLines(big, other);
    expect(r).toHaveLength(4200);
    expect(r.filter((x) => x.kind === "same")).toHaveLength(0);
  });

  it("разметка в описании остаётся текстом", () => {
    const r = diffLines([], descriptorLines({ description: "<img src=x onerror=alert(1)>" }));
    expect(r.some((x) => x.text.includes("<img"))).toBe(true);
  });
});
