import { describe, expect, it } from "vitest";
import { buildFilter, type Chip, parseFilter } from "./filter";

describe("фильтр событий", () => {
  it("собирает строку из чипов", () => {
    const chips: Chip[] = [
      { field: "app", negate: false, values: ["crm-bot"] },
      { field: "severity", negate: false, values: ["high", "critical"] },
      { field: "action", negate: true, values: ["allow"] },
      { field: "env", negate: true, values: ["dev", "test"] },
      { field: "stream", negate: false, values: ["true"] },
    ];
    expect(buildFilter(chips)).toBe(
      'app = "crm-bot" and severity in ("high", "critical") and action != "allow" and env not in ("dev", "test") and stream = true',
    );
  });

  it("разбирает собранное обратно без потерь", () => {
    const chips: Chip[] = [
      { field: "app", negate: false, values: ['с "кавычками" и \\'] },
      { field: "threat", negate: true, values: ["DM-01", "DM-13"] },
      { field: "has_content", negate: false, values: ["false"] },
    ];
    expect(parseFilter(buildFilter(chips))).toEqual(chips);
  });

  it("пустая строка — нет условий", () => {
    expect(parseFilter("  ")).toEqual([]);
    expect(buildFilter([])).toBe("");
  });

  it.each([
    'unknown = "x"',
    'app = "x',
    'app = "a\\n"',
    'app in ()',
    'app in ("a" "b")',
    'app = "a" or app = "b"',
    'app = "a" and',
    "stream = maybe",
    'app ~ "a"',
  ])("не разбирает %s", (src) => {
    expect(parseFilter(src)).toBeNull();
  });
});
