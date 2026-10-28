import { describe, expect, it } from "vitest";
import { formatCountdown, remainingSeconds } from "./countdown";

describe("обратный отсчёт", () => {
  it("считает секунды до срока и не уходит ниже нуля", () => {
    const now = Date.parse("2026-10-28T10:00:00Z");
    expect(remainingSeconds("2026-10-28T10:04:05Z", now)).toBe(245);
    expect(remainingSeconds("2026-10-28T10:00:00Z", now)).toBe(0);
    expect(remainingSeconds("2026-10-28T09:00:00Z", now)).toBe(0);
  });
  it("форматирует минуты и часы", () => {
    expect(formatCountdown(245)).toBe("4:05");
    expect(formatCountdown(0)).toBe("0:00");
    expect(formatCountdown(3723)).toBe("1:02:03");
  });
});
