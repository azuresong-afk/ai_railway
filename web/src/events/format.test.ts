import { afterEach, describe, expect, it } from "vitest";
import { displayTimezone, formatAbsolute, setDisplayTimezone } from "./format";

// ВРМ.2, В26 ревью 2.r5: даты показываются в часовом поясе установки из /me.
describe("formatAbsolute", () => {
  afterEach(() => setDisplayTimezone(undefined));

  it("показывает время в поясе установки", () => {
    setDisplayTimezone("Europe/Moscow");
    expect(formatAbsolute("2026-10-22T09:05:07Z")).toBe("22.10.2026, 12:05:07");
    setDisplayTimezone("Asia/Vladivostok");
    expect(formatAbsolute("2026-10-22T21:00:00Z")).toBe("23.10.2026, 07:00:00");
    setDisplayTimezone("UTC");
    expect(formatAbsolute("2026-10-22T21:00:00Z")).toBe("22.10.2026, 21:00:00");
  });

  it("неизвестный пояс не ломает показ", () => {
    setDisplayTimezone("Mars/Olympus");
    expect(displayTimezone()).toBeUndefined();
    expect(formatAbsolute("2026-10-22T09:05:07Z")).toMatch(/^22\.10\.2026, \d\d:05:07$/);
  });
});
