import { expect, type Page } from "@playwright/test";

// Любое нарушение CSP, ошибка в консоли браузера или внешний запрос валят тест.
// Ответы 400/401/422 от API (неверный код, нет сессии) браузер сам пишет в консоль как «Failed to load
// resource»: это ожидаемое поведение консоли, а не ошибка; нарушения CSP («Refused to ...») не пропускаются.
const expectedStatus = /^Failed to load resource: the server responded with a status of (400|401|422) /;

// origin — адрес, с которого консоль грузит страницы: preview для подмены API, настоящий сервер для live.spec.ts.
export function watch(page: Page, origin = "http://127.0.0.1:4173") {
  const problems: string[] = [];
  const external: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" && !expectedStatus.test(m.text())) problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(e.message));
  page.on("request", (r) => {
    if (!r.url().startsWith(origin + "/")) external.push(r.url());
  });
  return () => {
    expect(problems).toEqual([]);
    expect(external).toEqual([]);
  };
}
