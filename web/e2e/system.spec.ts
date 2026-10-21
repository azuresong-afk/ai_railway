import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

const status = {
  generated_at: "2026-10-21T12:00:00Z",
  server: {
    version: "0.2.0",
    started_at: "2026-10-21T10:00:00Z",
    selftest: { ok: true, checked_at: "2026-10-21T10:00:01Z", failed: 0 },
    integrity: [
      { component: "server", trigger: "startup", checked_at: "2026-10-21T10:00:00Z", ok: true, reason: "ok", manifest_version: "0.2.0", test_signed: true, failed: 0 },
    ],
  },
  gateways: [
    { id: "g1", name: "gw-1", state: "online", last_seen_at: "2026-10-21T11:59:50Z", version: "0.2.0", bundle_etag: "e", cert_not_after: "2027-10-21T00:00:00Z", selftest: null, integrity: null, events: null },
  ],
  events: { dropped: 0, rejected: 0 },
  time: { server_time: "2026-10-21T12:00:00Z", timezone: "Europe/Moscow", sync: "synchronized", error_micros: 120 },
  storage: { available: true, audit_bytes: 1048576, limit_bytes: 21474836480, used_percent: 1, warn_percent: 80, warn_exceeded: false },
  audit_chain: { checked_at: "2026-10-21T11:30:00Z", ok: true, checked: 100, last_seq: 100, reason: "ok", broken_seq: null },
  notifications: [],
  unavailable: [],
};

async function mockSystem(page: Page): Promise<{ verifies: number }> {
  const seen = { verifies: 0 };
  await page.route("**/api/v1/system/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    if (path === "/api/v1/system/status") return json(status);
    if (path === "/api/v1/system/integrity/verify" && req.method() === "POST") {
      seen.verifies++;
      return json({
        component: "server", trigger: "manual", checked_at: "2026-10-21T12:05:00Z", ok: true, reason: "ok",
        manifest_version: "0.2.0", test_signed: true, checked_files: 40, failures: [], omitted: 0,
      });
    }
    return route.fulfill({ status: 404, contentType: "application/json", body: "{}" });
  });
  return seen;
}

test("состояние системы: разделы и проверка целостности по кнопке", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "system.read", "integrity.verify"]) });
  const seen = await mockSystem(page);
  await page.goto("/#/system");
  await expect(page.getByRole("heading", { name: "Состояние системы" })).toBeVisible();
  await expect(page.getByText("Активных уведомлений нет")).toBeVisible();
  await expect(page.getByRole("table", { name: "Шлюзы" })).toContainText("gw-1");
  await expect(page.getByText("Europe/Moscow")).toBeVisible();
  await expect(page.getByRole("progressbar", { name: "Заполнение журнала аудита" })).toHaveAttribute("aria-valuenow", "1");
  await page.getByRole("button", { name: "Проверить целостность" }).click();
  await expect(page.getByText(/Проверка от 21\.10\.2026/)).toBeVisible();
  expect(seen.verifies).toBe(1);
  done();
});

test("состояние системы: без права проверки кнопки нет, раздел виден по system.read", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "system.read"]) });
  await mockSystem(page);
  await page.goto("/#/system");
  await expect(page.getByRole("heading", { name: "Состояние системы" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Проверить целостность" })).toHaveCount(0);
  done();
});
