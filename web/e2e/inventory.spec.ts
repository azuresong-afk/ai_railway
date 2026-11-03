import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

// Синтетические данные: хеши условные.
const h = (c: string) => c.repeat(64);

const overview = {
  applications: [
    { id: "a-1", slug: "support-bot", name: "Бот поддержки", env: "prod", department: "Поддержка", provider: "yandex", models: [], archived: false,
      keys: [{ id: "k-1", name: "основной", prefix: "aisk_ab12", state: "active", expires_at: "2027-01-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" }] },
  ],
  providers: [{ id: "p-1", slug: "yandex", name: "Яндекс", type: "yandexgpt", external: true, credential_set: true }],
  models: 1, usage: 1, limits: { models: 5000, usage: 20000 },
  sync: { synced_upto: "2026-11-03T08:00:00Z", run_at: "2026-11-03T08:10:00Z", limit_reached: false, skipped: 0 },
};
const model = (status: string) => ({
  id: "m-1", kind: "customer", provider: "", name: "qwen-ft", version: "1", title: "Qwen дообученная", description: "", owner: "ML", origin: "manual", status, file_count: 1,
  created_at: "2026-10-20T10:00:00Z", updated_at: "2026-10-21T10:00:00Z",
  files: [{ path: "pytorch_model.bin", size: 2048, role: "weights", sha256: h("a") }], usage: [],
});
const report = {
  id: "r-1", model_id: "m-1", kind: "scan", host: "gpu-1", scanner_version: "1.0.0", received_at: "2026-11-02T12:00:00Z", received_by: "token:t-1", verdict: "block",
  hashes: "no_reference", templates: "none", files: 1, findings: 1, truncated: false, blocked: true, block_reasons: ["scan"], report_findings: [],
  finding_files: [{ path: "pytorch_model.bin", size: 2048, format: "pickle", findings: [{ code: "pickle", severity: "block" }] }],
  mismatches: [], mismatch_total: 0, chat_templates: [],
};

async function mockInventory(page: Page) {
  const st = { status: "blocked", unblockBody: undefined as unknown };
  await page.route("**/api/v1/inventory**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    switch (`${req.method()} ${url.pathname}`) {
      case "GET /api/v1/inventory":
        return json(overview);
      case "GET /api/v1/inventory/models": {
        return json({ items: [{ ...model(st.status), files: undefined, usage: undefined }] });
      }
      case "GET /api/v1/inventory/models/m-1":
        return json(model(st.status));
      case "GET /api/v1/inventory/models/m-1/scan-reports":
        return json({ items: [report] });
      case "POST /api/v1/inventory/models/m-1/unblock":
        st.unblockBody = req.postDataJSON();
        st.status = "active";
        return json(model("active"));
      case "GET /api/v1/inventory/chat-templates":
        return json({ active: "none", families: [] });
      case "GET /api/v1/inventory/aibom":
        return route.fulfill({ status: 200, contentType: "application/vnd.cyclonedx+json", headers: { "Content-Disposition": 'attachment; filename="aisec-aibom.cdx.json"' }, body: '{"bomFormat":"CycloneDX","specVersion":"1.6"}' });
      default:
        return route.fulfill({ status: 404, contentType: "application/json", body: "{}" });
    }
  });
  return st;
}

test("реестр ИИ: приложения, карточка запрещённой модели, снятие запрета и выгрузка AI-BOM при строгом CSP", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "inventory.read", "inventory.manage", "inventory.unblock", "inventory.export"]) });
  const st = await mockInventory(page);
  await page.goto("/");
  await page.getByRole("link", { name: "Реестр ИИ" }).click();
  await expect(page.getByRole("heading", { name: "Реестр ИИ", level: 1 })).toBeVisible();
  await expect(page.getByRole("table", { name: "Приложения реестра" })).toContainText("Бот поддержки");
  await expect(page.getByRole("table", { name: "Ключи" })).toContainText("aisk_ab12");

  await page.getByRole("tab", { name: "Модели" }).click();
  await expect(page.getByRole("table", { name: "Модели реестра" })).toContainText("Запрещена");
  await page.getByRole("button", { name: "Открыть карточку модели qwen-ft" }).click();
  await expect(page.getByRole("heading", { name: "Qwen дообученная" })).toBeVisible();
  await expect(page.getByText(/Использование модели запрещено/)).toBeVisible();
  await expect(page.getByRole("table", { name: "Файлы модели" })).toContainText(h("a"));
  await expect(page.getByText("Замечаний нет")).toHaveCount(0);

  await page.getByRole("button", { name: "Снять запрет" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Текущий пароль").fill("Correct-Horse-1");
  await dialog.getByRole("button", { name: "Снять запрет" }).click();
  await expect(page.getByText(/Использование модели запрещено/)).toHaveCount(0);
  expect(st.unblockBody).toEqual({ password: "Correct-Horse-1" });

  await page.getByRole("tab", { name: "AI-BOM" }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Выгрузить AI-BOM" }).click();
  expect((await download).suggestedFilename()).toMatch(/^aisec-aibom-\d{4}-\d{2}-\d{2}\.cdx\.json$/);
  await expect(page.getByText(/Выгрузка записана в журнал аудита/)).toBeVisible();
  done();
});

test("реестр ИИ: без права раздела нет в меню, прямой адрес — отказ", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "system.read"]) });
  await page.goto("/#/inventory");
  await expect(page.getByText("Нет доступа: реестр ИИ")).toBeVisible();
  await expect(page.getByRole("link", { name: "Реестр ИИ" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Коллекции RAG" })).toHaveCount(0);
  done();
});

const kb = {
  slug: "kb-hr", version: 2, documents: 2, size: 4096, excluded: 0, exclusions: 0, loaded_at: "2026-11-02T10:00:00Z", loaded_by: "token:t-idx", prev_loaded_at: "2026-11-01T10:00:00Z",
  diff: { added: 0, changed: 1, removed: 0, added_ids: [], changed_ids: ["docs/policy.md"], removed_ids: [] }, created_at: "2026-10-20T10:00:00Z", exclusion_list: [] as unknown[],
};

test("коллекции RAG: изменения между версиями, документы и исключение документа при строгом CSP", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "rag.read", "rag.manage"]) });
  const posted: unknown[] = [];
  await page.route("**/api/v1/rag/**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    switch (`${req.method()} ${url.pathname}`) {
      case "GET /api/v1/rag/collections": {
        return json({ items: [{ ...kb, exclusion_list: undefined }], limits: { collections: 100, documents: 100000, body_bytes: 16777216, document_id_bytes: 512, exclusions: 1000, diff_sample_ids: 100 } });
      }
      case "GET /api/v1/rag/collections/kb-hr":
        return json(kb);
      case "GET /api/v1/rag/collections/kb-hr/manifest":
        return json({ version: 2, items: [{ id: "docs/policy.md", sha256: h("b"), size: 2048, excluded: false, blocked: false }] });
      case "POST /api/v1/rag/collections/kb-hr/exclusions":
        posted.push(req.postDataJSON());
        kb.exclusion_list = [{ id: "e-1", document_id: "docs/policy.md", reason: "", created_at: "2026-11-03T10:00:00Z", created_by: "user:u1" }];
        return json(kb.exclusion_list[0], 201);
      default:
        return route.fulfill({ status: 404, contentType: "application/json", body: "{}" });
    }
  });
  await page.goto("/");
  await page.getByRole("link", { name: "Коллекции RAG" }).click();
  await expect(page.getByRole("heading", { name: "Коллекции RAG", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "Открыть коллекцию kb-hr" }).click();
  await expect(page.getByRole("heading", { name: "kb-hr" })).toBeVisible();
  await expect(page.getByText("docs/policy.md").first()).toBeVisible();
  await page.getByRole("tab", { name: "Документы" }).click();
  await expect(page.getByRole("table", { name: "Документы манифеста" })).toContainText(h("b"));
  await page.getByRole("tab", { name: "Изменения" }).click();
  await page.getByRole("button", { name: "Исключить документ docs/policy.md" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Исключить документ" }).click();
  await page.getByRole("tab", { name: "Исключения" }).click();
  await expect(page.getByRole("table", { name: "Исключения" })).toContainText("docs/policy.md");
  expect(posted).toEqual([{ document_id: "docs/policy.md" }]);
  done();
});
