import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, csrfToken, request, setUnauthorizedHandler } from "./client";

const fetchMock = vi.fn();

function reply(status: number, body?: unknown) {
  fetchMock.mockResolvedValueOnce(new Response(body === undefined ? null : JSON.stringify(body), { status }));
}

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  // jsdom на http отбрасывает cookie с префиксом __Host-, поэтому читаем через подмену.
  vi.spyOn(document, "cookie", "get").mockReturnValue("a=1; __Host-aisec_csrf=tok%2B1");
});
afterEach(() => {
  fetchMock.mockReset();
  vi.unstubAllGlobals();
  setUnauthorizedHandler(undefined);
  vi.restoreAllMocks();
});

describe("клиент API", () => {
  it("читает CSRF-токен из cookie", () => {
    expect(csrfToken()).toBe("tok+1");
  });

  it("добавляет X-CSRF-Token к изменяющим запросам и не добавляет к GET", async () => {
    reply(204);
    await api.logout();
    reply(200, { setup_required: false });
    await api.setupStatus();
    const post = fetchMock.mock.calls[0]![1] as RequestInit;
    const get = fetchMock.mock.calls[1]![1] as RequestInit;
    expect((post.headers as Record<string, string>)["X-CSRF-Token"]).toBe("tok+1");
    expect((get.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
    expect(post.credentials).toBe("same-origin");
  });

  // Остаток ревью 4.r1 (УПД.10): фоновый опрос помечен заголовком и не продлевает сессию; изменяющий запрос — никогда.
  it("помечает фоновый GET заголовком X-AISec-Background", async () => {
    reply(200, {});
    await request("GET", "/api/v1/system/status", undefined, undefined, true);
    reply(200, {});
    await request("GET", "/api/v1/system/status");
    reply(204);
    await request("POST", "/api/v1/x", {}, undefined, true);
    const h = (i: number) => (fetchMock.mock.calls.at(i)![1] as RequestInit).headers as Record<string, string>;
    expect(h(0)["X-AISec-Background"]).toBe("1");
    expect(h(1)["X-AISec-Background"]).toBeUndefined();
    expect(h(2)["X-AISec-Background"]).toBeUndefined();
  });

  it("me возвращает null при 401", async () => {
    reply(401, { code: "unauthorized", detail: "x" });
    expect(await api.me()).toBeNull();
  });

  it("разбирает Problem Details", async () => {
    reply(400, { code: "invalid_request", detail: "Пароль слишком короткий.", errors: [{ field: "new_password", detail: "мало" }] });
    const err = await api.changePassword("a", "b").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).detail).toBe("Пароль слишком короткий.");
    expect((err as ApiError).fields).toHaveLength(1);
  });

  it("401 вне входа вызывает обработчик, 401 входа — нет", async () => {
    const h = vi.fn();
    setUnauthorizedHandler(h);
    reply(401, { code: "unauthorized", detail: "x" });
    await api.login("a", "b").catch(() => undefined);
    expect(h).not.toHaveBeenCalled();
    reply(401, { code: "unauthorized", detail: "x" });
    await api.logout().catch(() => undefined);
    expect(h).toHaveBeenCalledTimes(1);
  });

  it("ответ без JSON даёт общий текст", async () => {
    fetchMock.mockResolvedValueOnce(new Response("<html>", { status: 502 }));
    const err = (await api.logout().catch((e: unknown) => e)) as ApiError;
    expect(err.status).toBe(502);
    expect(err.detail).toBe("Запрос не выполнен.");
  });
});
