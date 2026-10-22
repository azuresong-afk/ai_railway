import type { Page, Request } from "@playwright/test";

export interface MockState {
  me: Record<string, unknown> | null;
  setupRequired?: boolean;
  // Принятый код TOTP; любой другой — 400.
  goodCode?: string;
  // Что вернёт вход при верном пароле.
  afterLogin?: Record<string, unknown>;
  afterVerify?: Record<string, unknown>;
  afterPassword?: Record<string, unknown>;
  calls: { method: string; path: string; csrf: string | undefined; body: unknown }[];
}

export const user = { id: "u1", login: "ivanov", display_name: "Иван Иванов" };
export const meOf = (session_state: string, permissions: string[] = ["session", "self"]) => ({
  user,
  session_state,
  permissions,
  timezone: "Europe/Moscow",
});

const problem = (status: number, code: string, detail: string) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify({ type: `urn:aisec:problem:${code}`, title: code, status, detail, code }),
});
export const CSRF = "csrf-test-token";
const ok = (body: unknown, cookie = false) => ({
  status: 200,
  contentType: "application/json",
  body: JSON.stringify(body),
  // Как сервер: cookie CSRF читается интерфейсом (Secure допустим на 127.0.0.1 в Chromium).
  ...(cookie ? { headers: { "Set-Cookie": `__Host-aisec_csrf=${CSRF}; Path=/; Secure; SameSite=Strict` } } : {}),
});

// Подмена API сервера для e2e консоли: проверяется интерфейс, а не сервер (он проверен своими тестами).
export async function mockApi(page: Page, init: Partial<MockState>): Promise<MockState> {
  const st: MockState = { me: null, calls: [], ...init };
  await page.route("**/api/v1/**", async (route) => {
    const req: Request = route.request();
    const path = new URL(req.url()).pathname;
    let body: unknown;
    try {
      body = req.postDataJSON();
    } catch {
      body = undefined;
    }
    st.calls.push({ method: req.method(), path, csrf: req.headers()["x-csrf-token"], body });
    const key = `${req.method()} ${path}`;
    switch (key) {
      case "GET /api/v1/me":
        return route.fulfill(st.me ? ok(st.me) : problem(401, "unauthorized", "Требуется вход."));
      case "GET /api/v1/auth/setup":
        return route.fulfill(ok({ setup_required: Boolean(st.setupRequired) }));
      case "POST /api/v1/auth/setup":
        st.setupRequired = false;
        return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify(user) });
      case "POST /api/v1/auth/login": {
        const b = body as { login: string; password: string };
        if (b.password !== "Correct-Horse-1") return route.fulfill(problem(401, "unauthorized", "Неверный логин или пароль."));
        st.me = st.afterLogin ?? meOf("active");
        return route.fulfill(ok(st.me, true));
      }
      case "POST /api/v1/auth/mfa/verify": {
        const b = body as { code?: string };
        if (b.code !== st.goodCode) return route.fulfill(problem(400, "invalid_request", "Неверный код."));
        st.me = st.afterVerify ?? meOf("active", ["session", "self", "system.read"]);
        return route.fulfill(ok(st.me));
      }
      case "POST /api/v1/auth/password":
        st.me = st.afterPassword ?? meOf("active");
        return route.fulfill({ status: 204 });
      case "POST /api/v1/auth/logout":
        st.me = null;
        return route.fulfill({ status: 204 });
      default:
        return route.fulfill(problem(404, "not_found", "Нет такого маршрута."));
    }
  });
  return st;
}
