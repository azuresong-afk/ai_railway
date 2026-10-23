import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type ModelPrice = S["ModelPrice"];
export type NewModelPrice = S["NewModelPrice"];
export type BudgetStatus = S["BudgetStatus"];
export type BudgetFields = S["BudgetFields"];

const id = encodeURIComponent;

// Права проверяет сервер, консоль только скрывает недоступное. Суммы — десятичные строки.
export const usageApi = {
  prices: (signal?: AbortSignal) => request<S["ModelPriceList"]>("GET", "/api/v1/model-prices", undefined, signal),
  createPrice: (b: NewModelPrice) => request<ModelPrice>("POST", "/api/v1/model-prices", b),
  updatePrice: (pid: string, b: S["ModelPriceFields"]) => request<ModelPrice>("PUT", `/api/v1/model-prices/${id(pid)}`, b),
  removePrice: (pid: string) => request<void>("DELETE", `/api/v1/model-prices/${id(pid)}`),
  budgets: (signal?: AbortSignal) => request<S["BudgetStatusList"]>("GET", "/api/v1/budgets", undefined, signal),
  setBudget: (appId: string, b: BudgetFields) => request<BudgetStatus>("PUT", `/api/v1/applications/${id(appId)}/budget`, b),
  removeBudget: (appId: string) => request<void>("DELETE", `/api/v1/applications/${id(appId)}/budget`),
};

// Десятичная строка: целая часть из цифр и не больше maxFrac знаков после точки (линейный разбор, без регулярных выражений).
function decimal(v: string, maxInt: number, maxFrac: number): boolean {
  const [int = "", frac, ...rest] = v.split(".");
  const digits = (x: string) => x.length > 0 && [...x].every((c) => c >= "0" && c <= "9");
  if (rest.length > 0 || !digits(int) || int.length > maxInt) return false;
  return frac === undefined || (digits(frac) && frac.length <= maxFrac);
}

// Сумма бюджета в рублях: до десяти знаков до точки, до двух после.
export const validBudget = (v: string): boolean => decimal(v, 10, 2);
// Цена за 1 000 токенов: до четырёх знаков после точки.
export const validPrice = (v: string): boolean => decimal(v, 7, 4);
