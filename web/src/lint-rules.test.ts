// @vitest-environment node
import { ESLint } from "eslint";

// Запреты фронтенда из CLAUDE.md должны действительно срабатывать.
const eslint = new ESLint({ cwd: process.cwd() });

async function messages(code: string): Promise<string[]> {
  const [res] = await eslint.lintText(code, { filePath: "src/probe.tsx" });
  return (res?.messages ?? []).map((m) => `${m.ruleId}: ${m.message}`);
}

const banned: [string, string, string][] = [
  ["dangerouslySetInnerHTML", "export const A = () => <div dangerouslySetInnerHTML={{ __html: 'x' }} />;", "dangerouslySetInnerHTML"],
  ["innerHTML", "document.body.innerHTML = 'x';", "innerHTML"],
  ["insertAdjacentHTML", "document.body.insertAdjacentHTML('beforeend', 'x');", "insertAdjacentHTML"],
  ["document.write", "document.write('x');", "document.write"],
  ["eval", "eval('1');", "no-eval"],
  ["new Function", "new Function('return 1');", "no-new-func"],
  ["setTimeout со строкой", "setTimeout('f()', 1);", "no-implied-eval"],
  ["localStorage", "localStorage.setItem('t', 'x');", "localStorage"],
  ["sessionStorage", "sessionStorage.getItem('t');", "sessionStorage"],
  ["внешний URL", "export const u = 'https://cdn.example.com/x.js';", "Абсолютные URL"],
];

describe("запреты eslint", () => {
  it.each(banned)("%s", async (_name, code, want) => {
    const got = await messages(code);
    expect(got.some((m) => m.includes(want))).toBe(true);
  });

  it("безопасный код проходит", async () => {
    expect(await messages("export const t = (s: string) => s.trim();")).toEqual([]);
  });
});
