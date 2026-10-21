import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import security from "eslint-plugin-security";
import reactHooks from "eslint-plugin-react-hooks";

// Запреты фронтенда из CLAUDE.md: каждый — отдельным правилом.
const banned = [
  { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: "dangerouslySetInnerHTML запрещён (ТЗ, 6.9)." },
  { selector: "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]", message: "innerHTML/outerHTML запрещены: выводите текст через React." },
  { selector: "CallExpression[callee.property.name='insertAdjacentHTML']", message: "insertAdjacentHTML запрещён." },
  { selector: "CallExpression[callee.property.name='write'][callee.object.name='document']", message: "document.write запрещён." },
  { selector: "Literal[value=/^https?:\\/\\//]", message: "Абсолютные URL запрещены: никаких внешних обращений (CLAUDE.md, «Сеть»)." },
];

export default tseslint.config(
  { ignores: ["dist", "node_modules", "src/api/schema.d.ts", "playwright-report", "test-results"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  security.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
      "no-restricted-syntax": ["error", ...banned],
      // Токены не хранятся в localStorage/sessionStorage (CLAUDE.md, «Фронтенд»).
      "no-restricted-globals": ["error",
        { name: "localStorage", message: "Хранилище браузера запрещено для токенов и данных." },
        { name: "sessionStorage", message: "Хранилище браузера запрещено для токенов и данных." }],
      "no-restricted-properties": ["error",
        { object: "window", property: "localStorage", message: "Запрещено." },
        { object: "window", property: "sessionStorage", message: "Запрещено." },
        { object: "globalThis", property: "eval", message: "Запрещено." },
        { object: "window", property: "eval", message: "Запрещено." }],
    },
  },
  {
    // Конфигурации и e2e работают в Node; абсолютные URL допустимы в тестах.
    files: ["*.config.{js,ts}", "e2e/**"],
    languageOptions: { globals: globals.node },
    rules: { "no-restricted-syntax": "off" },
  },
);
