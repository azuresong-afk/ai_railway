# Веб-консоль

Каркас инструментов фронтенда (задача 2.21 этапа 2, [ADR-0011](../docs/adr/0011-instrumenty-frontenda.md)): TypeScript, React, Vite, Tailwind CSS, ESLint с плагином безопасности, Vitest, Playwright. Экраны, дизайн-система и вход появятся в задачах 2.22–2.24.

## Требования
Node.js ≥ 22.12 и npm. Зависимости ставятся только из `package-lock.json`, без скриптов установки и без `audit`, `fund`, проверки обновлений (`.npmrc`). Источник пакетов — только `registry.npmjs.org`.

## Команды (из корня репозитория)
| Цель | Что делает |
|---|---|
| `make web-deps` | `npm ci --ignore-scripts` по lock-файлу (сеть или кэш npm) |
| `make web-deps-offline` | то же без сети, только из кэша npm |
| `make web-lint` | ESLint: запреты `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function`, `localStorage`/`sessionStorage`, абсолютных URL |
| `make web-typecheck`, `make web-test` | типы (`tsc`) и модульные тесты (Vitest) |
| `make web-api-types` / `web-api-check` | типы из `api/openapi.yaml` в `src/api/schema.d.ts` / проверка, что они не устарели |
| `make web-build` | статика в `web/dist` (встраивается в `aisec-server` при `go build`, пакет `web`) |
| `make web-e2e` | Playwright: консоль в Chromium при строгом CSP (ТЗ, 6.9) |
| `make web-check` | всё выше, кроме e2e |

`make check` включает `web-check` и `web-e2e`, если на машине есть `npm`; без него они выводятся как невыполненные.

## Правила
- Новый npm-пакет — только с согласия владельца и записью в `docs/cert/components.yaml` (`type: npm-package`, точная версия). `make licenses` сверяет `package.json`, lock-файл и реестр и проверяет лицензии всех пакетов.
- Лицензии: пакеты поставки (достижимые из `dependencies`) — MIT, BSD-2/3, Apache-2.0, ISC, OFL. Для пакетов только сборочной среды (`devDependencies`) по решению владельца от 20.10.2026 допускаются ещё MPL-2.0 (`lightningcss`, нужен Vite 8 и Tailwind 4), 0BSD, MIT-0, BlueOak-1.0.0, CC0-1.0, CC-BY-4.0 (данные), Python-2.0. Исключение: 0BSD у `tslib` (зависимость `echarts`, в поставке) подтверждено владельцем 21.10.2026.
- Никаких CDN, внешних шрифтов, скриптов и стилей; шрифты и иконки — локально. Сборка не создаёт встроенных скриптов и стилей, интерфейс работает при CSP без `'unsafe-inline'`.
- Playwright не скачивает браузеры. Браузер берётся из `PLAYWRIGHT_BROWSERS_PATH` сборочного образа; путь к исполняемому файлу можно задать `AISEC_CHROMIUM`.
- `src/api/schema.d.ts` генерируется, руками не правится.

## Radix UI и строгий CSP (задача 2.22, [ADR-0010](../docs/adr/0010-radix-ui-i-strogiy-csp.md))
Макет всех нужных примитивов — `#/dev/radix`, проверка — `e2e/radix.spec.ts` (падает на любом нарушении CSP, ошибке консоли и элементе `<style>`).
- Работают как есть: `popover`, `tooltip`, `tabs`, `checkbox`, `switch`, `radio-group`, `collapsible`, `label`, `toast`.
- Работают через замену `react-remove-scroll` (алиас в `vite.config.ts`, `src/shims/remove-scroll.tsx`): `dialog`, `alert-dialog`, `dropdown-menu`.
- Не используются (вставляют `<style>`): `select` — вместо него родной `<select>`; `scroll-area` — нативная прокрутка.
- Новый примитив Radix сначала добавляется в макет и e2e.
