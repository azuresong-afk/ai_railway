# Правила безопасного кодирования

Черновик этапа 0. Основа — правила из `CLAUDE.md` плюс разделы по Go, TypeScript и SQL (ТЗ, 8.3). Всё, что можно проверить автоматически, проверяется автоматически.

## Общие правила
Заполняется в задаче 0.16 плана этапа 0.

## Go
Заполняется в задаче 0.16 плана этапа 0.

## SQL
Заполняется в задаче 0.16 плана этапа 0.

## TypeScript
Заполняется в задаче 0.16 плана этапа 0.

## Что проверяется автоматически
Конфигурация — `.golangci.yml`, запуск — `make lint`. Работу запретов доказывает `make lint-selftest`: образец `tools/lintcheck/testdata/sample` содержит заведомые нарушения с маркерами `// want:<линтер>` и разрешённые случаи с маркерами `// clean:<линтер>`; утилита `tools/lintcheck` запускает линтеры и сверяет замечания с маркерами. Если правило ослабить, самопроверка падает.

| Правило | Как проверяется |
|---|---|
| Криптография только в `internal/crypto` (`crypto/*`, `golang.org/x/crypto/*`) | depguard, правило `crypto`; действует и в тестах, и в `tools/` |
| Без `unsafe`, `math/rand` (в том числе `math/rand/v2`), `net/http/pprof` | depguard, правило `unsafe-and-rand`; во всём коде |
| Без `os/exec` в серверных компонентах | depguard, правило `server-exec`: `cmd/aisec-gateway`, `cmd/aisec-server`, `cmd/aisec-media`, `internal/` |
| Без `reflect` в обход типов | depguard, правило `product-reflect`: `internal/` кроме тестов; исключение — `//nolint:depguard` с обоснованием |
| Технические логи только через `log/slog`; без `print`, `fmt.Print*`, `log.Print*` | forbidigo |
| Исходящие HTTP-запросы с контекстом | noctx |
| Ошибки проверяются | errcheck, errorlint, nilerr, gosec G104 |
| Закрытие тел ответов, строк и выражений SQL | bodyclose, rowserrcheck, sqlclosecheck |
| Проверки безопасности | gosec в режиме аудита |
| Каждое подавление — с линтером и обоснованием | nolintlint (`require-specific`, `require-explanation`) |
| Форматирование | gofmt (`make fmt-check` и форматтер в golangci-lint) |

Замечания не схлопываются по строке (`uniq-by-line: false`): иначе одно замечание скрывает другое на той же строке — это было обнаружено самопроверкой.

## Чек-лист ревью
Заполняется в задаче 0.16 плана этапа 0.
