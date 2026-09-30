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
| Криптография только в `internal/crypto` (`crypto/*`, `golang.org/x/crypto/*`) | depguard, правило `crypto`; действует и в тестах, и в `tools/`. Каталог `internal/crypto` в модуле ровно один — `./internal/crypto` (`make repocheck`), иначе вложенный `…/internal/crypto` снял бы запрет. Утилиты проверки пропускают `vendor/`, `build/`, `bin/`, `node_modules/` только в корне репозитория, а `testdata/` — на любой глубине: вложенный каталог с таким именем Go собирает, и пропуск открыл бы обход |
| Без `unsafe`, `math/rand` (в том числе `math/rand/v2`), `net/http/pprof`, `plugin` | depguard, правило `unsafe-and-rand`; во всём коде |
| Без `os/exec` в серверных компонентах | depguard, правило `server-exec`: `cmd/aisec-gateway`, `cmd/aisec-server`, `cmd/aisec-media`, `internal/`; там же запрещён `syscall` (исключение — по ADR с `//nolint:depguard`). Обходы через `os.StartProcess` и `syscall.Exec`/`ForkExec`/`StartProcess` ловит forbidigo во всём коде |
| Без `reflect` в обход типов | depguard, правило `product-reflect`: `cmd/aisec-gateway`, `cmd/aisec-server`, `cmd/aisec-media`, `internal/` кроме тестов; исключение — `//nolint:depguard` с обоснованием |
| cgo — только по ADR | `make repocheck`: файлы с `import "C"` разрешены только в путях из `CGO_ALLOWED` в `Makefile` (сейчас пусто). `make lint` и `make vet` идут с `CGO_ENABLED=1`, чтобы линтеры видели и файлы с cgo |
| Технические логи только через `log/slog`; без `print`, `fmt.Print*`, `log.Print*` | forbidigo с анализом типов: псевдоним импорта (`import f "fmt"`) запрет не обходит |
| Исходящие HTTP-запросы с контекстом | noctx |
| Ошибки проверяются | errcheck, errorlint, nilerr, gosec G104 |
| Закрытие тел ответов, строк и выражений SQL | bodyclose, rowserrcheck, sqlclosecheck |
| Проверки безопасности | gosec в режиме аудита — только в `make sast` (срабатывания размечаются в `docs/cert/sast-triage/`); `make sast` входит в `make check` |
| Каждое подавление — с линтером и обоснованием | nolintlint (`require-specific`, `require-explanation`) |
| Срабатывания SAST размечены | `make sast`: gosec в SARIF, сверка с `docs/cert/sast-triage/triage.yaml`, перечень подавлений `//nolint:gosec` (формат — `docs/cert/sast-triage/README.md`) |
| Форматирование | gofmt (`make fmt-check` и форматтер в golangci-lint) |

Самопроверка сверяет только размеченные строки: неразмеченные замечания в образце не считаются ошибкой. Образец собирается без сети (`GOPROXY=off`, `-mod=readonly`), а `golang.org/x/crypto` в нём подменён локальной заглушкой.

Замечания не схлопываются по строке (`uniq-by-line: false`): иначе одно замечание скрывает другое на той же строке — это было обнаружено самопроверкой.

## Чек-лист ревью
Заполняется в задаче 0.16 плана этапа 0.
