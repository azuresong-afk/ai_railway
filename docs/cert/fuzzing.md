# Фаззинг

Черновик этапа 0. Цели фаззинга, параметры прогонов, покрытие и найденные дефекты (ТЗ, 8.5).

## Как запускать
- `make fuzz-smoke` — каждая fuzz-цель репозитория по `FUZZTIME` (по умолчанию 10 с); входит в `make check` и выполняется на каждый pull request.
- `make fuzz-long` — каждая цель по `FUZZTIME_LONG` (по умолчанию 10 мин); ночной прогон в CI.
- Цели находятся автоматически: все функции `Fuzz*` во всех пакетах модуля (`tools/scripts/fuzz.sh`). Если целей нет, прогон падает.
- Начальные корпуса задаются в тестах (`f.Add`) и в `testdata/fuzz/<цель>/` каталога пакета; туда же Go сохраняет найденные падения — их нужно закоммитить вместе с исправлением (ТЗ, 8.5).

## Цели
| Цель | Пакет | Что проверяет | Задача |
|---|---|---|---|
| `FuzzLocalLinks` | `tools/docs-check` | Разбор ссылок в markdown | 0.3 |
| `FuzzParseReport` | `tools/lintcheck` | Разбор JSON-отчёта линтера | 0.4 |
| `FuzzParseMarkers` | `tools/lintcheck` | Разбор маркеров самопроверки | 0.4 |
| `FuzzParse` | `tools/internal/components` | Разбор реестра `components.yaml` со строгой схемой | 0.7 |
| `FuzzParseModulesTxt` | `tools/internal/components` | Разбор `vendor/modules.txt` | 0.7 |
| `FuzzParseSARIF` | `tools/sast-triage` | Разбор отчёта SARIF 2.1.0 | 0.5 |
| `FuzzParseTriage` | `tools/sast-triage` | Разбор файла разметки SAST | 0.5 |
| `FuzzParseBOM` | `tools/sbom` | Разбор SBOM CycloneDX и проверка обязательных полей | 0.8 |
| `FuzzParseMatrix` | `tools/dm-coverage` | Разбор матрицы 5.16 из ТЗ | 0.9 |
| `FuzzParseGoTestJSON` | `tools/dm-coverage` | Разбор отчёта `go test -json` | 0.9 |
| `FuzzParseJUnit` | `tools/dm-coverage` | Разбор отчёта JUnit XML | 0.9 |
| `FuzzParseCovers` | `tools/dm-coverage` | Разбор маркеров «Покрывает:» | 0.9 |
| `FuzzParseChatRequest` | `internal/mockllm` | Разбор запроса chat/completions (строка или массив частей в `content`) | 0.11 |
| `FuzzChatCompletionsHandler` | `internal/mockllm` | Обработчик входящих HTTP-запросов mock-llm: любой ответ-ошибка — JSON в формате OpenAI | 0.11 |
| `FuzzEvalExpression` | `tools/internal/components` | Разбор выражений лицензий SPDX; выражение из разрешённых лицензий всегда разрешено | 0.7 |

## Кампании и результаты
| Дата | Цель | Что найдено | Исправление |
|---|---|---|---|
| 30.09.2026 | `FuzzParseSARIF` (fuzz-smoke) | URI `file://` проходил проверку на пустоту, а после отрезания префикса давал срабатывание с пустым путём | Проверка после нормализации пути; вход сохранён в `tools/sast-triage/testdata/fuzz/FuzzParseSARIF/` как регрессионный |
