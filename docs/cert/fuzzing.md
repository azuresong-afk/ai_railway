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
| `FuzzParseUpstreamURL` | `internal/config` | Адрес провайдера: только https, без учётных данных и параметров | 0.12 |
| `FuzzProxyHandler` | `internal/gateway` | Обработчик входящих HTTP-запросов шлюза (аутентификация, разбор, маршрутизация, провайдер): перебираются метод, путь со строкой запроса, тело, `Content-Type` и произвольный заголовок. Запрос без `Authorization` получает действующий ключ приложения, фаззинг может его заменить. Ожидается: только коды 200, 400, 401, 404, 405, 413, 415; провайдеру уходят только собранный заново объект JSON, заголовки шлюза и никакой строки запроса | 0.13, 1.7 |
| `FuzzParse` | `internal/ids` | Разбор UUIDv7: принимаются только версия 7 и вариант RFC 9562 | 1.1 |
| `FuzzParseAppKey` | `internal/auth` | Разбор предъявленного ключа приложения | 1.3 |
| `FuzzParseGatewayFile` | `internal/config` | Файл конфигурации шлюза со строгой схемой | 1.3 |
| `FuzzParse` | `internal/chat` | Запрос chat/completions: для принятого запроса сборка устойчива, в собранном теле только известные поля, фрагменты для детекторов совпадают с отправляемыми провайдеру | 1.5 |
| `FuzzReader` | `internal/sse` | Поток SSE провайдера: окончания строк CR, LF, CRLF, комментарии, BOM; без паники, в пределах лимитов строки и события, записанное событие читается обратно тем же | 1.6 |
| `FuzzAssembler` | `internal/chat` | Сборка потокового ответа из частей: без паники и сверх пределов памяти; текст варианта — конкатенация приращений | 1.6 |
| `FuzzToGigaChat` | `internal/providers` | Перевод принятого шлюзом запроса в формат GigaChat: всегда валидный JSON или ошибка 400 для приложения | 1.8 |
| `FuzzGigaChatChunk` | `internal/providers` | Перевод части потока GigaChat: без паники, только вариант 0 | 1.8 |
| `FuzzToYandexGPT` | `internal/providers` | Перевод принятого шлюзом запроса в формат YandexGPT: всегда валидный JSON или ошибка 400 для приложения | 1.9 |
| `FuzzYandexGPTStreamDelta` | `internal/providers` | Приращения потока YandexGPT из накопленного текста: склейка приращений всегда равна накопленному тексту | 1.9 |
| `FuzzParse` | `internal/detect/corpus` | Разбор корпуса детектора (JSONL со строгой схемой): принятые примеры проходят проверку схемы | 1.10 |
| `FuzzParseTable` | `tools/detector-quality` | Таблица детекторов в `docs/detectors.md`: метрики только 0–1 | 1.10 |
| `FuzzDetect` | `internal/detect/pii` | Детектор `pii.ru`: без паники, находки проходят проверку реестра, значение по позициям проходит свою контрольную сумму | 1.11 |
| `FuzzAuthenticate` | `internal/auth` | Заголовок `Authorization` и проверка ключа: всегда ровно один исход (вход или отказ с причиной), вход — только с выпущенным ключом | 1.4 |
| `FuzzEvalExpression` | `tools/internal/components` | Разбор выражений лицензий SPDX; выражение из разрешённых лицензий всегда разрешено | 0.7 |

## Кампании и результаты
| Дата | Цель | Что найдено | Исправление |
|---|---|---|---|
| 30.09.2026 | `FuzzParseSARIF` (fuzz-smoke) | URI `file://` проходил проверку на пустоту, а после отрезания префикса давал срабатывание с пустым путём | Проверка после нормализации пути; вход сохранён в `tools/sast-triage/testdata/fuzz/FuzzParseSARIF/` как регрессионный |
