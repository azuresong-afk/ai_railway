# Сквозные тесты (e2e)

Тег сборки `e2e`: `go test -tags e2e ./test/e2e/ -bin build/bin` (или `make e2e`; цель зависит от `make manifest`).

| Файл | Что проверяет |
|---|---|
| `e2e_test.go`, `stage1_test.go` | этап 1: шлюз и mock-llm по TLS, строки матрицы обнаружения (`TestE2EDM…`) |
| `stage2_stand_test.go` | стенд этапа 2: настоящие `aisec-cli`, `aisec-server`, БД PostgreSQL на каждый тест, вход с паролем и TOTP |
| `stage2_test.go` | блокировка входа (DM-39), подмена бинарника и статики (DM-42), правка журнала аудита (DM-43), матрица «роль × эндпоинт», заголовки CSP |
| `stage2_bundle_test.go` | DM-42 для пакета политик: между шлюзом и сервером прокси теста; подменённый байт, подпись чужого ключа, откат, повреждённый и подменённый `bundle.json` |
| `stage2_console_live_test.go` | сквозной сценарий консоли в Chromium на настоящем сервере (`web/e2e/live.spec.ts`) |
| `pilot_stand_test.go`, `testdata/pilot/compose.e2e.yaml`, `netwatch/` | стенд пилота в docker compose (этап 3): установка по `install-pilot.md`, все сети внутренние, провайдер — mock-llm, ловушка сети `netwatch` (вышестоящий DNS и приёмник соединений) |
| `pilot_offline_test.go` | 3.7: установка и рабочий путь без выхода наружу; ловушка видит только провайдера, заданного администратором |
| `pilot_restore_test.go` | 3.8: `backup.sh`, потеря установки, `restore.sh` в пустую установку; вход, события, цепочка аудита, шлюз принимает пакеты |
| `pilot_scripts_test.go` | 3.8: отказы `backup.sh` и `restore.sh` на недоверенном каталоге и архиве копии (заглушка `docker`, нужен только root) |

## Окружение
- `AISEC_TEST_DATABASE_URL` — суперпользователь тестовой PostgreSQL (`postgres://aisec:…@127.0.0.1:5432/aisec_test?sslmode=disable`); тесты этапа 2 создают отдельную БД и роль на каждый тест. Без переменной они пропускаются. В CI БД поднимает сервис `postgres:17.6-alpine` (ADR-0002, дополнение); локально и в облаке: `pg_ctlcluster 16 main start`.
- Сценарий консоли дополнительно требует `web/node_modules` (`make web-deps`), консоль в бинарнике (`make web-build`, затем `make build manifest`) и браузер (`AISEC_CHROMIUM` или `PLAYWRIGHT_BROWSERS_PATH`); иначе пропускается с причиной. В CI Node.js нет.

Тесты пилота (`TestE2EPilot_…`, `TestE2EPilotScripts_…`) запускает `make e2e-pilot` (после `make images-test`): нужны Docker с compose и root (`prepare-host.sh` создаёт пользователей хоста `aisec`, `aisec-gw`, `aisec-db`; не от root цель вызывает `sudo -n`). Без `AISEC_E2E_PILOT=1` они пропускаются. Образ PostgreSQL из своего реестра — `AISEC_POSTGRES_IMAGE` (в облаке Docker Hub отвечает 429: `mirror.gcr.io/library/postgres`).

## Правило имён
Тест, зависящий от живой БД или браузера, не называется `TestDMxx_…`: `make dm-coverage` считает пропуск такого теста провалом строки матрицы. Строки покрываются модульными тестами; сквозные дополняют их (`TestE2EStage2_…`).
