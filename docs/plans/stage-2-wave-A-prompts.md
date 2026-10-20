# Этап 2, волна A: промпты для трёх потоков

Волна A плана `docs/plans/stage-2.md` («Параллельная работа»): задачи 2.1, 2.2 и 2.21 не зависят друг от друга и идут одновременно. Каждый промпт самодостаточен и запускается отдельным потоком из чата проекта.

Умолчания, пока владелец не решил иначе (20.10.2026):
- план этапа 2 и решения Р1–Р13 действуют в том виде, как предложены в `stage-2.md`;
- интеграционная ветка этапа 2 — `claude/stage-2-integration` от `main` (этап 1 влит PR #10);
- согласие на новую библиотеку поток спрашивает у владельца сам, до установки.

## A1. Задача 2.1 — PostgreSQL и `internal/store`
**Модель:** Sonnet 5.5, effort medium.

```
Поток A1 этапа 2: задача 2.1 из docs/plans/stage-2.md (PostgreSQL в docker compose, internal/store: пул pgx, встроенные SQL-миграции, aisec-cli migrate, org_id, UUIDv7, тесты на БД из make dev). Отвечай на русском. PR не создавать.
1. Ветки. git fetch origin. Интеграционная ветка — claude/stage-2-integration; если её нет, создай от origin/main и отправь. В свою рабочую ветку: git merge --ff-only origin/claude/stage-2-integration. Push в интеграционную ветку разрешаю; история только через merge: без rebase, amend и force-push.
2. Защита от повтора (docs/plans/roadmap.md): статус 2.1 в таблице stage-2.md, журнал и метка «задача 2.1 этапа 2» в git log. Готова или в работе — остановись и сообщи.
3. Захват: статус «в работе (дата)», коммит docs, git push origin HEAD:claude/stage-2-integration. Отклонён — fetch, merge, проверь снова.
4. Зависимость pgx/v5 не согласована. До установки — короткое обоснование мне (зачем, лицензия, активность, транзитивные из таблицы «Новые библиотеки») и жди «да». После — docs/cert/components.yaml, точные версии, go mod vendor. Пока ждёшь, делай то, что без pgx: compose, миграции на чистом SQL, исполнитель за интерфейсом.
5. Трогай только файлы потока A1: internal/store/, migrations/, deploy/compose/, cmd/aisec-cli (только migrate). SQL только параметризованный, у каждого вызова к БД — контекст и таймаут.
6. Go — с GOTOOLCHAIN=go1.27.2. golangci-lint и govulncheck в облаке не работают — их проверяет CI, так и напиши в отчёте. make check один раз перед коммитом задачи, в чат — итог.
7. Документы: docs/cert/attack-surface.md (порт БД, переменные окружения, команда migrate), components.yaml, README при необходимости; статус «готова» и строка журнала в stage-2.md. Коммит «feat: … (задача 2.1 этапа 2)», push в рабочую ветку и в интеграционную (перед этим fetch и merge).
Отчёт до 10 строк: что сделано, коммит, обновлённые документы, что проверить руками, вопросы.
```

## A2. Задача 2.2 — `internal/crypto`: пароли, AEAD, подпись, TOTP
**Модель:** Opus 5.5, effort high.

```
Поток A2 этапа 2: задача 2.2 из docs/plans/stage-2.md (internal/crypto: PasswordHasher на Argon2id, AEAD на AES-256-GCM, Signer/Verifier на Ed25519, метод TOTP по Р1, контрактные тесты профилей standard и gost; ADR-0006). Отвечай на русском. PR не создавать.
1. Ветки. git fetch origin. Интеграционная ветка — claude/stage-2-integration; если её нет, создай от origin/main и отправь. В свою рабочую ветку: git merge --ff-only origin/claude/stage-2-integration. Push в интеграционную ветку разрешаю; история только через merge: без rebase, amend и force-push.
2. Защита от повтора (docs/plans/roadmap.md): статус 2.2 в таблице stage-2.md, журнал и метка «задача 2.2 этапа 2» в git log. Готова или в работе — остановись и сообщи.
3. Захват: статус «в работе (дата)», коммит docs, git push origin HEAD:claude/stage-2-integration. Отклонён — fetch, merge, проверь снова.
4. Это internal/crypto: сначала короткий план (интерфейсы, параметры из Р1 и Р3, профиль gost — заглушка или отказ, тесты) и жди моего ответа. В том же сообщении — обоснование golang.org/x/crypto (только argon2; лицензия, транзитивные из таблицы «Новые библиотеки»). После согласия — docs/cert/components.yaml, точная версия, go mod vendor.
5. Трогай только internal/crypto/ и docs/adr/0006-*. Своих реализаций алгоритмов нет; секреты сравниваются за постоянное время; ограничение одновременных вычислений Argon2id (Р3); векторы RFC 6238 и RFC 8032 в тестах; fuzz для разбора закодированного хеша пароля.
6. Go — с GOTOOLCHAIN=go1.27.2. golangci-lint и govulncheck в облаке не работают — их проверяет CI, так и напиши в отчёте. make check один раз перед коммитом задачи, в чат — итог. Затем cert-reviewer на дифф задачи; важные замечания исправь до коммита.
7. Документы: ADR-0006, docs/cert/security-functions.md, components.yaml; статус «готова» и строка журнала в stage-2.md. Коммит «feat: … (задача 2.2 этапа 2)», push в рабочую ветку и в интеграционную (перед этим fetch и merge).
Отчёт до 10 строк: что сделано, коммит, обновлённые документы, что проверить руками, вопросы.
```

## A3. Задача 2.21 — инструменты фронтенда
**Модель:** Sonnet 5.5, effort medium.

```
Поток A3 этапа 2: задача 2.21 из docs/plans/stage-2.md (npm, TypeScript, Vite, Tailwind, eslint с плагинами безопасности, vitest, Playwright; сборка без сети из package-lock.json, встраивание статики в aisec-server через embed, licenses и sbom для npm, фронтенд в make check; решение Р12). Отвечай на русском. PR не создавать.
1. Ветки. git fetch origin. Интеграционная ветка — claude/stage-2-integration; если её нет, создай от origin/main и отправь. В свою рабочую ветку: git merge --ff-only origin/claude/stage-2-integration. Push в интеграционную ветку разрешаю; история только через merge: без rebase, amend и force-push.
2. Защита от повтора (docs/plans/roadmap.md): статус 2.21 в таблице stage-2.md, журнал и метка «задача 2.21 этапа 2» в git log. Готова или в работе — остановись и сообщи.
3. Захват: статус «в работе (дата)», коммит docs, git push origin HEAD:claude/stage-2-integration. Отклонён — fetch, merge, проверь снова.
4. Это сборка и зависимости: сначала короткий план и список npm-пакетов из ТЗ 11.2 с лицензиями и числом транзитивных, жди моего «да». Разрешены MIT, BSD-2/3, Apache-2.0, ISC, OFL; версии точные. После согласия — docs/cert/components.yaml.
5. Трогай только web/, цели фронтенда в Makefile, tools/license-check, tools/sbom и строку embed в cmd/aisec-server. Без CDN и внешних шрифтов; без dangerouslySetInnerHTML, eval, new Function — правило eslint на каждое.
6. Go — с GOTOOLCHAIN=go1.27.2. golangci-lint и govulncheck в облаке не работают — их проверяет CI; npm в облаке может быть недоступен — тогда так и скажи и проверь в CI. make check один раз перед коммитом задачи, в чат — итог.
7. Документы: components.yaml, docs/cert/attack-surface.md (если появились переменные окружения или цели сборки), web/README.md; статус «готова» и строка журнала в stage-2.md. Коммит «build: … (задача 2.21 этапа 2)», push в рабочую ветку и в интеграционную (перед этим fetch и merge).
Отчёт до 10 строк: что сделано, коммит, обновлённые документы, что проверить руками, вопросы.
```
