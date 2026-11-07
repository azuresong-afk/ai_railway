# ADR-0034. Пакеты deb и rpm и юниты systemd: установка без Docker

- Статус: принято (решения Р1 и Р2 плана этапа 6, план подтверждён владельцем 06.11.2026; подробности — поток A1). Инструменты сборки `dpkg-deb` и `rpmbuild` (раздел 9) — только после отдельного согласия владельца, записанного в «Ждут решения владельца» `docs/plans/stage-6.md`.
- Дата: 06.11.2026
- Связанные разделы ТЗ: 3.1, 5.17, 7.6 (ОБН.1), 7.9 (ЗИ.5, ЗИ.7), 8.7, 10.4, 11.3 (`deploy/packaging`), 14 (этап 6); решения Р1, Р2 плана этапа 6; ADR-0012, ADR-0019, ADR-0022, ADR-0024, ADR-0032, ADR-0033; задачи 6.14–6.17.

## Контекст
Сейчас продукт ставится только в docker compose (ADR-0019). Госсектор и КИИ работают на сертифицированных отечественных ОС, где Docker часто запрещён или не сертифицирован, а коммерческим заказчикам пакеты ОС привычнее. ТЗ требует ЗИ.5 для пакетов на этапе 6 и допускает изоляцию `aisec-media` «средствами systemd или контейнера без сети» (ЗИ.7). Ограничения:
- Изоляция без Docker не слабее, чем в compose (ТЗ 5.17; риск в плане этапа 5): свой пользователь на службу, без сети у `aisec-media` и `aisec-ml`, тот же список системных вызовов у `aisec-media`, те же пределы памяти, процессора и числа процессов.
- Бинарники, манифест и его подпись — те же файлы, что в каталоге выпуска и в образах (ADR-0019, ADR-0022): пакет не пересобирает и не переподписывает их, иначе воспроизводимость (6.22) и проверка `aisec-cli verify` теряют смысл.
- `aisec-ml` и `aisec-media` с OCR собраны с загрузчиком и `RPATH` `/opt/aisec/lib` (Makefile, `ML_LIB_PATH`), и у каждого свой выпуск и свой манифест (`build/release-ml`, `build/release-media`). На одном хосте два таких выпуска не помещаются в один `/opt/aisec`.
- Проверка ключей в коде: файл ключа не доступен группе и остальным (`KeyFilePermsOK`, 0600 или 0400); владелец не проверяется.
- Целевые ОС (Р1): Astra Linux Special Edition 1.8 (deb), РЕД ОС 8 (rpm), Альт 11 (rpm), systemd — из состава ОС. В облаке есть только systemd 255 без PID 1: юниты здесь можно проверить `systemd-analyze verify` и `security --offline`, но не запустить.
- Новые библиотеки — только с согласия владельца; Go-зависимостей пакеты не добавляют (Р1).

## Решение

### 1. Пакеты
Три пакета на каждый формат, версия пакета = версия выпуска (`VERSION` манифеста):

| Пакет | Содержимое | Зависит от |
|---|---|---|
| `aisec` | основной выпуск: `aisec-server`, `aisec-gateway`, `aisec-cli`, манифест и подпись; юниты сервера и шлюза; сценарии установки | `systemd` |
| `aisec-ml` | выпуск `aisec-ml`: бинарник, `lib/`, `models/`, свой манифест; юнит и дополнения юнитов шлюза и сервера | `aisec` той же версии |
| `aisec-media` | выпуск `aisec-media` (с OCR или без): бинарник, `lib/`, `models/`, свой манифест; юнит и дополнение юнита шлюза | `aisec` той же версии |

Сервер и шлюз в одном пакете, потому что основной манифест описывает все три бинарника: отдельные пакеты владели бы одним файлом манифеста, а `aisec-cli verify` на хосте с одним шлюзом не нашёл бы бинарник сервера. Какие службы запущены, решает администратор (`systemctl enable --now aisec-gateway` на узле шлюза). PostgreSQL в пакеты не входит и пакетом не требуется: это СУБД из репозитория ОС или СУБД заказчика (решение Р2 этапа 3 остаётся в силе), роли создаёт администратор по `prepare-host` (раздел 7).

### 2. Раскладка каталогов

| Путь | Владелец, права | Что |
|---|---|---|
| `/opt/aisec/` | `root:root`, каталоги 0755, файлы 0755/0644 | основной выпуск, как в образе: `bin/`, `aisec-manifest.json`, `.sig`; сервер и шлюз находят манифест по умолчанию (`../aisec-manifest.json`), флаги путей не нужны |
| `/opt/aisec-ml/opt/aisec/` | `root:root`, то же | дерево выпуска `aisec-ml` в том виде, как в образе; `/opt/aisec-ml` — корень службы (`RootDirectory=`, раздел 4); пустые точки монтирования `proc`, `sys`, `dev`, `run/aisec-ml`, `tmp` входят в пакет, чтобы systemd не создавал их сам вне учёта менеджера пакетов |
| `/opt/aisec-media/opt/aisec/` | `root:root`, то же | то же для `aisec-media` |
| `/etc/aisec/` | `root:root`, 0755 | настройки без секретов: `aisec-server.env`, `aisec-gateway.env`, `aisec-cli.env` (файлы конфигурации пакета, 0644), `peers.env` (создаёт `postinst`, раздел 3) |
| `/etc/aisec/credentials/` | `root:root`, 0700, файлы 0600 | секреты служб — источник `LoadCredential=` (раздел 5) |
| `/var/lib/aisec/` | `root:root`, 0755 | каталог над данными сервера, не монтируется службам на запись |
| `/var/lib/aisec/keys/` | `aisec:aisec`, 0700 | каталог ключей `aisec-cli init` (мастер-ключ, УЦ, подписи); сервер читает, пишет только `aisec-cli` |
| `/var/lib/aisec/backups/` | `aisec:aisec`, 0700 | резервные копии `aisec-cli backup` |
| `/var/lib/aisec-gateway/` | `root:root`, 0755 | каталог над состоянием шлюза (как `gateway/` в compose) |
| `/var/lib/aisec-gateway/reg/`, `state/` | `aisec-gw:aisec-gw`, 0700 | сертификат и ключ шлюза, ключ секретов пакета, последний пакет; `StateDirectory=` юнита шлюза |
| `/run/aisec-ml/`, `/run/aisec-media/` | `aisec-ml:aisec-gw` и `aisec-media:aisec-gw`, 0750 | сокеты; `RuntimeDirectory=` юнитов, сокет 0660 |
| журналы | journald | службы пишут в stdout и stderr; своих файлов журналов нет, ротация — настройками journald |

Каталоги `reg/` и `state/` создаёт systemd (`StateDirectory=aisec-gateway/reg aisec-gateway/state`): внутренние каталоги принадлежат пользователю службы, родительский — root. Поэтому шлюз, как и в compose, не может подменить `reg/` или `state/` символьной ссылкой, а сценарии пакета в эти каталоги не заходят. Каталоги сокетов существуют, только пока служба работает.

### 3. Пользователи и сокеты
- Системные пользователи с одноимённой группой, без входа и домашнего каталога (`useradd --system --user-group --no-create-home --home-dir /nonexistent --shell nologin`): `aisec` — сервер и `aisec-cli`; `aisec-gw` — шлюз; `aisec-ml`; `aisec-media`. Пользователя СУБД пакет не создаёт. Существующий пользователь не меняется.
- `aisec-ml` и `aisec-media` работают с основной группой `aisec-gw` (`Group=aisec-gw`), как в compose: группа нужна только для доступа шлюза к каталогу сокета.
- Собеседник по сокету — только шлюз: `-peer-uid` и `-peer-gid` = UID и GID `aisec-gw` (`SO_PEERCRED`, ADR-0024 раздел 2, ADR-0032 раздел 2). Числовые значения известны только после `useradd`, поэтому `postinst` пакета `aisec` пишет их в `/etc/aisec/peers.env` (0644, без секретов) при каждой настройке пакета, а юниты читают этот файл (`EnvironmentFile=`). Без файла `aisec-ml` и `aisec-media` не запускаются: флаги обязательны.
- `PrivateUsers=` у шлюза, `aisec-ml` и `aisec-media` не включается: в своём пространстве имён пользователей UID собеседника виден как 65534, и проверка `SO_PEERCRED` отвергала бы шлюз.

### 4. Юниты
Все юниты — `Type=exec`, `Restart=on-failure`, `UMask=0077`, общий набор ограничений:
- `NoNewPrivileges=yes`, `CapabilityBoundingSet=` и `AmbientCapabilities=` пустые (порты 8443–8445 больше 1024), `RestrictSUIDSGID=yes`;
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `DevicePolicy=closed`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes`, `ProtectProc=invisible`, `KeyringMode=private`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `RestrictRealtime=yes`, `RestrictNamespaces=yes`, `RemoveIPC=yes`;
- `SystemCallArchitectures=native`, `SystemCallErrorNumber=EPERM` (отказ, как `defaultAction` профилей Docker, а не завершение процесса);
- `MemoryMax=` и `MemorySwapMax=0`, `TasksMax=`, у `aisec-media` — `CPUQuota=`;
- запись — только в свои каталоги (`StateDirectory=`, `RuntimeDirectory=`); остальная файловая система только для чтения.

Особенности служб:

| Служба | Пользователь | Сеть | Системные вызовы | Пределы | Запись |
|---|---|---|---|---|---|
| `aisec-server` | `aisec` | `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | `@system-service`, без `@privileged @resources` | `MemoryMax=1G`, `TasksMax=256` | нет (ключи — только чтение) |
| `aisec-gateway` | `aisec-gw` | то же | то же | `MemoryMax=1G`, `TasksMax=256` | `StateDirectory=aisec-gateway/reg aisec-gateway/state` |
| `aisec-ml` | `aisec-ml:aisec-gw` | `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` | `@system-service`, без `@privileged` (`@resources` нужен потокам ONNX Runtime, как в профиле Docker) | `MemoryMax=2G`, `TasksMax=256` | `RuntimeDirectory=aisec-ml` |
| `aisec-media` | `aisec-media:aisec-gw` | `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` | список `seccomp/aisec-media.json` (раздел 6) | `MemoryMax=1G`, `CPUQuota=400%`, `TasksMax=64` | `RuntimeDirectory=aisec-media` |

- **Свой корень у `aisec-ml` и `aisec-media`.** `RootDirectory=/opt/aisec-ml` (`/opt/aisec-media`), `MountAPIVFS=yes`, `BindPaths=/run/aisec-ml` (`/run/aisec-media`), `/tmp` — `TemporaryFileSystem=/tmp:size=16m,mode=1777,noexec,nosuid,nodev`. Служба видит то же дерево, что в образе на `scratch`: `/opt/aisec/bin`, `/opt/aisec/lib`, `/opt/aisec/models`, манифест. Загрузчик и `RPATH` `/opt/aisec/lib` указывают на библиотеки своего выпуска, самопроверка целостности сверяет те же файлы, которые загружает процесс, а файлы хоста (`/etc`, `/home`, `/var`, чужие выпуски) службе не видны вовсе. Это строже compose: там корень — образ, а здесь ещё и без `/etc/passwd` и прочих файлов хоста. Пути моделей, ONNX Runtime и манифеста в юнитах не задаются, как в compose.
- **Шлюз и анализаторы.** Пакеты `aisec-ml` и `aisec-media` кладут дополнения `/usr/lib/systemd/system/aisec-gateway.service.d/50-aisec-ml.conf` и `50-aisec-media.conf`: `Wants=` и `After=` анализатора, путь сокета в окружении шлюза (`AISEC_GATEWAY_ML_SOCKET`, `AISEC_GATEWAY_MEDIA_SOCKET`). Не `Requires=`: падение анализатора не останавливает шлюз (ADR-0032, раздел 8). Пакет `aisec-ml` добавляет и дополнение сервера с `AISEC_SERVER_ML_TEMPLATES=true`, как `compose.ml.yaml`. Удаление пакета анализатора удаляет и дополнение — шлюз возвращается к работе без него.
- **Бюджет растров `aisec-media` (5В4).** `MemoryMax=1G` и `-mem-limit=1g` по умолчанию совпадают, `-workers=2`, `-max-raster-mib` по умолчанию 320: `aisec-media` при запуске проверяет, что исполнители укладываются в `-mem-limit`. Администратор меняет память одним дополнением (`systemctl edit aisec-media`), где задаёт и `MemoryMax=`, и `Environment=AISEC_MEDIA_MEM_LIMIT=`; руководство говорит менять их вместе. `CPUQuota=400%` — как `cpus: 4` (решение владельца 04.11.2026); в отличие от Docker, квота больше числа процессоров не мешает запуску.
- **Настройки.** Несекретные параметры — переменные окружения из `/etc/aisec/<служба>.env` (`EnvironmentFile=`): у всех флагов есть переменные `AISEC_*`. Пути к секретам — флаги в `ExecStart=` со спецификатором `%d` (каталог учётных данных), администратор их не задаёт.
- **Порядок запуска.** Сервер — `After=network-online.target postgresql.service` без `Requires=` на СУБД (она может быть на другом узле). Шлюз — `After=network-online.target aisec-server.service`, без зависимости от сервера: работает и при недоступном сервере, как в compose.

### 5. Ключи и секреты
- Файлы TLS (`console.key`, `gateway.key` и сертификаты), корень сервера для шлюза, якорь пакетов `gateway-bundle-anchor.pub`, файлы паролей БД (`*.pgpass`) лежат в `/etc/aisec/credentials/` (0700 root, файлы 0600 root). Служба получает только свои через `LoadCredential=имя:/etc/aisec/credentials/файл`; systemd копирует их в `/run/credentials/<служба>/` (каталог только для чтения, недоступный другим службам) и делает файл доступным пользователю службы. Пути в `ExecStart=` — `%d/имя`.
- Пароль БД — в файле паролей pgx: `Environment=PGPASSFILE=%d/db-server-pgpass`, в строке подключения пароля нет, как в compose.
- Ожидаемые права копии в `/run/credentials`: если файловая система каталога учётных данных не поддерживает ACL (`ramfs`), systemd отдаёт файл во владение пользователю службы с правами 0400 — проверка `KeyFilePermsOK` проходит. Если systemd выдаёт доступ через ACL (`tmpfs`), маска ACL видна в правах группы (0440), и служба **откажется запускаться** с понятной ошибкой: защита не ослабляется молча. Это проверяется на каждой целевой ОС (ручная проверка в `docs/pilot/manual-checks.md`); принять каталог учётных данных как доверенный в `internal/crypto` — отдельное решение, если ручная проверка его потребует.
- Каталог ключей `/var/lib/aisec/keys` — не учётные данные, а каталог `aisec:aisec` 0700: его пишет `aisec-cli` (init, ротация ключей, ADR-0018), а сервер сверяет открытые ключи в нём с ожидаемыми (самопроверка целостности). Копия в `/run/credentials` сделала бы ротацию невидимой до перезапуска и сломала бы эту сверку. Сервер видит каталог только для чтения (`ProtectSystem=strict`).
- `aisec-cli` запускается от `aisec` через обёртку `/usr/sbin/aisec-cli` (только root): `systemd-run --wait --collect` с `User=aisec`, рабочим каталогом `/var/lib/aisec` (пути в аргументах — абсолютные), ограничениями сервера (отличия — `/home` только для чтения, чтобы `verify` читал выпуск, и запись в `/var/lib/aisec/keys` и `/var/lib/aisec/backups`), файлом паролей владельца схемы `db-owner.pgpass` через `LoadCredential=` и настройками `/etc/aisec/aisec-cli.env`. Служба сервера пароля владельца схемы не получает. **Остаточный риск:** сервер и `aisec-cli` — один пользователь `aisec` (каталог ключей принадлежит пользователю сервера, а `KeyFilePermsOK` не допускает доступа группы), поэтому взломанный процесс сервера, пока работает `aisec-cli`, может прочитать его учётные данные через `/proc/<pid>/root` или каталог `/run/credentials` и писать в каталог ключей через его пространство имён. В compose этого пути нет: контейнеры разделены пространствами имён PID. Устранение — отдельный пользователь для `aisec-cli` и владение ключами через `internal/crypto` (через план) — кандидат ревью 6.r1; до него `aisec-cli` запускается только на время административных действий.

### 6. Профиль seccomp `aisec-media` без Docker
`SystemCallFilter=` юнита `aisec-media` — тот же список имён, что в `deploy/compose/pilot/seccomp/aisec-media.json`, плюс:
- правило `clone` с маской флагов пространств имён в профиле Docker заменяет `RestrictNamespaces=yes` (systemd ставит фильтр на те же флаги `clone`, `unshare`, `setns`);
- правило `socket` только с `AF_UNIX` — `RestrictAddressFamilies=AF_UNIX`;
- `clone3` с `ENOSYS` (чтобы потоки glibc и ONNX Runtime перешли на проверяемый `clone`) — тоже `RestrictNamespaces=yes`: systemd отвечает на `clone3` кодом `ENOSYS`, потому что не может проверить его флаги. Поэтому `clone3` **входит** в список разрешённых юнита. Запись `~clone3:ENOSYS` в режиме списка разрешённых только убрала бы вызов, код ошибки при этом теряется, а последний установленный фильтр (`SystemCallFilter=`) ответил бы `EPERM` — glibc тогда не создаёт потоки, и `aisec-media` с OCR не запускается (замечание ревью по чек-листу `cert-reviewer`, 06.11.2026; вывод по коду systemd и ядра, подтверждается ручной проверкой 7);
- systemd всегда добавляет группу `@default` (время, сон, завершение, `getrlimit`, `getpid` и подобные) — это вызовы без побочных эффектов; разница перечислена в тесте.

Расхождение списков ловит тест в `tools/imagecheck`: имена из JSON (плюс `clone3`) и из юнита совпадают с точностью до перечисленной разницы `@default`, запретов «`~…`» в юните нет, есть `RestrictNamespaces=yes`, `RestrictAddressFamilies=AF_UNIX`, `PrivateNetwork=yes` и `SystemCallErrorNumber=EPERM`. Проверка юнитов идёт по перечню разрешённых ключей, каждая требуемая директива — ровно одной строкой: многие директивы systemd накапливаются, и лишняя строка выше нужной расширила бы права.

### 7. Установка, обновление, удаление
- **Сценарии пакета** (`preinst`, `postinst`, `prerm`, `postrm` для deb и `%pre`, `%post`, `%preun`, `%postun` для rpm) — один POSIX-сценарий на действие, общий для обоих форматов, `set -eu`, `umask 077`, только фиксированные пути, без сети, без чтения файлов из каталогов, куда пишут службы, без `chown -R` и без перехода по символьным ссылкам (`install -d` с проверкой, что путь — не ссылка). Они создают пользователей, каталоги из раздела 2, `peers.env` и выполняют `systemctl daemon-reload`. Службы при установке не включаются и не запускаются.
- **Подготовка хоста** — `/usr/sbin/aisec-prepare-host` (`deploy/packaging/prepare-host.sh`, запускает администратор после установки): создаёт пароли ролей БД из `/dev/urandom` в `/etc/aisec/credentials/` (не выводит их), пишет файлы `*.pgpass`, создаёт роли `aisec_owner`, `aisec_server` и БД в локальном PostgreSQL (`--create-roles`, SQL через стандартный ввод `psql`) или пишет этот SQL в новый файл 0600 для СУБД на другом узле (`--write-sql`), кладёт якорь пакетов шлюза (`--bundle-anchor`) и проверяет наличие файлов TLS; повторный запуск безопасен. Состав ролей — тот же, что `initdb/10-aisec-roles.sql`; текст с паролями не пишется в журнал СУБД и в `pg_stat_statements`.
- **Первый запуск**: `aisec-prepare-host` → роли в СУБД → `aisec-cli migrate` и `aisec-cli init` → копия `bundle-signing.pub` в `credentials/gateway-bundle-anchor.pub` → `systemctl enable --now aisec-server` → регистрация шлюза → `systemctl enable --now aisec-gateway` (и анализаторы). Полная процедура — руководство администратора, раздел «Установка без Docker».
- **Обновление пакета.** Перед установкой новый выпуск проверяет установленная версия (раздел 9, как `verify-release.sh` в ADR-0019). Пакет при обновлении **останавливает** свои службы в `prerm` (иначе самопроверка целостности работающих процессов сочла бы заменённые файлы нарушением, а `aisec-media` с `integrity-action=stop` перезапустился бы новым бинарником раньше шлюза) и **не запускает** их в `postinst`, миграции не выполняет. Администратор запускает службы в порядке: шлюзы → `aisec-cli migrate` → сервер → `aisec-ml` и `aisec-media` (шлюзы обновляются раньше сервера и `aisec-media`: ADR-0032, дополнение 03.11.2026, формат пакета F1c). Шаги обновления и отката одной командой — `aisec-cli update`, ADR-0036 (задачи 6.18–6.20).
- **Удаление** (`apt remove`, `rpm -e`): службы останавливаются и выключаются, удаляются бинарники, юниты и дополнения. Остаются: `/etc/aisec` с секретами, `/var/lib/aisec` (ключи, копии), `/var/lib/aisec-gateway` (регистрация и состояние шлюза), журналы journald, пользователи (чтобы новый пользователь с тем же UID не получил чужие файлы). `apt purge` удаляет только файлы конфигурации пакета и `peers.env`; ключи, секреты и данные удаляет администратор явно (руководство: порядок и что уничтожать).

### 8. Сравнение с compose (ЗИ.5, ЗИ.7)

| compose | systemd | Комментарий |
|---|---|---|
| `user:` из `prepare-host.sh` | `User=`, `Group=` | те же пользователи, кроме `aisec-db` (СУБД не входит) |
| `read_only: true` | `ProtectSystem=strict`, `ProtectHome=yes`; у анализаторов — `RootDirectory=` | у анализаторов файлы хоста не видны вовсе |
| `cap_drop: [ALL]` | `CapabilityBoundingSet=` пустой, `AmbientCapabilities=` пустой | |
| `no-new-privileges:true` | `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes` | |
| профиль seccomp Docker по умолчанию | `SystemCallFilter=@system-service`, без `@privileged` (у сервера и шлюза — и без `@resources`) | у сервера, шлюза и `aisec-ml` |
| `seccomp=./seccomp/aisec-media.json` | тот же список и `clone3` + `RestrictNamespaces=yes` (маска `clone`, `ENOSYS` у `clone3`), `RestrictAddressFamilies=AF_UNIX` | разница — `@default`, раздел 6 |
| `network_mode: none` | `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` | у `aisec-ml` и `aisec-media` |
| сети `db`, `control` `internal: true` | нет аналога | исходящие соединения сервера ограничивает код (repocheck, ЗИ.2) и межсетевой экран хоста, как и в compose для сервера |
| `mem_limit`, `memswap_limit` | `MemoryMax=`, `MemorySwapMax=0` | |
| `cpus` | `CPUQuota=` | |
| `pids_limit` | `TasksMax=` | |
| `tmpfs: /tmp` (`noexec,nosuid,nodev`, 16 МБ) у `aisec-media` | `TemporaryFileSystem=/tmp:size=16m,…,noexec,nosuid,nodev` | у остальных — `PrivateTmp=yes` |
| `secrets:` (файлы хоста 0600 своего пользователя) | `LoadCredential=` из `/etc/aisec/credentials` (0600 root) | исходные файлы службе не видны вовсе |
| тома `:ro` с ключами | `ProtectSystem=strict` | |
| каталог над `reg/`, `state/` принадлежит root | `StateDirectory=aisec-gateway/reg aisec-gateway/state` | |
| `restart: unless-stopped` | `Restart=on-failure` | |
| журнал Docker `local` 5 × 20 МБ | journald | |
| — | `ProtectKernel*`, `ProtectProc`, `PrivateDevices`, `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictRealtime`, `RemoveIPC`, `UMask=0077` | строже compose |

### 9. Сборка пакетов (задача 6.15)
- Источник — только подписанные каталоги выпуска: `build/release`, `build/release-ml`, `build/release-media` после `make release-dir`, `release-sign` и `release-signed-check` (ADR-0022). Цель `make packages` ничего не компилирует и не подписывает манифесты: она раскладывает файлы каталога выпуска по разделу 2 и упаковывает их.
- Сборка в сборочном образе без сети (`docker run --network=none`, `deploy/build`) штатными `dpkg-deb` и `rpmbuild` (Р1). Инструменты ставятся в сборочный образ из закреплённого снимка репозитория Debian, как набор инструментов в `Dockerfile.ml`, и в поставку не входят (GPL допустима для инструментов сборки; запись `scope: build` в `docs/cert/components.yaml`).
- Детерминированность (на неё опирается 6.22): время всех файлов и архива — `SOURCE_DATE_EPOCH` (время последнего коммита), владелец файлов в архиве — `root:root` (`dpkg-deb --root-owner-group`, `%defattr` в rpm), порядок файлов — отсортированный, у rpm — `use_source_date_epoch_as_buildtime`, `clamp_mtime_to_source_epoch`, постоянное имя узла сборки и сжатие `gzip` без времени (оно же поддерживается rpm Альта). Повторная сборка из того же каталога выпуска даёт побайтно тот же пакет — тест 6.15, сравнение двух сборок — 6.22.
- **Подпись пакетов.** Пакеты перечисляются в манифесте пакетов `aisec-packages.json` (имя, формат, размер, SHA-256, версия выпуска), который подписывается ключом производителя тем же порядком, что манифест выпуска: `tools/manifest` на машине без сети (`make release-sign`). Перед установкой администратор проверяет пакет установленной версией: `aisec-cli verify -packages <каталог>` сверяет подпись манифеста пакетов, хеш каждого пакета и версию; затем состав пакета — что внутри ровно файлы подписанного манифеста выпуска с теми же хешами (без запуска сценариев пакета). Первая установка держится на отпечатке ключа производителя из руководства (ADR-0022). Встроенные подписи rpm и deb (GnuPG) не используются: это ещё один инструмент под GPL на машине подписи и второй ключ производителя другого вида; если репозиторий заказчика потребует подпись GnuPG, это отдельное решение.
- Пакеты, сценарии и юниты в ОЦЛ-манифест выпуска не входят (он описывает бинарники, статику, миграции, библиотеки и модели — ADR-0012). Целостность установленных юнитов и сценариев проверяют `dpkg --verify` и `rpm -V`; при необходимости юниты войдут в манифест выпуска отдельным решением (кандидат ревью 6.r1).

### 10. Поверхность атаки
- Сценарии пакета и `aisec-prepare-host` выполняются от root: только фиксированные пути, без сети, без входных данных извне, без перехода по ссылкам в каталогах, которые пишут службы. Обёртка `aisec-cli` — только для root, аргументы передаёт `aisec-cli` без разбора.
- Юниты и дополнения в `/usr/lib/systemd/system` принадлежат root; администратор может ослабить ограничения своим дополнением (`systemctl edit`) — это действие root, оно вне модели угроз продукта, руководство это оговаривает; `systemd-analyze security` показывает итог.
- Новые переменные окружения — только существующие `AISEC_*` в файлах `/etc/aisec/*.env` и `PGPASSFILE`; новых портов нет.

## Альтернативы
- **`nfpm`** (Go, MIT): одна утилита для deb и rpm, но новая зависимость с десятками транзитивных модулей и свой разбор форматов; Р1 выбирает штатные инструменты ОС.
- **Свой сборщик пакетов на стандартной библиотеке.** deb — `ar` и `tar`, это просто; rpm — свой формат заголовков, подписи и `cpio`, ошибка в нём даёт пакет, который на Альте или РЕД ОС ставится иначе. Лишний разборщик и риск (Р1).
- **Архив с установочным сценарием** вместо пакетов: без учёта файлов менеджером пакетов, без `dpkg --verify` и `rpm -V`, удаление и обновление — своим кодом от root.
- **Отдельные пакеты сервера и шлюза.** Отклонено: один манифест выпуска описывает все бинарники (раздел 1).
- **`aisec-ml` и `aisec-media` с отдельным загрузчиком и `RPATH` для пакетов** (`/opt/aisec-ml/lib`). Отклонено: бинарники пакета отличались бы от бинарников образа, а свой корень (`RootDirectory=`) даёт и общий путь, и более строгую изоляцию.
- **`DynamicUser=yes`.** Отклонено: UID меняется между запусками, а `SO_PEERCRED` и права каталога ключей требуют постоянных UID.
- **Секреты файлами в `/etc/aisec` с правами пользователя службы** (как `secrets:` compose). Отклонено по Р2: `LoadCredential=` не даёт службе видеть исходные файлы, а процессы других служб не видят копию.
- **Включать и запускать службы при установке, выполнять миграции в `postinst`.** Отклонено: сервер без ролей БД и TLS не запустится, а миграции — действие администратора с резервной копией (ОБН.1, ADR-0036).

## Последствия
- Новые файлы: `deploy/packaging/` (юниты, дополнения, сценарии пакета, `prepare-host.sh`, обёртка `aisec-cli`, настройки `*.env`), тест сверки seccomp в `tools/imagecheck` (6.16); цель `make packages`, проверка пакетов в `tools/manifest` и `aisec-cli verify -packages`, сборочный образ с `dpkg-deb` и `rpmbuild` (6.15, после согласия владельца). Флаги `cmd/*` не меняются: раскладка совпадает с образами.
- Документы: `docs/cert/attack-surface.md`, `security-functions.md` (ЗИ.5 и ЗИ.7 без Docker), `threat-model.md` (сценарии root, подмена пакета), `build-env.md` (сборка пакетов), руководство администратора («Установка без Docker»), `docs/pilot/manual-checks.md` (запуск юнитов на целевых ОС).
- Проверка в облаке ограничена: `systemd-analyze verify` и `security --offline`, `shellcheck` или `sh -n`, тесты списков. Запуск юнитов, `LoadCredential=` и права копий, `RootDirectory=` с ONNX Runtime, `MemoryMax=` и отсутствие сети — ручная проверка на ВМ и e2e установки (6.17).
- Astra Linux SE в режиме замкнутой программной среды требует подписи ELF-файлов ключом, зарегистрированным в ОС (`bsign`). Пакеты этого не делают; порядок — вопрос к пилоту на Astra и лаборатории (ручная проверка).
- Откат решения: удалить `deploy/packaging/`, цель `make packages` и проверку пакетов; поставка в compose от них не зависит.
