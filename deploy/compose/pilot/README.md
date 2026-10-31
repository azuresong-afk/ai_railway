# Установка пилота в docker compose

Сервер управления с веб-консолью, один шлюз, PostgreSQL и служебная `aisec-cli` ([ADR-0019](../../../docs/adr/0019-postavka-pilota.md)). Порядок установки, обновления и подключения своей СУБД описан в [docs/user/install-pilot.md](../../../docs/user/install-pilot.md).

| Файл | Что |
|---|---|
| `compose.yaml` | сервисы, сети, тома и секреты; проверяется командой `make images-verify` (`tools/imagecheck compose`) и тестами |
| `compose.shadow-ai-syslog.yaml` | дополнение к `compose.yaml`: приём журналов прокси и NGFW по syslog поверх TLS для теневого ИИ (порт 6514, по умолчанию на 127.0.0.1). Без него порт закрыт: `docker compose -f compose.yaml -f compose.shadow-ai-syslog.yaml up -d aisec-server` ([руководство администратора](../../../docs/user/admin-guide.md), «Теневой ИИ: приём по syslog») |
| `compose.ml.yaml` | дополнение к `compose.yaml`: процесс ML-детекторов `aisec-ml` (без сети, свой пользователь `aisec-ml`) и подключение к нему шлюза через Unix-сокет `ml/run` ([ADR-0024](../../../docs/adr/0024-ml-detektory-i-aisec-ml.md)). По умолчанию выключено: шлюз работает на эвристиках. Включение — ниже, «ML-детекторы» |
| `compose.media.yaml` | дополнение к `compose.yaml`: анализатор изображений `aisec-media` (без сети, корень только для чтения, лимиты памяти, процессора и процессов, свой пользователь `aisec-media`, профиль seccomp) и подключение к нему шлюза через Unix-сокет `media/run` ([ADR-0032](../../../docs/adr/0032-aisec-media.md)). По умолчанию выключено. Включение — ниже, «Анализатор изображений»; проверяется `make images-verify` и тестами `tools/imagecheck` |
| `seccomp/aisec-media.json` | профиль seccomp `aisec-media`: по умолчанию отказ (`EPERM`), разрешённые системные вызовы списком, `socket` — только `AF_UNIX`, `clone` — без новых пространств имён. Путь в `compose.media.yaml` — относительно каталога этого файла |
| `.env.example` | образец `.env`: версия, имена, адреса, UID и GID; секретов в нём нет |
| `prepare-host.sh` | от root: пользователи `aisec`, `aisec-gw`, `aisec-db`, `aisec-ml`, `aisec-media`, каталоги `0700` (каталоги сокетов `ml/run` и `media/run` — `0750`, группа шлюза), пароли ролей БД, UID и GID в `.env`; после `init` — якорь шлюза `secrets/gateway-bundle-anchor.pub` |
| `initdb/10-aisec-roles.sql` | роли `aisec_owner`, `aisec_server` и база `aisec` — при первом запуске PostgreSQL |
| `backup.sh` | от root: полная копия установки — архив ключей, секретов и каталогов шлюза, `pg_dump` БД, контрольные суммы ([руководство администратора](../../../docs/user/admin-guide.md), раздел 12) |
| `restore.sh` | от root: восстановление копии `backup.sh` в пустую установку после `prepare-host.sh`: файлы, БД одной транзакцией, миграции, завершение сессий и отзыв токенов API копии (`aisec-cli restore-finish`, запись `system.restored`), проверка цепочки аудита |
| `lab-install.sh` | от root: установка для лаборатории и стенда одной командой — образы собираются в Docker из исходников (тестовый ключ, **не для поставки**), сертификаты от собственного УЦ установки (`aisec-cli tls init`) или готовые сертификаты УЦ заказчика (`--tls-dir КАТАЛОГ`, проверка `aisec-cli tls check`); с `--media` — ещё анализатор изображений `aisec-media`; затем шаги ниже ([install-pilot.md](../../../docs/user/install-pilot.md), «Лаборатория») |
| `verify-release.sh` | проверка поставки (`-first`, первая установка) и нового выпуска перед обновлением (ОБН.1, ADR-0022): подпись — установленной `aisec-cli` (при первой установке — `aisec-cli` поставки после проверки архива), отпечаток ключа — с `AISEC_VENDOR_FINGERPRINT`, затем состав архивов, настройки, файлы и побайтная сверка образов; необязательный подкаталог `media/` — выпуск `aisec-media` с тем же ключом и версией |

Лаборатория, на хосте только Docker: `sudo ./lab-install.sh --host <адрес ВМ>` (сертификаты от собственного УЦ установки) или `sudo ./lab-install.sh --host <имя ВМ> --tls-dir /root/aisec-tls` (сертификаты УЦ заказчика: `console.crt`, `console.key`, `gateway.crt`, `gateway.key`, `ca.crt`). Сертификаты для установки без скрипта проверяйте до первого запуска: `aisec-cli tls check` ([install-pilot.md](../../../docs/user/install-pilot.md), шаг 3.4).

Коротко, по шагам:
```
sudo ./prepare-host.sh                                   # затем .env и сертификаты в ${AISEC_DATA_DIR}/secrets
docker compose up -d postgres
docker compose run --rm aisec-cli migrate
docker compose run --rm aisec-cli init -dir /etc/aisec/keys
sudo ./prepare-host.sh                                   # якорь шлюза secrets/gateway-bundle-anchor.pub
docker compose up -d aisec-server                        # первичная настройка в консоли
docker compose run --rm aisec-cli gateway token -name gw-1 -ttl 1h
read -rs AISEC_GATEWAY_REGISTRATION_TOKEN && export AISEC_GATEWAY_REGISTRATION_TOKEN
docker compose run --rm --no-deps -e AISEC_GATEWAY_REGISTRATION_TOKEN \
  aisec-gateway register -console https://<AISEC_CONSOLE_HOST>:8444 -console-ca /run/secrets/console-ca \
  -out-dir /var/lib/aisec-gateway/reg -state-dir /var/lib/aisec-gateway/state
docker compose up -d
```

Образы собирает `make images` (только `RELEASE=1` из каталога выпуска, подписанного ключом производителя на машине без сети, ADR-0022) или `make images-test` (тестовый ключ, **не для поставки**).

**Отпечаток ключа производителя:** публикуется с первым выпуском (`make release-fingerprint`). Сверяйте его с отпечатком в руководстве установки или в письме производителя: этот файл приходит вместе с поставкой и сам по себе доверия не даёт.

## ML-детекторы (задача 4.19)
`injection.ml` и `toxicity.ml` работают в отдельном процессе `aisec-ml` без сети. Пока в поставке нет пакета моделей (часть 2 задачи 4.19), `aisec-ml` не принимает соединения, а проверки с ML-детекторами в политике получают признак `ml_unavailable` и решаются по остальным детекторам.

1. `sudo ./prepare-host.sh` — создаёт пользователя `aisec-ml`, каталог `ml/run` и пишет `AISEC_ML_UID` в `.env` (повторный запуск безопасен).
2. Образ `aisec-ml` — архив `images/aisec-ml.tar` выпуска с ML (`make images ML=1`): `docker load -i images/aisec-ml.tar`. Проверка подписи выпуска `aisec-ml`: `docker compose run --rm -v "$PWD/release-ml:/release-ml:ro" aisec-cli verify -manifest /release-ml/aisec-manifest.json`. Скрипт `verify-release.sh` образ `aisec-ml` пока не проверяет.
3. В `.env`: `COMPOSE_FILE=compose.yaml:compose.ml.yaml` и `COMPOSE_PROFILES=db,ml` (своя СУБД — `COMPOSE_PROFILES=ml`). Без профиля `ml` дополнение не запустится — это защита от шлюза, который ждёт несуществующий сокет.
4. `docker compose up -d`. Отключение — убрать `compose.ml.yaml` из `COMPOSE_FILE` и `ml` из `COMPOSE_PROFILES`, затем `docker compose up -d --remove-orphans`.

Всплеск проверок без ML поднимает встроенное оповещение «Проверки без ML-детекторов» (`frequency.ml_unavailable`).

## Анализатор изображений (задача 5.38)
Изображения из запросов разбирает только отдельный процесс `aisec-media` ([ADR-0032](../../../docs/adr/0032-aisec-media.md), ЗИ.7): контейнер без сети (`network_mode: none`), корень только для чтения, `/tmp` — tmpfs 16 МиБ без исполнения, память `AISEC_MEDIA_MEM_LIMIT` (своп не добавляется), процессор `AISEC_MEDIA_CPUS`, не больше 64 процессов и потоков, без привилегий и с профилем `seccomp/aisec-media.json`. Соединения по сокету принимаются только от шлюза (UID и GID — `AISEC_GW_UID`, `AISEC_GW_GID`). Шлюз начинает передавать изображения с задачи 5.39; до неё анализатор работает вхолостую.

1. `sudo ./prepare-host.sh` — создаёт пользователя `aisec-media`, каталог `media/run` (`0750`, владелец `aisec-media`, группа `aisec-gw`) и пишет `AISEC_MEDIA_UID` в `.env`.
2. Выпуск `aisec-media` — свой каталог с манифестом и подписью (`make media-release-dir`, `make images MEDIA=1`), в поставке — подкаталог `media/`. `./verify-release.sh -first` проверяет его подпись тем же ключом производителя, версию и образ `images/aisec-media.tar`; затем `docker load -i media/images/aisec-media.tar`.
3. В `.env`: `COMPOSE_FILE=compose.yaml:compose.media.yaml` (вместе с ML — `compose.yaml:compose.ml.yaml:compose.media.yaml`) и `media` в `COMPOSE_PROFILES` (например, `db,media`). Без профиля `media` compose откажет («depends on undefined service»), а не запустит шлюз без анализатора. Число исполнителей и лимиты — `AISEC_MEDIA_WORKERS`, `AISEC_MEDIA_MEM_LIMIT`, `AISEC_MEDIA_CPUS` (`.env.example`).
4. `docker compose up -d`. Отключение — убрать `compose.media.yaml` из `COMPOSE_FILE` и `media` из `COMPOSE_PROFILES`, затем `docker compose up -d --remove-orphans`.

Лаборатория: `sudo ./lab-install.sh --host <адрес ВМ> --media` собирает выпуск и образ `aisec-media` и сам делает шаги 1–3. Проверки, которые требуют Docker на хосте (нет сети, OOM, seccomp на живом контейнере), — в [docs/pilot/manual-checks.md](../../../docs/pilot/manual-checks.md).

