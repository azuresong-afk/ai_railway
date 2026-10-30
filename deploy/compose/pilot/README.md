# Установка пилота в docker compose

Сервер управления с веб-консолью, один шлюз, PostgreSQL и служебная `aisec-cli` ([ADR-0019](../../../docs/adr/0019-postavka-pilota.md)). Порядок установки, обновления и подключения своей СУБД описан в [docs/user/install-pilot.md](../../../docs/user/install-pilot.md).

| Файл | Что |
|---|---|
| `compose.yaml` | сервисы, сети, тома и секреты; проверяется командой `make images-verify` (`tools/imagecheck compose`) и тестами |
| `compose.shadow-ai-syslog.yaml` | дополнение к `compose.yaml`: приём журналов прокси и NGFW по syslog поверх TLS для теневого ИИ (порт 6514, по умолчанию на 127.0.0.1). Без него порт закрыт: `docker compose -f compose.yaml -f compose.shadow-ai-syslog.yaml up -d aisec-server` ([руководство администратора](../../../docs/user/admin-guide.md), «Теневой ИИ: приём по syslog») |
| `compose.ml.yaml` | дополнение к `compose.yaml`: процесс ML-детекторов `aisec-ml` (без сети, свой пользователь `aisec-ml`) и подключение к нему шлюза через Unix-сокет `ml/run` ([ADR-0024](../../../docs/adr/0024-ml-detektory-i-aisec-ml.md)). По умолчанию выключено: шлюз работает на эвристиках. Включение — ниже, «ML-детекторы» |
| `.env.example` | образец `.env`: версия, имена, адреса, UID и GID; секретов в нём нет |
| `prepare-host.sh` | от root: пользователи `aisec`, `aisec-gw`, `aisec-db`, `aisec-ml`, каталоги `0700` (каталог сокета `ml/run` — `0750`, группа шлюза), пароли ролей БД, UID и GID в `.env`; после `init` — якорь шлюза `secrets/gateway-bundle-anchor.pub` |
| `initdb/10-aisec-roles.sql` | роли `aisec_owner`, `aisec_server` и база `aisec` — при первом запуске PostgreSQL |
| `backup.sh` | от root: полная копия установки — архив ключей, секретов и каталогов шлюза, `pg_dump` БД, контрольные суммы ([руководство администратора](../../../docs/user/admin-guide.md), раздел 12) |
| `restore.sh` | от root: восстановление копии `backup.sh` в пустую установку после `prepare-host.sh`: файлы, БД одной транзакцией, миграции, завершение сессий и отзыв токенов API копии (`aisec-cli restore-finish`, запись `system.restored`), проверка цепочки аудита |
| `lab-install.sh` | от root: установка для лаборатории и стенда одной командой — образы собираются в Docker из исходников (тестовый ключ, **не для поставки**), сертификаты от собственного УЦ установки (`aisec-cli tls init`) или готовые сертификаты УЦ заказчика (`--tls-dir КАТАЛОГ`, проверка `aisec-cli tls check`), затем шаги ниже ([install-pilot.md](../../../docs/user/install-pilot.md), «Лаборатория») |
| `verify-release.sh` | проверка поставки (`-first`, первая установка) и нового выпуска перед обновлением (ОБН.1, ADR-0022): подпись — установленной `aisec-cli` (при первой установке — `aisec-cli` поставки после проверки архива), отпечаток ключа — с `AISEC_VENDOR_FINGERPRINT`, затем состав архивов, настройки, файлы и побайтная сверка образов |

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

С дополнением сервер тоже знает про `aisec-ml` (`AISEC_SERVER_ML_TEMPLATES=true` в `compose.ml.yaml`): новые политики из шаблонов получают правила `injection.ml` и `toxicity.ml` с действием «журнал». Политики, созданные раньше, не меняются — правила в них администратор добавляет сам.

Всплеск проверок без ML поднимает встроенное оповещение «Проверки без ML-детекторов» (`frequency.ml_unavailable`).

