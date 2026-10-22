# Установка пилота в docker compose

Сервер управления с веб-консолью, один шлюз, PostgreSQL и служебная `aisec-cli` ([ADR-0019](../../../docs/adr/0019-postavka-pilota.md)). Порядок установки, обновления и подключения своей СУБД описан в [docs/user/install-pilot.md](../../../docs/user/install-pilot.md).

| Файл | Что |
|---|---|
| `compose.yaml` | сервисы, сети, тома и секреты; проверяется командой `make images-verify` (`tools/imagecheck compose`) и тестами |
| `.env.example` | образец `.env`: версия, имена, адреса, UID и GID; секретов в нём нет |
| `prepare-host.sh` | от root: пользователи `aisec`, `aisec-gw`, `aisec-db`, каталоги `0700`, пароли ролей БД, UID и GID в `.env` |
| `initdb/10-aisec-roles.sql` | роли `aisec_owner`, `aisec_server` и база `aisec` — при первом запуске PostgreSQL |
| `verify-release.sh` | проверка нового выпуска перед обновлением (ОБН.1): подпись — установленной `aisec-cli`, затем состав архивов, настройки, файлы и побайтная сверка образов |

Коротко:
```
sudo ./prepare-host.sh                                   # затем .env и сертификаты в ${AISEC_DATA_DIR}/secrets
docker compose up -d postgres
docker compose run --rm aisec-cli migrate
docker compose run --rm aisec-cli init -dir /etc/aisec/keys
docker compose up -d aisec-server                        # первичная настройка в консоли
docker compose run --rm aisec-cli gateway token -name gw-1 -ttl 1h
read -rs AISEC_GATEWAY_REGISTRATION_TOKEN && export AISEC_GATEWAY_REGISTRATION_TOKEN
docker compose run --rm --no-deps -e AISEC_GATEWAY_REGISTRATION_TOKEN \
  aisec-gateway register -console https://<AISEC_CONSOLE_HOST>:8444 -console-ca /run/secrets/console-ca -out-dir /var/lib/aisec-gateway/reg
docker compose up -d
```

Образы собирает `make images` (только `RELEASE=1` с ключом производителя) или `make images-test` (тестовый ключ, **не для поставки**).
