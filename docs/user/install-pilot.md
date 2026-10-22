# Установка пилота в docker compose (черновик)

Черновик задачи 3.5 этапа 3. Полный текст руководства с чек-листом пилота и замером установки на чистой ВМ — задача 3.31. Устройство поставки и обоснования описаны в [ADR-0019](../adr/0019-postavka-pilota.md).

> **Образы с тестовым ключом манифеста (`aisec-test/…:ВЕРСИЯ-test`) заказчику не передаются.** Их собирает CI для проверки. Поставочные образы `aisec/…` появятся вместе с ключом производителя (`make images`, `RELEASE=1`).

## 1. Что нужно
- ВМ с Linux x86-64: 4 vCPU, 8 ГБ памяти, 40 ГБ диска (без учёта событий). Синхронизацию времени нужно настроить по [инструкции](../install/time-sync.md).
- Docker Engine 24 или новее с правами root (rootless не поддерживается) и Docker Compose 2.20 или новее.
- Каталог выпуска: `aisec-manifest.json`, `aisec-manifest.json.sig`, `bin/`, `images/aisec-server.tar`, `images/aisec-gateway.tar`, `images/aisec-cli.tar` и каталог `deploy/compose/pilot` из поставки.
- Официальный образ PostgreSQL `postgres:17.11-alpine3.24` с digest из `compose.yaml` — из Docker Hub или из реестра организации. Продукт его не распространяет.
- Сертификаты TLS от корпоративного УЦ:
  - для консоли — с именем, по которому её открывают администраторы, например `aisec.example.ru`;
  - для шлюза — с именем, по которому к нему обращаются приложения (можно взять тот же сертификат, если в нём оба имени);
  - корневой сертификат этого УЦ.
- Сеть: наружу ходит только шлюз, и только к провайдерам LLM, которых вы зададите в консоли. PostgreSQL и `aisec-cli` подключены только к внутренним сетям Docker. Сервер подключён к сети с опубликованным портом консоли и сам соединяется только с PostgreSQL и с SMTP, syslog и webhook из ваших настроек. Если эти каналы не нужны, закройте исходящие соединения сервера правилом в цепочке `DOCKER-USER` межсетевого экрана хоста.

## 2. Подготовка хоста
1. Загрузите образы: `docker load -i images/aisec-server.tar` и так же два других. PostgreSQL получите командой `docker pull postgres:17.11-alpine3.24@sha256:…`, digest возьмите из `compose.yaml`. Для своего реестра задайте `AISEC_POSTGRES_IMAGE` в `.env`.
2. Перейдите в каталог `deploy/compose/pilot` и выполните `sudo ./prepare-host.sh`. Скрипт:
   - создаёт системных пользователей `aisec` (сервер и `aisec-cli`), `aisec-gw` (шлюз) и `aisec-db` (PostgreSQL) без входа в систему;
   - создаёт каталоги в `AISEC_DATA_DIR` (по умолчанию `/srv/aisec`) с правами `0700`;
   - генерирует пароли ролей БД;
   - записывает UID и GID пользователей в `.env`.
   Если `.env` не было, скрипт создаёт его из `.env.example`.
3. Заполните `.env`: `AISEC_VERSION`, `AISEC_CONSOLE_HOST` (имя из сертификата консоли), а также `AISEC_CONSOLE_BIND` и `AISEC_GATEWAY_BIND` — адреса интерфейсов хоста. По умолчанию это `127.0.0.1`, и тогда консоль и шлюз доступны только с самого хоста.
4. Положите сертификаты, подставив свой `AISEC_DATA_DIR`:
   ```
   sudo install -o aisec    -g aisec    -m 0644 console.crt    /srv/aisec/secrets/console.crt
   sudo install -o aisec    -g aisec    -m 0600 console.key    /srv/aisec/secrets/console.key
   sudo install -o root     -g root     -m 0644 ca.crt         /srv/aisec/secrets/console-ca.crt
   sudo install -o aisec-gw -g aisec-gw -m 0644 gateway.crt    /srv/aisec/secrets/gateway.crt
   sudo install -o aisec-gw -g aisec-gw -m 0600 gateway.key    /srv/aisec/secrets/gateway.key
   ```
   Повторный запуск `prepare-host.sh` покажет, каких файлов ещё нет.

## 3. Первый запуск
Команды выполняются в каталоге `deploy/compose/pilot` от root или пользователя группы `docker`.
1. Запустите БД: `docker compose up -d postgres`. При первом запуске создаются роли `aisec_owner` (владелец схемы) и `aisec_server` (вход сервера, не владелец таблиц), а также база `aisec`.
2. Выполните миграции: `docker compose run --rm aisec-cli migrate`.
3. Создайте ключи установки: `docker compose run --rm aisec-cli init -dir /etc/aisec/keys`. Сохраните **токен первичной настройки**: он показывается один раз и действует 24 часа. Ключи лежат в `/srv/aisec/keys` и принадлежат пользователю `aisec`. Резервную копию `master.key` храните отдельно от копии БД.
4. Запустите сервер: `docker compose up -d aisec-server`. Откройте `https://AISEC_CONSOLE_HOST:8444` и выполните первичную настройку ([руководство администратора](admin-guide.md), раздел 3).
5. Зарегистрируйте шлюз. Токен вводится без отображения и не попадает в историю оболочки:
   ```
   docker compose run --rm aisec-cli gateway token -name gw-1 -ttl 1h
   read -rs AISEC_GATEWAY_REGISTRATION_TOKEN && export AISEC_GATEWAY_REGISTRATION_TOKEN
   docker compose run --rm --no-deps -e AISEC_GATEWAY_REGISTRATION_TOKEN \
     aisec-gateway register -console https://AISEC_CONSOLE_HOST:8444 -console-ca /run/secrets/console-ca \
     -out-dir /var/lib/aisec-gateway/reg
   unset AISEC_GATEWAY_REGISTRATION_TOKEN
   ```
   Здесь `AISEC_CONSOLE_HOST` — то же имя, что в `.env`.
6. Запустите всё: `docker compose up -d`. Шлюз получит подписанный пакет конфигурации от сервера, после этого `GET https://<шлюз>:8443/readyz` отвечает `{"status":"ok"}`. Провайдеры, приложения и политики настраиваются в консоли ([руководство администратора](admin-guide.md), разделы 5–7).

Проверка установки: `docker compose run --rm aisec-cli verify` сверяет все файлы выпуска с подписанным манифестом, код возврата 3 означает нарушение. Состояние компонентов показывает экран «Состояние системы».

## 4. Обновление
1. Получите каталог нового выпуска и проверьте его: `./verify-release.sh /путь/к/выпуску`. Скрипт работает с копией выпуска во временном каталоге (`TMPDIR`, нужно место размером с выпуск). Выпуск старше установленного он отвергает. Подпись и файлы проверяет `aisec-cli` **установленной** версии. Затем скрипт проверяет состав архивов образов, загружает их, сверяет настройки и полный список файлов каждого образа и побайтно сравнивает бинарники с проверенными. При расхождении загруженные образы удаляются. Устанавливать выпуск можно только после строки «Выпуск проверен».
2. Сделайте резервную копию конфигурации ([backup.md](../install/backup.md)) и копию БД средствами PostgreSQL.
3. Укажите новую `AISEC_VERSION` в `.env`, затем выполните:
   ```
   docker compose stop aisec-gateway aisec-server
   docker compose run --rm aisec-cli migrate
   docker compose up -d
   ```
4. Откат: вернуть прежнюю `AISEC_VERSION` и принять откат командой `docker compose run --rm aisec-cli verify -accept-rollback`, для шлюза — с `-gateway gw-1`. Запись о принятии попадает в журнал аудита. Миграции назад не откатываются: при откате схемы восстановите копию БД.

## 5. Своя СУБД
Задайте `COMPOSE_PROFILES=` (пусто), создайте роли и базу так же, как в `initdb/10-aisec-roles.sql`, и задайте в `.env` строки `AISEC_SERVER_DB_URL` и `AISEC_OWNER_DB_URL` с `sslmode=verify-full`. Пароли кладите только в passfile `secrets/db-server.pgpass` и `secrets/db-owner.pgpass` (формат `*:*:*:роль:пароль`, владелец `aisec`, права `0400`). Корень УЦ СУБД подключите дополнительным секретом.

## 6. Где что лежит
| Путь на хосте | Владелец | Что |
|---|---|---|
| `/srv/aisec/keys` | `aisec`, `0700` | ключи `aisec-cli init` (мастер-ключ, УЦ шлюзов, ключи подписи) |
| `/srv/aisec/secrets` | `root`, `0700` | сертификаты TLS, пароли и passfile ролей БД |
| `/srv/aisec/pg` | `aisec-db`, `0700` | данные PostgreSQL |
| `/srv/aisec/gateway` | `root`, `0755` | каталоги шлюза: `reg/` (сертификат шлюза) и `state/` (последний пакет и ключ секретов пакета), оба `aisec-gw`, `0700` |
| `/srv/aisec/backups` | `aisec`, `0700` | резервные копии `aisec-cli backup` (`/var/lib/aisec/backups` в контейнере) |
