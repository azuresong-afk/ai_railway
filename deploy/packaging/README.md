# Установка без Docker: юниты systemd и сценарии пакетов

Решение — [ADR-0034](../../docs/adr/0034-pakety-i-yunity-systemd.md) (задачи 6.14–6.17). Порядок установки для администратора — [руководство администратора](../../docs/user/admin-guide.md), раздел «Установка без Docker». Сборка пакетов deb и rpm (`make packages`) — задача 6.15, после согласия владельца на `dpkg-deb` и `rpmbuild`; до неё файлы раскладываются по таблице ниже вручную (ручная проверка 7, `docs/pilot/manual-checks.md`).

## Пакеты и раскладка

| Файл в репозитории или выпуске | Путь на хосте | Права | Пакет |
|---|---|---|---|
| `build/release/bin/*`, `aisec-manifest.json`, `.sig` | `/opt/aisec/bin/*`, `/opt/aisec/aisec-manifest.json`, `.sig` | `root`, 0755 / 0644 | `aisec` |
| `build/release-ml/{bin,lib,models}`, манифест и подпись | `/opt/aisec-ml/opt/aisec/…` | `root`, 0755 / 0644 | `aisec-ml` |
| `build/release-media/{bin,lib,models}`, манифест и подпись | `/opt/aisec-media/opt/aisec/…` | `root`, 0755 / 0644 | `aisec-media` |
| `systemd/aisec-server.service`, `aisec-gateway.service` | `/usr/lib/systemd/system/` | `root`, 0644 | `aisec` |
| `systemd/aisec-ml.service`, `aisec-gateway.service.d/50-aisec-ml.conf`, `aisec-server.service.d/50-aisec-ml.conf` | `/usr/lib/systemd/system/…` | `root`, 0644 | `aisec-ml` |
| `systemd/aisec-media.service`, `aisec-gateway.service.d/50-aisec-media.conf` | `/usr/lib/systemd/system/…` | `root`, 0644 | `aisec-media` |
| `etc/aisec-server.env`, `aisec-gateway.env`, `aisec-cli.env` | `/etc/aisec/` (файлы конфигурации пакета) | `root`, 0644 | `aisec` |
| `scripts/prepare-host.sh` | `/usr/sbin/aisec-prepare-host` | `root`, 0755 | `aisec` |
| `scripts/aisec-cli.sh` | `/usr/sbin/aisec-cli` | `root`, 0755 | `aisec` |
| `scripts/aisec-gateway-register.sh` | `/usr/sbin/aisec-gateway-register` | `root`, 0755 | `aisec` |
| `scripts/postinst.sh`, `prerm.sh`, `postrm.sh` | не устанавливаются — сценарии пакета | — | все |

Точки монтирования корней анализаторов — пустые каталоги `proc`, `sys`, `dev`, `tmp`, `run/aisec-ml` (`run/aisec-media`) в `/opt/aisec-ml` и `/opt/aisec-media` — входят в пакет (6.15), иначе systemd создаст их сам вне учёта менеджера пакетов. Каталоги `/etc/aisec`, `/etc/aisec/credentials`, `/var/lib/aisec{,/keys,/backups}`, `/var/lib/aisec-gateway{,/reg,/state}` и `/etc/aisec/peers.env` создаёт `postinst.sh`; `/run/aisec-ml` и `/run/aisec-media` — systemd при запуске службы.

## Сценарии пакета

Один POSIX-сценарий на действие для обоих форматов; обёртки deb и rpm (6.15) передают пакет и действие:

| Сценарий | deb | rpm |
|---|---|---|
| `postinst.sh ПАКЕТ install` | `postinst configure` без прежней версии | `%post` при `$1 = 1` |
| `postinst.sh ПАКЕТ upgrade` | `postinst configure` с прежней версией | `%post` при `$1 ≥ 2` |
| `prerm.sh ПАКЕТ upgrade` | `prerm upgrade` (старого пакета, до распаковки нового) | `%pre` нового пакета при `$1 ≥ 2`: `%preun` старого в rpm выполняется уже после установки файлов нового |
| `prerm.sh ПАКЕТ remove` | `prerm remove` | `%preun` при `$1 = 0` |
| `postrm.sh ПАКЕТ remove` / `purge` | `postrm remove` / `purge` | `%postun` при `$1 = 0` (`purge` в rpm нет) |
| `postrm.sh ПАКЕТ upgrade` | `postrm upgrade` | `%postun` при `$1 ≥ 1` |

Правила для сценариев от root (ADR-0034, раздел 7): `set -eu`, `umask 077`, фиксированные пути, без сети, без чтения файлов из каталогов, куда пишут службы, без `chown -R`, отказ на символьной ссылке вместо каталога. Службы при установке не включаются и не запускаются, миграции не выполняются.

## Проверка

`make packaging-check` (`check.sh`): `tools/imagecheck units` — ограничения юнитов и совпадение списка системных вызовов `aisec-media` с `deploy/compose/pilot/seccomp/aisec-media.json`; `systemd-analyze verify` и `security --offline --threshold=15` во временном корне, сверка группы `@default` с перечнем в `tools/imagecheck/systemd.go`; `shellcheck`, если он есть, иначе `sh -n` и `dash -n`. Сверка юнитов и профиля идёт и в `make test` (`TestPackagingUnits`, `TestMediaUnitMatchesSeccomp`). Правка списка вызовов — в обоих файлах сразу.
