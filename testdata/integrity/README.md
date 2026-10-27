# Ключи манифеста целостности из репозитория — НЕ ДЛЯ ПОСТАВКИ

`manifest-test.signkey` — закрытый ключ Ed25519 (`AISEC MANIFEST SIGNING KEY`, профиль `standard`). Его пара — открытый ключ `internal/integrity/keys/manifest-test.pub`, встроенный в сборки **без** тега `aisec_release` (решение Р10 этапа 2, ADR-0012).

- Ключ опубликован в репозитории намеренно. Им подписывают `make manifest` и `make images-test` в CI и при разработке.
- Манифест, подписанный этим ключом, принимают только сборки с тестовым ключом. В каждом результате проверки у них стоит `test_signed: true`, при запуске в журнал пишется предупреждение.
- Поставочная сборка (`make release-dir RELEASE=1`, ADR-0022):
  - встраивает открытый ключ производителя `internal/integrity/keys/manifest.pub`;
  - манифест подписывается отдельным шагом на машине без сети (`make release-sign` или `tools/manifest sign`) закрытым ключом производителя, который хранится вне репозитория на отдельном носителе (ТЗ, 10.4).
- `manifest-release-ci.signkey` — **имитация ключа производителя** для тестов поставочной сборки. Её открытая пара `internal/integrity/keys/manifest-release-ci.pub` встраивается вместо `manifest.pub` только в `make release-test` без `RELEASE=1` (`go test -overlay`): так в каждой проверке видно, что поставочная сборка принимает подпись ключом производителя и отвергает тестовый и чужой ключ. Поставочная сборка эту пару не принимает (`EmbeddedVerifier`), `tools/manifest sign` ею не подписывает.
- Расширение `.signkey` выбрано потому, что `.gitignore` исключает `*.key` и `*.pem`: так ключи стенда и установки не попадают в репозиторий случайно.

Пары пересоздаёт команда `go run ./tools/manifest gen-key -test -key testdata/integrity/manifest-test.signkey -pub internal/integrity/keys/manifest-test.pub` (для имитации — `manifest-release-ci.*`). Старые файлы перед этим нужно удалить. Флаг `-test` отключает проверку сети: ключ производителя создаётся только без него, на машине без сети.
