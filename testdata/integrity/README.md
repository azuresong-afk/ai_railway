# Тестовый ключ манифеста целостности — НЕ ДЛЯ ПОСТАВКИ

`manifest-test.signkey` — закрытый ключ Ed25519 (`AISEC MANIFEST SIGNING KEY`, профиль `standard`). Его пара — открытый ключ `internal/integrity/keys/manifest-test.pub`, встроенный в сборки **без** тега `aisec_release` (решение Р10 этапа 2, ADR-0012).

- Ключ опубликован в репозитории намеренно. Им подписывает `make manifest` без `MANIFEST_KEY` в CI и при разработке.
- Манифест, подписанный этим ключом, принимают только сборки с тестовым ключом. В каждом результате проверки у них стоит `test_signed: true`, при запуске в журнал пишется предупреждение.
- Поставочная сборка — `make manifest RELEASE=1 MANIFEST_KEY=…`:
  - встраивает открытый ключ производителя `internal/integrity/keys/manifest.pub`;
  - подписывает закрытым ключом производителя, который хранится вне репозитория (ТЗ, 10.4).
- Расширение `.signkey` выбрано потому, что `.gitignore` исключает `*.key` и `*.pem`: так ключи стенда и установки не попадают в репозиторий случайно.

Пару пересоздаёт команда `go run ./tools/manifest gen-key -key testdata/integrity/manifest-test.signkey -pub internal/integrity/keys/manifest-test.pub`. Старые файлы перед этим нужно удалить.
