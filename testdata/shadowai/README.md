# Теневой ИИ: тестовые ключи, каталог и журналы — НЕ ДЛЯ ПОСТАВКИ

Данные для тестов задачи 4.22 (ADR-0027). Пользователи, адреса и узлы вне каталога — вымышленные (`*.example.ru`, `*.example.com`, сети `10.0.0.0/8` и `192.0.2.0/24`).

- `subkey-test.signkey` — закрытый тестовый рабочий ключ Ed25519 (`AISEC VENDOR SUBKEY`), `subkey-test.pub` — его открытый ключ.
- `subkey-test.endorsement` — заверение этого ключа (назначение `service_db`, номер 1, срок 01.10.2026 — 30.09.2031), подписанное **тестовым** ключом производителя `testdata/integrity/manifest-test.signkey`. Его принимают только сборки без тега `aisec_release` — как манифест с тестовым ключом (ADR-0022, п. 7).
- `catalog-test.aisecdb` — каталог `internal/shadowai/catalog/catalog.yaml`, подписанный тестовым рабочим ключом. Годится для разработки и лаборатории (`make images-test`): `PUT /api/v1/shadow-ai/catalog`. Тест `TestTestCatalogMatchesSource` сверяет его содержимое с исходником.
- `access-squid.log`, `access.csv`, `usergate-cef.log` — синтетические журналы прокси Squid (native), CSV и CEF в виде выгрузки UserGate.

После правки `catalog.yaml` (с увеличением `version`) подписанный файл пересоздаётся:

```
rm testdata/shadowai/catalog-test.aisecdb
go run ./tools/manifest sign-db -test -key testdata/shadowai/subkey-test.signkey \
  -endorsement testdata/shadowai/subkey-test.endorsement \
  -in internal/shadowai/catalog/catalog.yaml -out testdata/shadowai/catalog-test.aisecdb
```

Поставочный каталог подписывает владелец рабочим ключом производителя на машине без сети (`gen-subkey`, `endorse`, `sign-db` без `-test`, ADR-0027, п. 3).
