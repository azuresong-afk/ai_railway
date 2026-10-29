# Лицензии: тестовые ключи и лицензия — НЕ ДЛЯ ПОСТАВКИ

Данные для тестов задач 4.26 и 4.27 (ADR-0026). Владелец и ИНН вымышленные: ИНН `0012345673` — код региона 00 не существует, контрольная цифра верная.

- `subkey-test.signkey` — закрытый тестовый рабочий ключ Ed25519 (`AISEC VENDOR SUBKEY`), `subkey-test.pub` — его открытый ключ.
- `subkey-test.endorsement` — заверение этого ключа (назначение `license`, номер 2, срок 01.10.2026 — 30.09.2031), подписанное **тестовым** ключом производителя `testdata/integrity/manifest-test.signkey`. Его принимают только сборки без тега `aisec_release` (ADR-0022, п. 7).
- `license-test.json` — содержимое тестовой лицензии: № 1, коммерческая, 28.10.2026 — 28.10.2027, 10 шлюзов, 50 приложений, все модули.
- `license-test.aiseclic` — она же, подписанная тестовым рабочим ключом. Годится для разработки и лаборатории (`make images-test`): «Администрирование → Лицензия» или `PUT /api/v1/license`. Тест `TestTestLicenseMatchesSource` сверяет содержимое с `license-test.json`.

Лицензии с другими сроками и пределами тесты подписывают сами этим же ключом. Пересоздать файл после правки `license-test.json` (с новым номером):

```
rm testdata/license/license-test.aiseclic
go run ./tools/manifest sign-license -test -key testdata/license/subkey-test.signkey \
  -endorsement testdata/license/subkey-test.endorsement \
  -in testdata/license/license-test.json -out testdata/license/license-test.aiseclic
```

Поставочные лицензии подписывает владелец рабочим ключом лицензий на машине без сети (`gen-subkey`, `endorse -purpose license`, `sign-license` без `-test`, ADR-0026, п. 9).
