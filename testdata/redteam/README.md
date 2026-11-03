# Тестирование устойчивости: тестовая база сценариев — НЕ ДЛЯ ПОСТАВКИ

Данные для тестов задачи 5.32 этапа 5 (ADR-0031, раздел 5; ADR-0028).

- `scenarios-test.json` — пять синтетических сценариев (DM-01, DM-06, DM-08, DM-10, DM-19) на русском и английском, по одному на каждое условие успеха: `contains` (в том числе двухшаговый), `canary`, `findings`, `judge`. Настоящую библиотеку сценариев наполняет задача 5.31.
- `scenarios-test.aisecdb` — эта база (вид `redteam_scenarios`), подписанная **тестовым** рабочим ключом `testdata/shadowai/subkey-test.signkey` с заверением `testdata/shadowai/subkey-test.endorsement`. Её принимают только сборки без тега `aisec_release`. Годится для разработки и лаборатории: `PUT /api/v1/redteam/scenarios`. Тест `TestTestScenariosMatchSource` сверяет содержимое с исходником.

После правки `scenarios-test.json` (с увеличением `version`) подписанный файл пересоздаётся:

```
rm testdata/redteam/scenarios-test.aisecdb
go run ./tools/manifest sign-db -test -kind redteam_scenarios -key testdata/shadowai/subkey-test.signkey \
  -endorsement testdata/shadowai/subkey-test.endorsement \
  -in testdata/redteam/scenarios-test.json -out testdata/redteam/scenarios-test.aisecdb
```

- `scenarios-library-test.aisecdb` — тестовая подпись полной библиотеки (задача 5.31): исходник `internal/redteam/scenariosdb/scenarios.json`, тот же тестовый ключ, НЕ ДЛЯ ПОСТАВКИ. Пересоздаётся командой из `internal/redteam/scenariosdb/README.md`; тест `TestLibraryTestSignature` сверяет её с исходником.

Проверка файла: `go run ./cmd/aisec-cli servicedb inspect testdata/redteam/scenarios-test.aisecdb`.

Поставочную базу подписывает владелец рабочим ключом производителя на машине без сети (`sign-db` без `-test`, ADR-0027, п. 3; ADR-0028).
