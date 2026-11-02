# Реестр ИИ: тестовая база эталонов шаблонов чата — НЕ ДЛЯ ПОСТАВКИ

Данные для тестов задачи 5.21 этапа 5 (ADR-0029, дополнение 1; ADR-0028).

- `chat-templates-test.aisecdb` — база эталонов `internal/inventory/templatesdb/chat-templates.json` (вид `chat_template_baselines`), подписанная **тестовым** рабочим ключом `testdata/shadowai/subkey-test.signkey` с заверением `testdata/shadowai/subkey-test.endorsement`. Её принимают только сборки без тега `aisec_release`. Годится для разработки и лаборатории: `PUT /api/v1/inventory/chat-templates`. Тест `TestTestTemplatesMatchSource` сверяет содержимое с исходником.

После правки `chat-templates.json` (с увеличением `version`) подписанный файл пересоздаётся:

```
rm testdata/inventory/chat-templates-test.aisecdb
go run ./tools/manifest sign-db -test -kind chat_template_baselines -key testdata/shadowai/subkey-test.signkey \
  -endorsement testdata/shadowai/subkey-test.endorsement \
  -in internal/inventory/templatesdb/chat-templates.json -out testdata/inventory/chat-templates-test.aisecdb
```

Проверка файла: `go run ./cmd/aisec-cli servicedb inspect testdata/inventory/chat-templates-test.aisecdb`.

Поставочную базу подписывает владелец рабочим ключом производителя на машине без сети (`sign-db` без `-test`, ADR-0027, п. 3; ADR-0028).
