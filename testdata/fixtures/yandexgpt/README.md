# Фикстуры YandexGPT (Foundation Models API)

Ответы метода `POST /foundationModels/v1/completion` для контрактных тестов адаптера
(`internal/providers/yandexgpt_test.go`). Написаны вручную по публичной документации
yandex.cloud (план этапа 1, Р8), без реальных ключей. До пилота адаптер проверяется на
настоящей учётной записи; расхождения исправляются здесь и в адаптере.

- `completion.json` — ответ с текстом; счётчики токенов — строками (int64 в protobuf JSON).
- `completion_tool_calls.json` — ответ с вызовом функции (`toolCallList`, аргументы — объект).
- `stream.ndjson` — потоковый ответ: строки JSON, в каждой — накопленный к этому моменту текст;
  последняя — со статусом `ALTERNATIVE_STATUS_FINAL`.
- `error.json` — ошибка (`error.message`, `httpCode`, `grpcCode`).
