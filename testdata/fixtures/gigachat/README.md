# Фикстуры GigaChat API

Ответы GigaChat API для контрактных тестов адаптера (`internal/providers/gigachat_test.go`).
Написаны вручную по публичной документации developers.sber.ru (план этапа 1, Р8),
без реальных ключей и токенов. До пилота адаптер проверяется на настоящей учётной
записи; расхождения с действительностью исправляются здесь и в адаптере.

- `token.json` — ответ `POST /api/v2/oauth` (токен доступа, срок в миллисекундах Unix).
- `chat.json` — ответ `POST /api/v1/chat/completions` с текстом.
- `chat_function_call.json` — ответ с вызовом функции (`function_call`, аргументы — объект).
- `stream.txt` — потоковый ответ (SSE), завершается `data: [DONE]`.
- `error_422.json` — ошибка в формате GigaChat (`status`, `message`).
