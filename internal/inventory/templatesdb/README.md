# База эталонов шаблонов чата (`chat_template_baselines`)

Исходник служебной базы задачи 5.21 этапа 5 (ADR-0029, дополнение 1): формат `aisec-chat-templates-v1`, разбор — `inventory.ParseTemplateBase`. Сервер не встраивает базу в выпуск: её загружают подписанным файлом `*.aisecdb` (`PUT /api/v1/inventory/chat-templates`, ADR-0028).

## Содержимое версии 1 (02.11.2026)
18 семейств, 19 эталонов: Qwen2.5, Qwen3, QwQ, Llama 3.1/3.2/3.3, Mistral NeMo, Ministral 3, Gemma 2, Phi-3.5, DeepSeek-R1-Distill (Qwen и Llama), DeepSeek-V3.1, Hermes 3 и Hermes 2 Pro (шаблон `tool_use`), Command R+ (`tool_use`), Granite 3.3, Kimi K2, gpt-oss.

- `source` — репозиторий издателя модели на Hugging Face; `license` — лицензия модели по карточке издателя (SPDX или `LicenseRef-…`; `NOASSERTION` — лицензия в карточке не указана однозначно).
- `text` — только при лицензии из `inventory.RedistributableLicenses` (`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`); для лицензий сообщества Llama и Gemma, `CC-BY-NC-4.0`, изменённой MIT и `NOASSERTION` — только хеш.
- `sha256` — SHA-256 нормализованного текста (`inventory.NormalizeTemplate`: без BOM, переводы строк `\n`, без пробелов и табуляций в концах строк, без пустых строк в начале и конце).

## Как собрана
Hugging Face из облака разработки недоступен (403), поэтому тексты шаблонов взяты из копий в репозитории `ggml-org/llama.cpp` (`models/templates/*.jinja`, ветка `master`, 02.11.2026); эти копии сделаны с `tokenizer_config.json` издателей. Хеши посчитаны по нормализованному тексту, тексты с разрешающей лицензией включены как есть.

## Что сделать владельцу до поставки
1. Сверить хеши с оригиналами издателей: скачать `tokenizer_config.json` (или `chat_template.jinja`) каждого источника, нормализовать и сравнить с `sha256`. Расхождение — заменить эталон оригиналом (копия в llama.cpp могла отстать).
2. Дополнить семейства, которые используют пилоты (например, GigaChat и YandexGPT в контуре заказчика, Saiga, Vikhr, T-lite), — по тем же правилам лицензий.
3. Увеличить `version`, обновить `date`, подписать рабочим ключом производителя (`aisec-manifest-sign sign-db -kind chat_template_baselines`, без `-test`) и проверить `aisec-cli servicedb inspect`.
