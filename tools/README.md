# Служебные утилиты сборки и проверки: sbom, license-check, dm-coverage, sast-triage, manifest (манифест целостности, ADR-0012) и др. В поставку не входят.

Корпус изображений `testdata/corpus/media` — `tools/synth-media` (`make media-corpus`, задача 5.36; headless Chromium из `AISEC_CHROMIUM`).

Эксперимент OCR — `tools/ocr-eval` (`make ocr-venv`, `make ocr-models`, `make ocr-eval`; задача 5.40, ADR-0033): прогон кандидатов на корпусе изображений (Python, пакеты с хешами, модели со сверкой SHA-256) и отчёт на Go — CER, находки детекторов, время. В `make check` входят только тесты Go.

Демо-данные для демо-стенда — `tools/demo-data` (`make demo-data`, задача 3.29); сверка находок DAST (OWASP ZAP baseline) с правилами и разметкой — `tools/dast-triage` (`make dast`, задача 3.30). Обе утилиты вне поставки.
