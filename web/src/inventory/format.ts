import type { Model, ModelFile, ScanReport } from "./api";

export const kindTitle = new Map<Model["kind"], string>([
  ["provider", "Модель провайдера"],
  ["customer", "Модель заказчика"],
]);

export const originTitle = new Map<Model["origin"], string>([
  ["traffic", "По трафику"],
  ["manual", "Вручную"],
]);

export const statusTitle = new Map<Model["status"], string>([
  ["active", "Действует"],
  ["blocked", "Запрещена"],
]);

export const roleTitle = new Map<ModelFile["role"], string>([
  ["weights", "Веса"],
  ["adapter", "Адаптер"],
  ["tokenizer", "Токенизатор"],
  ["config", "Конфигурация"],
  ["other", "Другое"],
]);

export const envTitle = new Map([
  ["prod", "Рабочая"],
  ["test", "Тестовая"],
]);

export const providerTypeTitle = new Map([
  ["openai", "OpenAI-совместимый"],
  ["gigachat", "GigaChat"],
  ["yandexgpt", "YandexGPT"],
]);

export const keyStateTitle = new Map([
  ["active", "Действует"],
  ["expired", "Истёк"],
]);

export const verdictTitle = new Map<ScanReport["verdict"], string>([
  ["ok", "Замечаний нет"],
  ["warn", "Есть предупреждения"],
  ["block", "Запрет"],
]);

export const reportKindTitle = new Map<ScanReport["kind"], string>([
  ["scan", "Проверка файлов"],
  ["verify", "Сверка хешей"],
]);

export const hashesTitle = new Map<ScanReport["hashes"], string>([
  ["match", "Совпадают"],
  ["mismatch", "Не совпадают"],
  ["no_reference", "Эталона нет"],
]);

export const templatesTitle = new Map<ScanReport["templates"], string>([
  ["none", "Шаблонов нет"],
  ["baseline", "Совпадают с эталоном"],
  ["unknown", "Семейство неизвестно"],
  ["changed", "Изменены относительно эталона"],
  ["injection", "Найдена инъекция"],
]);

export const blockReasonTitle = new Map<string, string>([
  ["scan", "находка сканера"],
  ["chat_template", "шаблон чата"],
  ["hash_mismatch", "расхождение хешей"],
]);

export const mismatchTitle = new Map<string, string>([
  ["changed", "хеш изменился"],
  ["missing", "файла нет"],
  ["extra", "лишний файл"],
  ["not_hashed", "хеш не посчитан"],
]);

export const findingTitle = new Map<string, string>([
  ["pickle", "формат pickle: исполняемый код в весах"],
  ["malformed", "структура файла нарушена"],
  ["limit_exceeded", "файл не проверен целиком: превышен предел"],
  ["external_data", "внешние данные за пределами каталога"],
  ["unknown_format", "формат не распознан"],
  ["not_scanned", "файл не проверялся"],
  ["onnx_domain", "нестандартный домен операторов ONNX"],
  ["external_data_missing", "внешние данные ONNX не найдены"],
]);

export const sourceTitle = new Map<string, string>([
  ["gguf", "метаданные GGUF"],
  ["tokenizer_config", "tokenizer_config.json"],
  ["chat_template_json", "chat_template.json"],
  ["chat_template_jinja", "chat_template.jinja"],
]);

export const sha256Re = /^[0-9a-f]{64}$/;
