-- Отчёты сканера моделей и запрет использования модели (ТЗ 5.12, DM-27–DM-29;
-- задачи 5.21 и 5.22 этапа 5, ADR-0029, п. 4 и дополнение 1).
--
-- Отчёт присылает aisec-cli models scan или models verify с узла заказчика,
-- где лежат файлы модели. В отчёте — пути, размеры, форматы, хеши SHA-256 и
-- находки по файлам, шаблоны чата (метаданные модели) и итоги проверки на
-- сервере. Весов и их фрагментов здесь нет. На модель хранится не больше 20
-- последних отчётов (удаляет сервис той же транзакцией).

-- Состояние blocked — запрет использования модели: сервер выставляет его по
-- отчёту (несовпадение хешей, находка с запретом, инъекция в шаблоне чата),
-- снимает администратор безопасности (inventory.unblock). Модель в этом
-- состоянии исключается из пакета конфигурации шлюзов.
ALTER TABLE inventory_models DROP CONSTRAINT inventory_models_status_check;
ALTER TABLE inventory_models ADD CONSTRAINT inventory_models_status_check CHECK (status IN ('active', 'blocked'));

-- Смена состояния модели меняет пакет конфигурации шлюзов (раздел
-- blocked_models): счётчик изменений растёт той же транзакцией (миграция
-- 0030), поэтому запрет доходит до шлюзов при следующем опросе.
CREATE TRIGGER inventory_models_revision_status AFTER UPDATE OF status ON inventory_models
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION config_revision_bump();
-- Запрещённая модель появляется (восстановление копии) или исчезает
-- (удаление организации) — тоже изменение пакета. Добавление и удаление
-- действующих моделей пакет не меняет: счётчик не трогается.
CREATE TRIGGER inventory_models_revision_insert AFTER INSERT ON inventory_models
    FOR EACH ROW WHEN (NEW.status = 'blocked') EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER inventory_models_revision_delete AFTER DELETE ON inventory_models
    FOR EACH ROW WHEN (OLD.status = 'blocked') EXECUTE FUNCTION config_revision_bump();

-- Отчёт сканера. kind: scan — проверка форматов и хешей, verify — только
-- хеши. verdict — итог отчёта: ok, warn (находки без запрета), block.
-- hashes — сверка с эталонными хешами реестра: match, mismatch,
-- no_reference (у модели нет файлов весов и адаптеров в реестре).
-- templates — итог проверки шаблонов чата: none (шаблонов нет), baseline
-- (совпали с эталоном), unknown (эталона семейства нет), changed (отличается
-- от эталонов семейства), injection (детектор нашёл внедрённые инструкции).
-- report — проверенный отчёт и итоги сервера (JSON до 4 МиБ на входе).
CREATE TABLE inventory_scan_reports (
    id              uuid        PRIMARY KEY,
    org_id          uuid        NOT NULL REFERENCES organizations (id),
    model_id        uuid        NOT NULL REFERENCES inventory_models (id) ON DELETE CASCADE,
    kind            text        NOT NULL CHECK (kind IN ('scan', 'verify')),
    host            text        NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253),
    scanner_version text        NOT NULL CHECK (char_length(scanner_version) BETWEEN 1 AND 64),
    received_at     timestamptz NOT NULL CHECK (isfinite(received_at)),
    received_by     text        NOT NULL CHECK (char_length(received_by) BETWEEN 1 AND 128),
    verdict         text        NOT NULL CHECK (verdict IN ('ok', 'warn', 'block')),
    hashes          text        NOT NULL CHECK (hashes IN ('match', 'mismatch', 'no_reference')),
    templates       text        NOT NULL CHECK (templates IN ('none', 'baseline', 'unknown', 'changed', 'injection')),
    files           integer     NOT NULL CHECK (files BETWEEN 0 AND 10000),
    findings        integer     NOT NULL CHECK (findings >= 0),
    blocked         boolean     NOT NULL,
    report          jsonb       NOT NULL
);

CREATE INDEX inventory_scan_reports_model ON inventory_scan_reports (model_id, received_at DESC, id);

REVOKE ALL ON inventory_scan_reports FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON inventory_scan_reports TO aisec_app;
