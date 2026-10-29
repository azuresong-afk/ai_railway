-- Модуль соответствия требованиям (задача 4.24 этапа 4, решение Р10, ТЗ 5.9):
-- ручные отметки по пунктам базы требований, загруженная подписанная база
-- требований и раздел отчёта «Соответствие» в расписаниях рассылки (4.25).
--
-- Номер: 0062 — лицензии, 0063 — исключения теневого ИИ, 0064 — квоты (4.29).

-- Ручная отметка по пункту (организационные меры): одна на пункт, прежняя
-- заменяется; история изменений — в журнале аудита (compliance.mark_set).
-- Комментарий и документ вводит администратор безопасности; сами требования
-- (ID пункта) в БД не проверяются: база требований — служебная, обновляется
-- без миграций, а отметка без пункта в действующей базе не показывается.
CREATE TABLE compliance_marks (
    org_id         uuid        NOT NULL REFERENCES organizations (id),
    requirement_id text        NOT NULL CHECK (requirement_id ~ '^[a-z0-9][a-z0-9._-]{1,63}$'),
    status         text        NOT NULL CHECK (status IN ('met', 'partial', 'not_met', 'not_applicable')),
    comment        text        NOT NULL CHECK (char_length(comment) BETWEEN 1 AND 1000),
    document       text        NOT NULL DEFAULT '' CHECK (char_length(document) <= 300),
    review_by      date,
    set_at         timestamptz NOT NULL,
    set_by         text        NOT NULL CHECK (char_length(set_by) BETWEEN 1 AND 128),
    PRIMARY KEY (org_id, requirement_id)
);

-- Загруженная подписанная база требований (ADR-0027, п. 3): файл хранится
-- целиком, подпись проверяется заново при запуске сервера.
CREATE TABLE compliance_base (
    org_id        uuid        PRIMARY KEY REFERENCES organizations (id),
    version       bigint      NOT NULL CHECK (version > 0),
    base_date     date        NOT NULL,
    subkey_serial bigint      NOT NULL CHECK (subkey_serial > 0),
    fingerprint   text        NOT NULL CHECK (char_length(fingerprint) BETWEEN 1 AND 128),
    requirements  integer     NOT NULL CHECK (requirements > 0),
    file          bytea       NOT NULL CHECK (octet_length(file) BETWEEN 1 AND 4194304),
    uploaded_at   timestamptz NOT NULL,
    uploaded_by   text        NOT NULL CHECK (char_length(uploaded_by) BETWEEN 1 AND 128)
);

-- Отчёт «Соответствие» в рассылке: как у отчёта по инцидентам, раздел
-- допускается только автору с правом compliance.read на момент сохранения
-- расписания (3В31 ревью 3.r4, УПД.2).
ALTER TABLE report_schedules
    DROP CONSTRAINT report_schedules_report_check,
    ADD CONSTRAINT report_schedules_report_check CHECK (report IN ('summary', 'incidents', 'pilot', 'compliance')),
    ADD COLUMN scope_compliance boolean NOT NULL DEFAULT false,
    ADD CHECK (report <> 'compliance' OR scope_compliance);

REVOKE ALL ON compliance_marks, compliance_base FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_marks TO aisec_app;
GRANT SELECT, INSERT, UPDATE ON compliance_base TO aisec_app;
GRANT UPDATE (scope_compliance) ON report_schedules TO aisec_app;
