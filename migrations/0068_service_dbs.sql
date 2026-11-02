-- Служебные базы (ОБН.4; задача 5.15 этапа 5, ADR-0028): одна таблица для
-- всех видов вместо таблицы на каждую базу.
--
-- На вид хранится не больше двух версий: текущая (current) и предыдущая
-- (previous) — откат только на неё. Строка — подписанный файл целиком
-- (подпись проверяется заново при каждом запуске сервера), версия, дата
-- выпуска, число записей, номер заверения и отпечаток рабочего ключа, кто
-- и когда загрузил. Строки каталога теневого ИИ (0061) и базы требований
-- (0065) переносятся в слот current, прежние таблицы удаляются: до первого
-- пилота совместимость не нужна (ADR-0028, п. 6).

CREATE TABLE service_dbs (
    org_id        uuid        NOT NULL REFERENCES organizations (id),
    kind          text        NOT NULL CHECK (kind ~ '^[a-z0-9_]{1,64}$'),
    slot          text        NOT NULL CHECK (slot IN ('current', 'previous')),
    version       bigint      NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    db_date       date        NOT NULL,
    records       integer     NOT NULL CHECK (records >= 0),
    -- Номер заверения рабочего ключа и отпечаток ключа (ADR-0027, п. 2).
    subkey_serial bigint      NOT NULL CHECK (subkey_serial BETWEEN 1 AND 9007199254740991),
    fingerprint   text        NOT NULL CHECK (char_length(fingerprint) BETWEEN 1 AND 128),
    file          bytea       NOT NULL CHECK (octet_length(file) BETWEEN 1 AND 4194304),
    uploaded_at   timestamptz NOT NULL,
    uploaded_by   text        NOT NULL CHECK (char_length(uploaded_by) BETWEEN 1 AND 128),
    PRIMARY KEY (org_id, kind, slot)
);

INSERT INTO service_dbs (org_id, kind, slot, version, db_date, records, subkey_serial, fingerprint, file, uploaded_at, uploaded_by)
SELECT org_id, 'shadow_ai_catalog', 'current', version, catalog_date, services, subkey_serial, fingerprint, file, uploaded_at, uploaded_by
FROM shadow_ai_catalog;

INSERT INTO service_dbs (org_id, kind, slot, version, db_date, records, subkey_serial, fingerprint, file, uploaded_at, uploaded_by)
SELECT org_id, 'compliance_requirements', 'current', version, base_date, requirements, subkey_serial, fingerprint, file, uploaded_at, uploaded_by
FROM compliance_base;

DROP TABLE shadow_ai_catalog;
DROP TABLE compliance_base;

REVOKE ALL ON service_dbs FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON service_dbs TO aisec_app;
