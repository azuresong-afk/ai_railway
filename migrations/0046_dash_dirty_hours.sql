-- Часы агрегатов дашбордов к досчёту (3В25 ревью 3.r3 этапа 3). Хук приёма
-- событий больше не ждёт блокировку агрегатов: если час пересчитывается
-- (досчёт держит его исключительную блокировку) или прирост не удался, хук
-- добавляет сюда строку и пакет событий принимается без задержки. Задача
-- досчёта пересчитывает такие часы первыми и удаляет строки. Уникального
-- ключа нет намеренно: вставка не ждёт удаления той же строки досчётом.
CREATE TABLE dash_dirty_hours (
    org_id    uuid        NOT NULL REFERENCES organizations (id),
    bucket    timestamptz NOT NULL CHECK (date_trunc('hour', bucket, 'UTC') = bucket),
    marked_at timestamptz NOT NULL
);

CREATE INDEX dash_dirty_hours_org_bucket ON dash_dirty_hours (org_id, bucket);

REVOKE ALL ON dash_dirty_hours FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON dash_dirty_hours TO aisec_app;
