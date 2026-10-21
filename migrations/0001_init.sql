-- Организации. Все таблицы с данными заказчика несут org_id (ТЗ 6.2, 12):
-- в MVP одна организация, но схема не требует переделки для нескольких.
CREATE TABLE organizations (
    id         uuid        PRIMARY KEY,
    name       text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Организация по умолчанию с фиксированным идентификатором UUIDv7-формата.
INSERT INTO organizations (id, name)
VALUES ('00000000-0000-7000-8000-000000000001', 'Организация по умолчанию');
