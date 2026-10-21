-- События в API консоли (ТЗ 5.5, 5.8, 7.3 УПД.7; задача 2.16): изменение
-- сроков хранения, сохранённые фильтры, агрегаты по минутам и часам.

-- Имя разрешения — из 2–3 частей через точку: events.content.read из ТЗ 5.5
-- (проверка в коде — internal/auth.validPermissionName).
ALTER TABLE role_permissions DROP CONSTRAINT role_permissions_permission_check;
ALTER TABLE role_permissions ADD CONSTRAINT role_permissions_permission_check
    CHECK (permission ~ '^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*){1,2}$' AND char_length(permission) <= 64);

-- Сроки хранения меняет администратор через API с записью в аудит той же
-- транзакцией (events.settings_changed). Удаление по-прежнему только
-- секциями (events_drop_expired).
GRANT UPDATE (metadata_days, content_days, updated_at) ON event_settings TO aisec_app;

-- Сохранённые фильтры: личные, в канонической записи языка фильтров.
CREATE TABLE event_filters (
    id         uuid        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    user_id    uuid        NOT NULL REFERENCES users (id),
    name       text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    filter     text        NOT NULL CHECK (octet_length(filter) <= 2048),
    created_at timestamptz NOT NULL,
    UNIQUE (org_id, user_id, name)
);

-- Агрегаты для дашбордов (ТЗ 5.8, 12). Отсутствующее измерение — пустая
-- строка, чтобы оно входило в первичный ключ. threats — счётчики по ID
-- строк матрицы обнаружения: {"DM-05": 3}.
CREATE TABLE event_aggregates_minute (
    org_id             uuid        NOT NULL REFERENCES organizations (id),
    bucket             timestamptz NOT NULL,
    app                text        NOT NULL,
    type               text        NOT NULL,
    action             text        NOT NULL,
    severity           text        NOT NULL,
    events             bigint      NOT NULL CHECK (events > 0),
    with_findings      bigint      NOT NULL CHECK (with_findings >= 0),
    non_text_unchecked bigint      NOT NULL CHECK (non_text_unchecked >= 0),
    tokens_prompt      bigint      NOT NULL CHECK (tokens_prompt >= 0),
    tokens_completion  bigint      NOT NULL CHECK (tokens_completion >= 0),
    threats            jsonb       NOT NULL CHECK (jsonb_typeof(threats) = 'object'),
    PRIMARY KEY (org_id, bucket, app, type, action, severity)
);

CREATE TABLE event_aggregates_hour (LIKE event_aggregates_minute INCLUDING ALL);
ALTER TABLE event_aggregates_hour
    ADD FOREIGN KEY (org_id) REFERENCES organizations (id);

-- Отметка задания агрегатов: учтены события, принятые не позже
-- received_upto. Начало — неделя назад: старше сервер события не принимает.
CREATE TABLE event_aggregate_state (
    id            boolean     PRIMARY KEY DEFAULT true CHECK (id),
    received_upto timestamptz NOT NULL
);

INSERT INTO event_aggregate_state (received_upto) VALUES (now() - interval '8 days');

-- Поиск минут, в которые попали недавно принятые события.
CREATE INDEX events_received ON events (received_at);

REVOKE ALL ON event_filters, event_aggregates_minute, event_aggregates_hour, event_aggregate_state FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON event_filters TO aisec_app;
-- Агрегаты — производные данные: пересчёт заменяет строки, срок хранения
-- удаляет старые.
GRANT SELECT, INSERT, UPDATE, DELETE ON event_aggregates_minute, event_aggregates_hour TO aisec_app;
GRANT SELECT ON event_aggregate_state TO aisec_app;
GRANT UPDATE (received_upto) ON event_aggregate_state TO aisec_app;
