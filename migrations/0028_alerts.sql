-- Оповещения (ТЗ 5.6; ADR-0020, решения Р3, Р4 этапа 3; задачи 3.9, 3.10).
--
-- Правила «порог» и «новое» считаются в транзакции приёма событий, правила
-- безопасности — в транзакции записи аудита, остальные — фоновой задачей.
-- Содержимое запросов и ответов сюда не копируется: только ID событий и
-- метаданные из столбцов events. Каналы и журнал доставки — миграция 3.13.

CREATE TABLE alert_rules (
    id               uuid        PRIMARY KEY,
    org_id           uuid        NOT NULL REFERENCES organizations (id),
    -- Ключ встроенного правила (создаёт код сервера); NULL — правило администратора.
    builtin_key      text        CHECK (builtin_key ~ '^[a-z][a-z0-9_.]{2,63}$'),
    kind             text        NOT NULL CHECK (kind IN ('threshold', 'new', 'frequency', 'anomaly', 'budget', 'system', 'security')),
    name             text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description      text        NOT NULL CHECK (char_length(description) <= 2000),
    enabled          boolean     NOT NULL,
    severity         text        NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    condition        jsonb       NOT NULL CHECK (jsonb_typeof(condition) = 'object' AND octet_length(condition::text) <= 8192),
    group_by         text[]      NOT NULL CHECK (cardinality(group_by) <= 4),
    suppress_minutes integer     NOT NULL CHECK (suppress_minutes BETWEEN 0 AND 10080),
    group_minutes    integer     NOT NULL CHECK (group_minutes BETWEEN 0 AND 1440),
    recipients       jsonb       NOT NULL CHECK (jsonb_typeof(recipients) = 'object' AND octet_length(recipients::text) <= 8192),
    version          integer     NOT NULL CHECK (version >= 1),
    created_at       timestamptz NOT NULL,
    created_by       text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at       timestamptz NOT NULL,
    updated_by       text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    UNIQUE (org_id, builtin_key),
    -- Системные правила и правила безопасности не отключаются (ТЗ 5.6).
    CHECK (enabled OR kind NOT IN ('system', 'security'))
);

CREATE INDEX alert_rules_org ON alert_rules (org_id, created_at, id);

CREATE TABLE alerts (
    id                uuid        PRIMARY KEY,
    org_id            uuid        NOT NULL REFERENCES organizations (id),
    rule_id           uuid        NOT NULL REFERENCES alert_rules (id),
    kind              text        NOT NULL CHECK (kind IN ('threshold', 'new', 'frequency', 'anomaly', 'budget', 'system', 'security')),
    severity          text        NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    title             text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 300),
    status            text        NOT NULL CHECK (status IN ('new', 'in_progress', 'closed')),
    -- Ключ дедупликации постоянен; open_key равен ему, пока оповещение
    -- принимает новые срабатывания, иначе NULL (ADR-0020, п. 3).
    dedup_key         text        NOT NULL CHECK (octet_length(dedup_key) <= 2048),
    open_key          text,
    group_values      jsonb       NOT NULL CHECK (jsonb_typeof(group_values) = 'object' AND octet_length(group_values::text) <= 4096),
    count             bigint      NOT NULL CHECK (count >= 1),
    suppressed        bigint      NOT NULL CHECK (suppressed >= 0),
    -- Время событий по часам шлюза; NULL — оповещение не по событиям.
    first_event_at    timestamptz,
    last_event_at     timestamptz,
    created_at        timestamptz NOT NULL,
    last_triggered_at timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    assignee_id       uuid,
    closed_at         timestamptz,
    closed_by         text        CHECK (char_length(closed_by) BETWEEN 1 AND 128),
    -- Связь с инцидентом: внешний ключ добавляет задача 3.16.
    incident_id       uuid,
    details           jsonb       NOT NULL CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 16384),
    CHECK (open_key IS NULL OR open_key = dedup_key),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK ((closed_at IS NULL) = (closed_by IS NULL)),
    CHECK (status <> 'closed' OR open_key IS NULL)
);

-- Не больше одного оповещения, принимающего срабатывания, на ключ: вставка
-- при параллельном приёме идёт через ON CONFLICT по этому индексу.
CREATE UNIQUE INDEX alerts_open_key ON alerts (org_id, rule_id, open_key) WHERE open_key IS NOT NULL;
CREATE INDEX alerts_org_created ON alerts (org_id, created_at DESC, id DESC);
-- Окно подавления: последнее закрытое оповещение по ключу.
CREATE INDEX alerts_rule_closed ON alerts (rule_id, dedup_key, closed_at DESC) WHERE status = 'closed';

-- Ссылки на события (не больше 100 на оповещение, дальше только счётчик).
CREATE TABLE alert_events (
    alert_id uuid        NOT NULL REFERENCES alerts (id),
    event_id uuid        NOT NULL,
    -- Ключ секции события (время из UUIDv7) — для перехода к событию.
    event_ts timestamptz NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);

-- Жизненный цикл: новое → принято в работу → закрыто.
CREATE TABLE alert_history (
    id          uuid        PRIMARY KEY,
    alert_id    uuid        NOT NULL REFERENCES alerts (id),
    at          timestamptz NOT NULL,
    actor       text        NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 128),
    from_status text        NOT NULL CHECK (from_status IN ('new', 'in_progress', 'closed')),
    to_status   text        NOT NULL CHECK (to_status IN ('new', 'in_progress', 'closed')),
    comment     text        NOT NULL CHECK (char_length(comment) <= 2000)
);

CREATE INDEX alert_history_alert ON alert_history (alert_id, at);

-- Значения, уже встреченные правилом «новое».
CREATE TABLE alert_seen (
    rule_id    uuid        NOT NULL REFERENCES alert_rules (id),
    value      text        NOT NULL CHECK (char_length(value) BETWEEN 1 AND 256),
    first_seen timestamptz NOT NULL,
    PRIMARY KEY (rule_id, value)
);

-- Права роли сервера: правила и оповещения не удаляются; у оповещения
-- меняются только изменяемые столбцы; ссылки, история и встреченные
-- значения только добавляются.
REVOKE ALL ON alert_rules, alerts, alert_events, alert_history, alert_seen FROM PUBLIC;
GRANT SELECT, INSERT ON alert_rules, alerts, alert_events, alert_history, alert_seen TO aisec_app;
GRANT UPDATE (name, description, enabled, severity, condition, group_by, suppress_minutes, group_minutes, recipients,
    version, updated_at, updated_by) ON alert_rules TO aisec_app;
GRANT UPDATE (status, open_key, count, suppressed, first_event_at, last_event_at, last_triggered_at, updated_at,
    assignee_id, closed_at, closed_by, incident_id, details) ON alerts TO aisec_app;
