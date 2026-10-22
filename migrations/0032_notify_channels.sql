-- Каналы уведомлений и журнал доставки (ТЗ 5.6, Р4; ADR-0020 п. 9;
-- задача 3.13 этапа 3).

-- Каналы. Секреты (пароль SMTP, адрес и ключ подписи webhook) — одним
-- шифротекстом ключа данных с AAD notify_channels|secret|<id> (ЗИ.1,
-- ADR-0007). Каналы не удаляются: отключение — ослабление (DM-40), ссылки
-- из журнала доставки сохраняются.
CREATE TABLE notify_channels (
    id            uuid        PRIMARY KEY,
    org_id        uuid        NOT NULL REFERENCES organizations (id),
    name          text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    type          text        NOT NULL CHECK (type IN ('email', 'webhook', 'syslog')),
    enabled       boolean     NOT NULL,
    min_severity  text        NOT NULL CHECK (min_severity IN ('info', 'low', 'medium', 'high', 'critical')),
    -- Настройки без секретов: адрес, порт, формат, корневые сертификаты.
    settings      jsonb       NOT NULL CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 300000),
    -- Какие секреты заданы (без значений): password, url, signing_key.
    secret_fields text[]      NOT NULL CHECK (cardinality(secret_fields) <= 3
        AND secret_fields <@ ARRAY['password', 'url', 'signing_key']),
    secret        bytea       CHECK (octet_length(secret) BETWEEN 16 AND 8192),
    secret_key_id uuid        REFERENCES data_keys (id),
    version       integer     NOT NULL CHECK (version >= 1),
    created_at    timestamptz NOT NULL,
    created_by    text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at    timestamptz NOT NULL,
    updated_by    text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    UNIQUE (org_id, name),
    CHECK ((secret IS NULL) = (secret_key_id IS NULL)),
    CHECK ((secret IS NULL) = (cardinality(secret_fields) = 0))
);

CREATE INDEX notify_channels_org ON notify_channels (org_id, created_at, id);
CREATE INDEX notify_channels_key ON notify_channels (secret_key_id) WHERE secret_key_id IS NOT NULL;

-- Журнал доставки и очередь повторов: без содержимого запросов и
-- секретов, ошибка — код без текста ответа получателя.
CREATE TABLE alert_deliveries (
    id         uuid        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    channel_id uuid        NOT NULL REFERENCES notify_channels (id),
    -- Оповещение; NULL — тестовая отправка.
    alert_id   uuid        REFERENCES alerts (id),
    kind       text        NOT NULL CHECK (kind IN ('alert', 'test')),
    status     text        NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    attempts   integer     NOT NULL CHECK (attempts BETWEEN 0 AND 5),
    next_at    timestamptz NOT NULL,
    error      text        NOT NULL CHECK (error ~ '^[a-z0-9_]{0,40}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    sent_at    timestamptz,
    CHECK ((kind = 'test') = (alert_id IS NULL)),
    CHECK ((status = 'sent') = (sent_at IS NOT NULL))
);

CREATE INDEX alert_deliveries_due ON alert_deliveries (next_at) WHERE status = 'pending';
CREATE INDEX alert_deliveries_channel ON alert_deliveries (channel_id, created_at DESC, id DESC);
CREATE INDEX alert_deliveries_alert ON alert_deliveries (alert_id) WHERE alert_id IS NOT NULL;

REVOKE ALL ON notify_channels, alert_deliveries FROM PUBLIC;
GRANT SELECT, INSERT ON notify_channels, alert_deliveries TO aisec_app;
GRANT UPDATE (name, enabled, min_severity, settings, secret_fields, secret, secret_key_id, version, updated_at, updated_by)
    ON notify_channels TO aisec_app;
GRANT UPDATE (status, attempts, next_at, error, updated_at, sent_at) ON alert_deliveries TO aisec_app;

-- Доставки удаляются вместе с оповещением по сроку хранения (миграция
-- 0031), тестовые — по тому же сроку от создания.
CREATE FUNCTION alert_deliveries_delete_guard() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF OLD.alert_id IS NULL THEN
        IF OLD.created_at < now() - make_interval(days => alert_retention_days(OLD.org_id)) THEN
            RETURN OLD;
        END IF;
    ELSIF alert_expired(OLD.alert_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'журнал доставки удаляется только по сроку хранения' USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER alert_deliveries_delete_guard BEFORE DELETE ON alert_deliveries
    FOR EACH ROW EXECUTE FUNCTION alert_deliveries_delete_guard();

GRANT DELETE ON alert_deliveries TO aisec_app;
