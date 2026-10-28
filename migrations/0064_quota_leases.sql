-- Распределённые квоты и бюджеты при нескольких шлюзах (ADR-0021, задача
-- 4.29 этапа 4). В режиме leased счётчики ведёт сервер, а шлюз берёт у него
-- аренду — долю квоты на короткий срок. Выданная единица учитывается сразу
-- при выдаче, поэтому сумма выданного в окне не больше лимита при любом
-- числе шлюзов. Режим local (по умолчанию) — поведение этапа 3: счётчики в
-- памяти каждого шлюза.

ALTER TABLE install_settings
    ADD COLUMN quota_mode text NOT NULL DEFAULT 'local' CHECK (quota_mode IN ('local', 'leased')),
    -- Время последней смены режима: расход бюджета месяца до включения
    -- аренды берётся из heartbeat один раз после неё (строка base).
    ADD COLUMN quota_mode_changed_at timestamptz CHECK (isfinite(quota_mode_changed_at));

-- Строка на приложение и квоту: выдачи сериализуются её блокировкой
-- (SELECT … FOR UPDATE), два сервера не выдадут одну единицу дважды.
CREATE TABLE quota_locks (
    org_id uuid NOT NULL REFERENCES organizations (id),
    app_id uuid NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    quota  text NOT NULL CHECK (quota IN ('requests_per_minute', 'tokens_per_minute', 'tokens_per_day', 'budget')),
    PRIMARY KEY (org_id, app_id, quota)
);

-- Выдачи и учтённый расход. kind:
--   lease   — аренда шлюза: выдано granted, израсходовано used (NULL — шлюз
--             ещё не сообщил: учитывается всё выданное);
--   offline — расход шлюза на автономной доле, пока сервер был недоступен;
--   base    — расход бюджета месяца до включения аренды (по heartbeat).
-- Единицы: запросы, токены или расход 1e-7 ₽ (бюджет). window_key — окно:
-- minute для минутных квот (учитывается до expires_at + 1 мин), сутки
-- ГГГГ-ММ-ДД и месяц ГГГГ-ММ в часовом поясе установки.
CREATE TABLE quota_grants (
    id          uuid        PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES organizations (id),
    app_id      uuid        NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    quota       text        NOT NULL CHECK (quota IN ('requests_per_minute', 'tokens_per_minute', 'tokens_per_day', 'budget')),
    kind        text        NOT NULL CHECK (kind IN ('lease', 'offline', 'base')),
    -- Шлюз (CN сертификата); у base — пусто.
    gateway_id  text        NOT NULL CHECK (char_length(gateway_id) <= 128 AND (kind = 'base') = (gateway_id = '')),
    -- Идентификатор запроса шлюза: повтор запроса не выдаёт единицы дважды.
    request_id  uuid,
    window_key  text        NOT NULL CHECK (window_key = 'minute' OR window_key ~ '^[0-9]{4}-(0[1-9]|1[0-2])(-[0-3][0-9])?$'),
    granted     bigint      NOT NULL CHECK (granted BETWEEN 0 AND 4611686018427387904),
    used        bigint      CHECK (used >= 0 AND used <= granted),
    granted_at  timestamptz NOT NULL CHECK (isfinite(granted_at)),
    expires_at  timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at >= granted_at),
    reported_at timestamptz CHECK (isfinite(reported_at)),
    CHECK ((kind = 'base') = (request_id IS NULL)),
    CHECK (kind = 'lease' OR used = granted),
    CHECK ((used IS NULL) = (reported_at IS NULL) OR kind <> 'lease'),
    UNIQUE (org_id, gateway_id, request_id, kind)
);

CREATE INDEX quota_grants_window ON quota_grants (org_id, app_id, quota, window_key, expires_at);
CREATE INDEX quota_grants_last ON quota_grants (org_id, app_id, quota, gateway_id, granted_at) WHERE kind = 'lease';
CREATE INDEX quota_grants_expires ON quota_grants (org_id, expires_at);

-- Шлюз сообщил в heartbeat, что работает на автономной доле: условие
-- «квоты в автономном режиме» на «Состоянии системы».
CREATE TABLE quota_gateway_state (
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    gateway_id text        NOT NULL CHECK (char_length(gateway_id) BETWEEN 1 AND 128),
    autonomous boolean     NOT NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (org_id, gateway_id)
);

REVOKE ALL ON quota_locks, quota_grants, quota_gateway_state FROM PUBLIC;
-- UPDATE нужен для SELECT … FOR UPDATE; столбцы строки сервер не меняет.
GRANT SELECT, INSERT, UPDATE ON quota_locks TO aisec_app;
-- UPDATE — только отчёт шлюза об израсходованном; DELETE — очистка старых окон.
GRANT SELECT, INSERT, DELETE ON quota_grants TO aisec_app;
GRANT UPDATE (used, reported_at) ON quota_grants TO aisec_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON quota_gateway_state TO aisec_app;

-- «Состояние системы» (ЗИ.6): quota_approximate — режим local при нескольких
-- шлюзах на связи; quota_autonomous:<ID> — шлюз на автономной доле.
ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server',
                      'test_build', 'ca_expiry', 'ca_expiry:critical',
                      'customer_cert_expiry', 'customer_cert_expiry:critical', 'alert_job_stale',
                      'license_expiry', 'license_expiry:critical', 'license_grace', 'license_restricted',
                      'license_invalid', 'license_clock', 'quota_approximate')
        OR condition ~ '^(integrity:gateway|config_bundle_lag|events_dropped|gateway_offline|cert_expiry|reports_stale|gateway_clock|gateway_tls|quota_autonomous):[0-9a-f-]{1,64}$'));
