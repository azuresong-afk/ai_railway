-- События шлюзов (ТЗ 5.5, 7.9 ЗИ.1, 11.1; решения Р4, Р9 этапа 2; задача 2.15).
-- Таблицы секционированы по суткам UTC средствами ядра PostgreSQL, без
-- расширений. Ключ секции ts — время из UUIDv7 события, поэтому повтор
-- события с тем же ID попадает в ту же строку и ON CONFLICT (id, ts) DO NOTHING
-- делает приём идемпотентным по ID. Секции создаёт и удаляет только функции
-- ниже (SECURITY DEFINER): у роли сервера нет прав на DDL.

CREATE TABLE events (
    id                 uuid        NOT NULL,
    -- Время из UUIDv7 (ключ секции) и время события по часам шлюза:
    -- различаются не больше чем на 5 минут (проверяет сервер).
    ts                 timestamptz NOT NULL,
    event_time         timestamptz NOT NULL,
    org_id             uuid        NOT NULL REFERENCES organizations (id),
    -- Шлюз — из клиентского сертификата mTLS, не из тела пакета.
    gateway_id         uuid        NOT NULL REFERENCES gateways (id),
    received_at        timestamptz NOT NULL,
    type               text        NOT NULL CHECK (type IN ('gateway_request', 'check', 'auth_failure')),
    app                text        CHECK (char_length(app) BETWEEN 1 AND 256),
    env                text        CHECK (char_length(env) BETWEEN 1 AND 256),
    -- Псевдоним пользователя (HMAC на ключе шлюза), не исходный идентификатор.
    user_alias         text        CHECK (char_length(user_alias) BETWEEN 1 AND 256),
    provider           text        CHECK (char_length(provider) BETWEEN 1 AND 256),
    model              text        CHECK (char_length(model) BETWEEN 1 AND 256),
    source             text        CHECK (char_length(source) BETWEEN 1 AND 256),
    policy_mode        text        CHECK (policy_mode IN ('monitor', 'enforce')),
    action             text        CHECK (char_length(action) BETWEEN 1 AND 256),
    rule               text        CHECK (char_length(rule) BETWEEN 1 AND 256),
    severity           text        CHECK (char_length(severity) BETWEEN 1 AND 256),
    storage            text        NOT NULL CHECK (storage IN ('none', 'masked', 'full')),
    threats            text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(threats) <= 64),
    stream             boolean     NOT NULL,
    non_text_unchecked boolean     NOT NULL,
    has_content        boolean     NOT NULL,
    -- Решение с трассировкой, находки, задержки, токены, проверка ответа,
    -- псевдонимизация, auth_failure — без содержимого запросов и ответов.
    details            jsonb       NOT NULL CHECK (jsonb_typeof(details) = 'object'),
    PRIMARY KEY (id, ts),
    CHECK (has_content = false OR storage <> 'none')
) PARTITION BY RANGE (ts);

CREATE INDEX events_org_ts ON events (org_id, ts DESC);

-- Содержимое — отдельно от метаданных: свой срок хранения (по умолчанию 90
-- дней против 12 месяцев) и отдельный доступ (events.content.read, 2.16).
-- masked — замаскированный шлюзом текст; full — только шифротекст JSON
-- {request, response} на производном ключе суток key_day от ключа данных
-- key_id (ADR-0007, п. 8), AAD — event_content/sealed/ID события (Р4).
CREATE TABLE event_content (
    event_id uuid        NOT NULL,
    ts       timestamptz NOT NULL,
    org_id   uuid        NOT NULL REFERENCES organizations (id),
    storage  text        NOT NULL CHECK (storage IN ('masked', 'full')),
    request  text        CHECK (octet_length(request) <= 65552),
    response text        CHECK (octet_length(response) <= 65552),
    key_id   uuid        REFERENCES data_keys (id),
    key_day  date,
    alg      text        CHECK (char_length(alg) BETWEEN 1 AND 32),
    sealed   bytea       CHECK (octet_length(sealed) BETWEEN 1 AND 262144),
    PRIMARY KEY (event_id, ts),
    CHECK ((storage = 'masked' AND sealed IS NULL AND key_id IS NULL AND key_day IS NULL AND alg IS NULL
            AND (request IS NOT NULL OR response IS NOT NULL))
        OR (storage = 'full' AND request IS NULL AND response IS NULL AND sealed IS NOT NULL
            AND key_id IS NOT NULL AND alg IS NOT NULL AND key_day = (ts AT TIME ZONE 'UTC')::date))
) PARTITION BY RANGE (ts);

-- События не меняются и не удаляются построчно: срок хранения — удалением
-- секций (функция events_drop_expired).
CREATE FUNCTION events_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION '%: события не изменяются и не удаляются построчно', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END
$$;

CREATE TRIGGER events_immutable BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION events_immutable();
CREATE TRIGGER event_content_immutable BEFORE UPDATE OR DELETE ON event_content
    FOR EACH ROW EXECUTE FUNCTION events_immutable();

-- Сроки хранения (ТЗ 5.5): одна строка на установку — секции общие для всех
-- организаций. Содержимое — не меньше 7 суток: сервер принимает события за
-- 7 суток назад, и их секции должны существовать. Изменение — через API
-- настроек с записью в аудит (следующие задачи); у сервера пока только чтение.
CREATE TABLE event_settings (
    id            boolean     PRIMARY KEY DEFAULT true CHECK (id),
    metadata_days integer     NOT NULL DEFAULT 365 CHECK (metadata_days BETWEEN 30 AND 3650),
    content_days  integer     NOT NULL DEFAULT 90 CHECK (content_days BETWEEN 7 AND 3650),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (content_days <= metadata_days)
);

INSERT INTO event_settings DEFAULT VALUES;

-- Счётчики отправителя шлюза с его запуска (ТЗ 4.4, DM-44): отброшенные из-за
-- переполнения очереди и отклонённые сервером события. Для «Состояния
-- системы» (задача 2.20).
CREATE TABLE gateway_event_stats (
    gateway_id  uuid        PRIMARY KEY REFERENCES gateways (id),
    started_at  timestamptz NOT NULL,
    dropped     bigint      NOT NULL CHECK (dropped >= 0),
    rejected    bigint      NOT NULL CHECK (rejected >= 0),
    reported_at timestamptz NOT NULL
);

-- Учёт шифрований производными ключами (ADR-0007, п. 8): у AES-GCM со
-- случайным nonce рабочий предел — 2^31 шифрований на ключ. Производный ключ
-- суток day для назначения purpose выводится из ключа данных data_key_id.
CREATE TABLE derived_key_usage (
    data_key_id uuid    NOT NULL REFERENCES data_keys (id),
    purpose     text    NOT NULL CHECK (purpose ~ '^[a-z][a-z0-9_.-]{0,31}$'),
    day         date    NOT NULL,
    sealed      bigint  NOT NULL CHECK (sealed BETWEEN 0 AND 2147483648),
    PRIMARY KEY (data_key_id, purpose, day)
);

-- Секции: events_pYYYYMMDD и event_content_pYYYYMMDD на сутки UTC. Функция
-- создаёт недостающие секции от days_back суток назад до days_ahead вперёд.
-- Схема берётся по самой таблице, search_path функции фиксируется ниже.
CREATE FUNCTION events_ensure_partitions(days_back integer, days_ahead integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    today   date := (now() AT TIME ZONE 'UTC')::date;
    d       date;
    parent  regclass;
    nsp     text;
    part    text;
    created integer := 0;
BEGIN
    IF days_back IS NULL OR days_ahead IS NULL
        OR days_back NOT BETWEEN 0 AND 31 OR days_ahead NOT BETWEEN 0 AND 31 THEN
        RAISE EXCEPTION 'секции событий: days_back и days_ahead — от 0 до 31'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOREACH parent IN ARRAY ARRAY['events'::regclass, 'event_content'::regclass] LOOP
        SELECT n.nspname INTO nsp FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.oid = parent;
        FOR d IN SELECT g::date FROM generate_series(today - days_back, today + days_ahead, interval '1 day') AS g LOOP
            part := (SELECT c.relname FROM pg_class c WHERE c.oid = parent) || '_p' || to_char(d, 'YYYYMMDD');
            IF to_regclass(format('%I.%I', nsp, part)) IS NULL THEN
                EXECUTE format('CREATE TABLE %I.%I PARTITION OF %s FOR VALUES FROM (%L) TO (%L)',
                    nsp, part, parent,
                    to_char(d, 'YYYY-MM-DD') || ' 00:00:00+00', to_char(d + 1, 'YYYY-MM-DD') || ' 00:00:00+00');
                created := created + 1;
            END IF;
        END LOOP;
    END LOOP;
    RETURN created;
END
$$;

-- Удаляет секции старше срока хранения из event_settings: содержимое —
-- старше content_days суток, метаданные — старше metadata_days. Возвращает
-- имена удалённых секций (сервер пишет их в аудит). Срок задают только
-- настройки: аргументов, которыми можно сократить хранение, у функции нет.
CREATE FUNCTION events_drop_expired() RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    today date := (now() AT TIME ZONE 'UTC')::date;
    meta  integer;
    cont  integer;
    r     record;
    d     date;
BEGIN
    SELECT metadata_days, content_days INTO STRICT meta, cont FROM event_settings;
    FOR r IN
        SELECT n.nspname AS nsp, c.relname AS part, p.relname AS parent
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE i.inhparent IN ('events'::regclass, 'event_content'::regclass)
        ORDER BY c.relname
    LOOP
        IF r.part !~ ('^' || r.parent || '_p[0-9]{8}$') THEN
            CONTINUE;
        END IF;
        d := to_date(right(r.part, 8), 'YYYYMMDD');
        IF (r.parent = 'events' AND d < today - meta) OR (r.parent = 'event_content' AND d < today - cont) THEN
            EXECUTE format('DROP TABLE %I.%I', r.nsp, r.part);
            RETURN NEXT r.part;
        END IF;
    END LOOP;
END
$$;

-- search_path функций SECURITY DEFINER фиксирован: сначала pg_catalog, затем
-- схема событий, временные объекты — последними (их нельзя подставить).
DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION events_ensure_partitions(integer, integer) SET search_path = pg_catalog, %I, pg_temp',
        current_schema());
    EXECUTE format('ALTER FUNCTION events_drop_expired() SET search_path = pg_catalog, %I, pg_temp',
        current_schema());
END
$$;

-- Права: сервер добавляет и читает события, вызывает функции секций и
-- ведёт счётчики. UPDATE и DELETE событий нет ни у кого (триггер).
REVOKE ALL ON events, event_content, event_settings, gateway_event_stats, derived_key_usage FROM PUBLIC;
REVOKE ALL ON FUNCTION events_ensure_partitions(integer, integer), events_drop_expired() FROM PUBLIC;
GRANT SELECT, INSERT ON events, event_content TO aisec_app;
GRANT SELECT ON event_settings TO aisec_app;
GRANT SELECT, INSERT, UPDATE ON gateway_event_stats TO aisec_app;
GRANT SELECT, INSERT ON derived_key_usage TO aisec_app;
GRANT UPDATE (sealed) ON derived_key_usage TO aisec_app;
GRANT EXECUTE ON FUNCTION events_ensure_partitions(integer, integer), events_drop_expired() TO aisec_app;
