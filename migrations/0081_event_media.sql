-- Изображения запроса в содержимом события full (задача 6.13, ADR-0039).
-- Строка на изображение: шифротекст байтов производным ключом суток
-- события от ключа данных key_id (ADR-0007, п. 8), AAD —
-- event_media/sealed/<ID события>/<номер>. Место и формат — открытыми: они
-- уже есть в details.media события. Срок — как у содержимого (content_days):
-- секции event_media_pYYYYMMDD создаёт и удаляет те же функции, что и
-- секции event_content.
CREATE TABLE event_media (
    event_id  uuid        NOT NULL,
    ts        timestamptz NOT NULL,
    idx       smallint    NOT NULL CHECK (idx BETWEEN 0 AND 15),
    org_id    uuid        NOT NULL REFERENCES organizations (id),
    location  text        NOT NULL CHECK (char_length(location) BETWEEN 1 AND 256),
    format    text        NOT NULL CHECK (format IN ('png', 'jpeg', 'gif', 'webp', 'bmp', 'tiff')),
    sanitized boolean     NOT NULL DEFAULT false,
    key_id    uuid        NOT NULL REFERENCES data_keys (id),
    key_day   date        NOT NULL,
    alg       text        NOT NULL CHECK (char_length(alg) BETWEEN 1 AND 32),
    -- 3 МиБ изображения (events.MaxStoredImageBytes) и запас на nonce, тег
    -- и заголовок шифротекста любого криптопрофиля.
    sealed    bytea       NOT NULL CHECK (octet_length(sealed) BETWEEN 1 AND 3146752),
    PRIMARY KEY (event_id, ts, idx),
    CHECK (key_day = (ts AT TIME ZONE 'UTC')::date),
    CHECK (NOT sanitized OR format IN ('png', 'jpeg'))
) PARTITION BY RANGE (ts);

-- Строки не меняются и не удаляются построчно, кроме перешифрования новой
-- версией ключа данных той же организации: меняются только key_id и sealed.
CREATE FUNCTION event_media_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    upgrade boolean;
BEGIN
    IF TG_OP = 'UPDATE'
        AND (NEW.event_id, NEW.ts, NEW.idx, NEW.org_id, NEW.location, NEW.format, NEW.sanitized, NEW.key_day, NEW.alg)
            IS NOT DISTINCT FROM (OLD.event_id, OLD.ts, OLD.idx, OLD.org_id, OLD.location, OLD.format, OLD.sanitized, OLD.key_day, OLD.alg)
        AND NEW.key_id <> OLD.key_id THEN
        EXECUTE format('SELECT n.version > o.version AND n.org_id = o.org_id FROM %I.data_keys o, %I.data_keys n
            WHERE o.id = $1 AND n.id = $2', TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
            INTO upgrade USING OLD.key_id, NEW.key_id;
        IF coalesce(upgrade, false) THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION '%: события не изменяются и не удаляются построчно', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END
$$;

CREATE TRIGGER event_media_guard BEFORE UPDATE OR DELETE ON event_media
    FOR EACH ROW EXECUTE FUNCTION event_media_guard();

-- Секции: те же функции, что в 0010, с третьей таблицей. Сигнатуры и
-- поведение для events и event_content не меняются.
CREATE OR REPLACE FUNCTION events_ensure_partitions(days_back integer, days_ahead integer) RETURNS integer
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
    FOREACH parent IN ARRAY ARRAY['events'::regclass, 'event_content'::regclass, 'event_media'::regclass] LOOP
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

-- Изображения удаляются по сроку содержимого (content_days) вместе с
-- секциями event_content тех же суток.
CREATE OR REPLACE FUNCTION events_drop_expired() RETURNS SETOF text
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
        WHERE i.inhparent IN ('events'::regclass, 'event_content'::regclass, 'event_media'::regclass)
        ORDER BY c.relname
    LOOP
        IF r.part !~ ('^' || r.parent || '_p[0-9]{8}$') THEN
            CONTINUE;
        END IF;
        d := to_date(right(r.part, 8), 'YYYYMMDD');
        IF (r.parent = 'events' AND d < today - meta)
            OR (r.parent IN ('event_content', 'event_media') AND d < today - cont) THEN
            EXECUTE format('DROP TABLE %I.%I', r.nsp, r.part);
            RETURN NEXT r.part;
        END IF;
    END LOOP;
END
$$;

DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION events_ensure_partitions(integer, integer) SET search_path = pg_catalog, %I, pg_temp',
        current_schema());
    EXECUTE format('ALTER FUNCTION events_drop_expired() SET search_path = pg_catalog, %I, pg_temp',
        current_schema());
END
$$;

-- Секции event_media создаёт сервер при запуске и раз в сутки
-- (events.PGStore.EnsurePartitions), как секции событий.

REVOKE ALL ON event_media FROM PUBLIC;
REVOKE ALL ON FUNCTION event_media_guard() FROM PUBLIC;
GRANT SELECT, INSERT ON event_media TO aisec_app;
