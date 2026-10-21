-- Архивация журнала аудита (ТЗ 7.4 РСБ.4; решение Р5 этапа 2; ADR-0008).
-- Записи старше срока хранения выгружаются aisec-cli audit archive в файл с
-- подписанной контрольной точкой и только затем удаляются под ролью
-- aisec_audit_archiver. Хранимая часть цепочки начинается от последней точки.

-- Контрольные точки: seq и hash последней архивированной записи, связь с
-- предыдущей точкой (prev_seq, prev_hash; у первой — 0 и нулевой хеш), хеш
-- тела файла архива и подпись Ed25519 ключом audit-signing.key. Подпись
-- проверяется открытым ключом из каталога ключей, а не из этой таблицы:
-- public_key здесь — только для сверки при разборе инцидента.
CREATE TABLE audit_checkpoints (
    id             uuid        PRIMARY KEY,
    org_id         uuid        NOT NULL REFERENCES organizations (id),
    seq            bigint      NOT NULL UNIQUE CHECK (seq > 0),
    hash           bytea       NOT NULL CHECK (octet_length(hash) BETWEEN 16 AND 64),
    hash_alg       text        NOT NULL CHECK (char_length(hash_alg) BETWEEN 1 AND 32),
    prev_seq       bigint      NOT NULL CHECK (prev_seq >= 0 AND prev_seq < seq),
    prev_hash      bytea       NOT NULL CHECK (octet_length(prev_hash) BETWEEN 16 AND 64),
    records        bigint      NOT NULL CHECK (records = seq - prev_seq),
    archive_name   text        NOT NULL CHECK (char_length(archive_name) BETWEEN 1 AND 255),
    archive_hash   bytea       NOT NULL CHECK (octet_length(archive_hash) BETWEEN 16 AND 64),
    created_at     timestamptz NOT NULL CHECK (isfinite(created_at)),
    sig_alg        text        NOT NULL CHECK (char_length(sig_alg) BETWEEN 1 AND 32),
    signature      bytea       NOT NULL CHECK (octet_length(signature) BETWEEN 32 AND 256),
    public_key     bytea       NOT NULL CHECK (octet_length(public_key) BETWEEN 16 AND 256)
);

-- Точки только добавляются: подмена или удаление точки спрятали бы
-- удаление начала журнала. Функция audit_append_only — из 0002_audit.
CREATE TRIGGER audit_checkpoints_no_update BEFORE UPDATE ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_checkpoints_no_delete BEFORE DELETE ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_checkpoints_no_truncate BEFORE TRUNCATE ON audit_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();

-- Новая точка описывает журнал как он есть: продолжает последнюю точку
-- (первая — от 0 и нулевого хеша), её запись есть в журнале с тем же
-- хешем и алгоритмом, все записи диапазона на месте, а после неё журнал
-- продолжается (последняя запись не архивируется). Так роль архиватора не
-- может вставить точку, которая скрыла бы удаление непроверенных записей;
-- подпись точки проверяет internal/audit. Таблицы читаются по схеме
-- триггера, search_path функции фиксирован.
CREATE FUNCTION audit_checkpoint_link() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    last_seq  bigint;
    last_hash bytea;
    n         bigint;
BEGIN
    EXECUTE format('SELECT seq, hash FROM %I.%I ORDER BY seq DESC LIMIT 1', TG_TABLE_SCHEMA, TG_TABLE_NAME)
        INTO last_seq, last_hash;
    IF last_seq IS NULL THEN
        last_seq := 0;
        last_hash := decode(repeat('00', octet_length(NEW.prev_hash)), 'hex');
    END IF;
    IF NEW.prev_seq <> last_seq OR NEW.prev_hash <> last_hash THEN
        RAISE EXCEPTION 'контрольная точка % не продолжает предыдущую', NEW.seq
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    EXECUTE format('SELECT count(*) FROM %I.audit_log WHERE seq = $1 AND hash = $2 AND hash_alg = $3', TG_TABLE_SCHEMA)
        INTO n USING NEW.seq, NEW.hash, NEW.hash_alg;
    IF n <> 1 THEN
        RAISE EXCEPTION 'контрольная точка %: такой записи в журнале нет', NEW.seq
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    EXECUTE format('SELECT count(*) FROM %I.audit_log WHERE seq > $1 AND seq <= $2', TG_TABLE_SCHEMA)
        INTO n USING NEW.prev_seq, NEW.seq;
    IF n <> NEW.records THEN
        RAISE EXCEPTION 'контрольная точка %: в журнале % записей диапазона из %', NEW.seq, n, NEW.records
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    EXECUTE format('SELECT count(*) FROM (SELECT 1 FROM %I.audit_log WHERE seq > $1 LIMIT 1) t', TG_TABLE_SCHEMA)
        INTO n USING NEW.seq;
    IF n = 0 THEN
        RAISE EXCEPTION 'контрольная точка %: последняя запись журнала не архивируется', NEW.seq
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER audit_checkpoints_link BEFORE INSERT ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION audit_checkpoint_link();

-- Удаление из журнала (0002 разрешала его роли архиватора) — теперь только
-- записей, уже покрытых контрольной точкой: удалить запись, о которой нет
-- точки, нельзя даже архиватору.
CREATE OR REPLACE FUNCTION audit_log_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    covered bigint;
BEGIN
    IF TG_OP = 'DELETE' AND current_user = 'aisec_audit_archiver' THEN
        EXECUTE format('SELECT max(seq) FROM %I.audit_checkpoints', TG_TABLE_SCHEMA) INTO covered;
        IF covered IS NOT NULL AND OLD.seq <= covered THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION '%: удаление записи % без контрольной точки запрещено', TG_TABLE_NAME, OLD.seq
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RAISE EXCEPTION '%: % запрещено (только добавление)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

-- Связность для пустого журнала. В 0002 пустая таблица принимала любую
-- первую запись; теперь первая запись продолжает последнюю контрольную точку,
-- а без точек — начинается с номера 1 и нулевого prev_hash. Таблицы
-- читаются по схеме триггера (временная таблица в сессии их не подменит).
CREATE OR REPLACE FUNCTION audit_log_link() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    last_seq  bigint;
    last_hash bytea;
BEGIN
    EXECUTE format('SELECT seq, hash FROM %I.%I ORDER BY seq DESC LIMIT 1', TG_TABLE_SCHEMA, TG_TABLE_NAME)
        INTO last_seq, last_hash;
    IF last_seq IS NULL THEN
        EXECUTE format('SELECT seq, hash FROM %I.audit_checkpoints ORDER BY seq DESC LIMIT 1', TG_TABLE_SCHEMA)
            INTO last_seq, last_hash;
    END IF;
    IF last_seq IS NULL THEN
        IF NEW.seq <> 1 OR NEW.prev_hash <> decode(repeat('00', octet_length(NEW.prev_hash)), 'hex') THEN
            RAISE EXCEPTION 'журнал аудита: первая запись должна иметь номер 1 и нулевой prev_hash'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.seq <> last_seq + 1 OR NEW.prev_hash <> last_hash THEN
        RAISE EXCEPTION 'журнал аудита: запись % не продолжает цепочку', NEW.seq
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

-- Права. Процедура архивации работает под SET ROLE aisec_audit_archiver
-- (логину aisec-cli нужно членство в этой роли): читает и удаляет записи,
-- добавляет контрольную точку и запись audit.archive. Удаление разрешает
-- триггер audit_log_guard только этой роли и только для записей, покрытых
-- точкой.
REVOKE ALL ON audit_checkpoints FROM PUBLIC;
GRANT SELECT ON audit_checkpoints TO aisec_app;
GRANT SELECT, INSERT ON audit_checkpoints TO aisec_audit_archiver;
GRANT SELECT, INSERT, DELETE ON audit_log TO aisec_audit_archiver;
GRANT SELECT ON audit_settings TO aisec_audit_archiver;
