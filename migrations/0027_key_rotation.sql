-- Ротация мастер-ключа и ключа данных (ТЗ 7.9 ЗИ.1, 10.4; решение Р1 этапа 3;
-- ADR-0018, п. 2, 3, 9; задача 3.2).
--
-- 1. Мастер-ключ: строки data_keys перешифровываются новым мастер-ключом
--    (aisec-cli keys rotate-master). Обёртка меняется только вместе с ростом
--    master_version — номера мастер-ключа, которым она сделана.
-- 2. Ключ данных: aisec-cli keys rotate-data перешифровывает секреты TOTP и
--    содержимое событий full новой версией ключа. Триггеры разрешают это
--    только как переход на более новую версию ключа при неизменных
--    остальных столбцах; прочие изменения подключённого фактора и
--    содержимого событий по-прежнему запрещены всем.

ALTER TABLE data_keys ADD COLUMN master_version integer NOT NULL DEFAULT 1 CHECK (master_version > 0);

CREATE OR REPLACE FUNCTION data_keys_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.sealed < OLD.sealed THEN
        RAISE EXCEPTION 'data_keys: счётчик шифрований не уменьшается'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id <> OLD.id OR NEW.org_id <> OLD.org_id OR NEW.version <> OLD.version
        OR NEW.profile <> OLD.profile OR NEW.alg <> OLD.alg OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'data_keys: ключ не меняется, ротация — новой версией'
            USING ERRCODE = 'check_violation';
    END IF;
    -- Новая обёртка — только новым мастер-ключом (rotate-master).
    IF (NEW.wrapped <> OLD.wrapped) <> (NEW.master_version <> OLD.master_version)
        OR NEW.master_version < OLD.master_version THEN
        RAISE EXCEPTION 'data_keys: обёртка меняется только вместе с ростом номера мастер-ключа'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
        RAISE EXCEPTION 'data_keys: выведенный ключ не возвращается'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

-- Переход шифротекста на более новую версию ключа данных той же
-- организации проверяется запросом к data_keys по схеме триггера:
-- временная таблица в сессии её не подменит.

-- Подключённый фактор меняется только сбросом, кроме перешифрования новой
-- версией ключа данных: секрет и ключ меняются вместе, остальное — нет.
CREATE OR REPLACE FUNCTION user_mfa_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    upgrade boolean;
BEGIN
    IF NEW.user_id <> OLD.user_id THEN
        RAISE EXCEPTION 'user_mfa: пользователь не меняется' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.last_step < OLD.last_step THEN
        RAISE EXCEPTION 'user_mfa: шаг кода не уменьшается' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'enabled' AND (NEW.state <> OLD.state OR NEW.alg <> OLD.alg
        OR NEW.created_at <> OLD.created_at OR NEW.enabled_at IS DISTINCT FROM OLD.enabled_at) THEN
        RAISE EXCEPTION 'user_mfa: подключённый фактор меняется только сбросом' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'enabled' AND (NEW.secret <> OLD.secret OR NEW.data_key_id <> OLD.data_key_id) THEN
        IF NEW.data_key_id <> OLD.data_key_id THEN
            EXECUTE format('SELECT n.version > o.version AND n.org_id = o.org_id FROM %I.data_keys o, %I.data_keys n
                WHERE o.id = $1 AND n.id = $2', TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
                INTO upgrade USING OLD.data_key_id, NEW.data_key_id;
        END IF;
        IF NOT coalesce(upgrade, false) THEN
            RAISE EXCEPTION 'user_mfa: секрет подключённого фактора меняется только сбросом или перешифрованием новой версией ключа'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

-- Содержимое событий не меняется и не удаляется построчно, кроме
-- перешифрования новой версией ключа данных: меняются только key_id и
-- sealed (те же сутки, тот же алгоритм).
CREATE FUNCTION event_content_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    upgrade boolean;
BEGIN
    IF TG_OP = 'UPDATE'
        AND (NEW.event_id, NEW.ts, NEW.org_id, NEW.storage, NEW.request, NEW.response, NEW.key_day, NEW.alg)
            IS NOT DISTINCT FROM (OLD.event_id, OLD.ts, OLD.org_id, OLD.storage, OLD.request, OLD.response, OLD.key_day, OLD.alg)
        AND NEW.sealed IS NOT NULL AND OLD.key_id IS NOT NULL AND NEW.key_id IS NOT NULL
        AND NEW.key_id <> OLD.key_id THEN
        -- Схема родительской таблицы: у секций своя схема не бывает.
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

DROP TRIGGER event_content_immutable ON event_content;
CREATE TRIGGER event_content_guard BEFORE UPDATE OR DELETE ON event_content
    FOR EACH ROW EXECUTE FUNCTION event_content_guard();
