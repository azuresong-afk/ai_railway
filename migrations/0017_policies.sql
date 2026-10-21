-- Политики в сервере управления (ТЗ 5.3; задача 2.12): неизменяемые
-- версии, откат новой версией, импорт и экспорт YAML по схеме этапа 1.
-- Версия хранится каноничным YAML (policy.Marshal) с хешем профиля — из
-- него собирается пакет для шлюзов (задача 2.13). Шаблоны в БД не хранятся:
-- они в коде и обновляются вместе с продуктом.

CREATE TABLE policies (
    id              uuid        PRIMARY KEY,
    org_id          uuid        NOT NULL REFERENCES organizations (id),
    -- slug — ID политики в YAML, файле шлюза и пакете; неизменяем и не
    -- совпадает с ID шаблона.
    slug            text        NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'
                                    AND slug NOT IN ('base', 'pii-strict', 'external-no-pii', 'monitor-only')),
    -- name и mode — из текущей версии (для списка без разбора YAML).
    name            text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    mode            text        NOT NULL CHECK (mode IN ('monitor', 'enforce')),
    current_version integer     NOT NULL CHECK (current_version >= 1),
    created_at      timestamptz NOT NULL,
    created_by      text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at      timestamptz NOT NULL,
    updated_by      text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    UNIQUE (org_id, slug)
);

CREATE TABLE policy_versions (
    policy_id        uuid        NOT NULL REFERENCES policies (id),
    version          integer     NOT NULL CHECK (version >= 1),
    spec_yaml        text        NOT NULL CHECK (octet_length(spec_yaml) BETWEEN 1 AND 1048576),
    spec_hash        bytea       NOT NULL CHECK (octet_length(spec_hash) BETWEEN 16 AND 64),
    hash_alg         text        NOT NULL CHECK (char_length(hash_alg) BETWEEN 1 AND 32),
    -- source — как появилась версия: api, import, rollback, template.
    source           text        NOT NULL CHECK (source IN ('api', 'import', 'rollback', 'template')),
    comment          text        NOT NULL DEFAULT '' CHECK (char_length(comment) <= 500),
    rolled_back_from integer     CHECK (rolled_back_from >= 1 AND rolled_back_from < version),
    created_at       timestamptz NOT NULL,
    created_by       text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    PRIMARY KEY (policy_id, version),
    CHECK ((source = 'rollback') = (rolled_back_from IS NOT NULL))
);

-- Текущая версия политики существует: проверка в конце транзакции, потому
-- что политика и её первая версия вставляются вместе.
ALTER TABLE policies ADD CONSTRAINT policies_current_version_fkey
    FOREIGN KEY (id, current_version) REFERENCES policy_versions (policy_id, version)
    DEFERRABLE INITIALLY DEFERRED;

-- Версия неизменяема и не удаляется никем, включая владельца схемы; номер —
-- строго следующий за последним (без пропусков и вставки в прошлое).
CREATE FUNCTION policy_versions_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE
    last integer;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'policy_versions: версии политик неизменяемы — сохраните новую версию'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT max(version) INTO last FROM policy_versions WHERE policy_id = NEW.policy_id;
    IF NEW.version <> coalesce(last, 0) + 1 THEN
        RAISE EXCEPTION 'policy_versions: номер версии — следующий за последним'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER policy_versions_guard BEFORE INSERT OR UPDATE OR DELETE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION policy_versions_guard();

-- Политика не удаляется; ID, организация, slug и создание неизменны;
-- текущая версия только растёт на единицу (откат — тоже новая версия).
CREATE FUNCTION policies_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'policies: политики не удаляются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (NEW.id, NEW.org_id, NEW.slug, NEW.created_at, NEW.created_by) IS DISTINCT FROM
       (OLD.id, OLD.org_id, OLD.slug, OLD.created_at, OLD.created_by) THEN
        RAISE EXCEPTION 'policies: ID, slug и сведения о создании не меняются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.current_version <> OLD.current_version + 1 THEN
        RAISE EXCEPTION 'policies: текущая версия меняется только на следующую'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER policies_guard BEFORE UPDATE OR DELETE ON policies
    FOR EACH ROW EXECUTE FUNCTION policies_guard();

REVOKE ALL ON policies, policy_versions FROM PUBLIC;
GRANT SELECT, INSERT ON policies, policy_versions TO aisec_app;
GRANT UPDATE (name, mode, current_version, updated_at, updated_by) ON policies TO aisec_app;
