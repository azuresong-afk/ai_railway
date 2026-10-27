-- Реестр агентов, MCP-серверов и инструментов (ТЗ 5.10, 5.16; задача 4.8
-- этапа 4, ADR-0023, раздел 1). Инструмент хранит последнее увиденное и
-- одобренное описание (каноническая форма, internal/agents.DescriptorHash) и
-- их хеши: изменение после одобрения переводит его в changed, вызовы
-- блокируются до повторного одобрения (DM-25). Учётные данные MCP-сервера
-- шифруются ключом данных с AAD mcp_servers|credential|<id> (ADR-0007).
-- Ключ приложения можно привязать к агенту при выпуске; привязка не
-- меняется, агент с привязанным ключом не удаляется.

CREATE TABLE mcp_servers (
    id                uuid        PRIMARY KEY,
    org_id            uuid        NOT NULL REFERENCES organizations (id),
    -- slug — имя в пути прокси шлюза (/mcp/v1/{slug}); function занят
    -- функциями агентов в политике вызовов.
    slug              text        NOT NULL CHECK (slug ~ '^[a-z0-9-]{1,64}$' AND slug <> 'function'),
    name              text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    url               text        NOT NULL CHECK (char_length(url) BETWEEN 8 AND 2048),
    ca_pem            text        NOT NULL CHECK (char_length(ca_pem) BETWEEN 1 AND 262144),
    -- Имя заголовка учётных данных; NULL — Authorization: Bearer.
    auth_header       text        CHECK (auth_header ~ '^[A-Za-z0-9-]{1,64}$'),
    credential        bytea       CHECK (octet_length(credential) BETWEEN 16 AND 17408),
    credential_key_id uuid        REFERENCES data_keys (id),
    credential_alg    text        CHECK (char_length(credential_alg) BETWEEN 1 AND 32),
    credential_set_at timestamptz,
    -- Сервер вне контура заказчика: по умолчанию; снимает только
    -- администратор безопасности (DM-40).
    external          boolean     NOT NULL DEFAULT true,
    -- Разрешён адрес http:// (администратор безопасности, DM-40).
    insecure_http     boolean     NOT NULL DEFAULT false,
    call_timeout_s    integer     NOT NULL DEFAULT 0 CHECK (call_timeout_s BETWEEN 0 AND 600),
    versions          text[]      NOT NULL CHECK (cardinality(versions) BETWEEN 1 AND 2
                                  AND versions <@ ARRAY['2026-07-28', '2025-11-25']),
    created_at        timestamptz NOT NULL,
    created_by        text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at        timestamptz NOT NULL,
    updated_by        text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    UNIQUE (org_id, slug),
    CHECK (url LIKE 'https://%' OR insecure_http AND url LIKE 'http://%'),
    CHECK ((credential IS NULL) = (credential_key_id IS NULL)
       AND (credential IS NULL) = (credential_alg IS NULL)
       AND (credential IS NULL) = (credential_set_at IS NULL))
);

CREATE TABLE agents (
    id          uuid        PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES organizations (id),
    app_id      uuid        NOT NULL REFERENCES applications (id),
    slug        text        NOT NULL CHECK (slug ~ '^[a-z0-9-]{1,64}$'),
    name        text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    owner       text        NOT NULL DEFAULT '' CHECK (char_length(owner) <= 200),
    status      text        NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at  timestamptz NOT NULL,
    created_by  text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at  timestamptz NOT NULL,
    updated_by  text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    UNIQUE (org_id, app_id, slug),
    -- Цель составного внешнего ключа app_keys (agent_id, app_id): ключ
    -- привязывается только к агенту своего приложения.
    UNIQUE (id, app_id)
);

CREATE INDEX agents_app ON agents (app_id, slug);

-- MCP-серверы агента. Сервер из списка агента не удаляется (внешний ключ
-- без каскада), агент удаляется вместе со списком.
CREATE TABLE agent_servers (
    org_id    uuid NOT NULL REFERENCES organizations (id),
    agent_id  uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    server_id uuid NOT NULL REFERENCES mcp_servers (id),
    PRIMARY KEY (agent_id, server_id)
);

CREATE INDEX agent_servers_server ON agent_servers (server_id);

-- Инструмент: пара (MCP-сервер, имя) или (агент, имя) для функций пути chat.
CREATE TABLE agent_tools (
    id                  uuid        PRIMARY KEY,
    org_id              uuid        NOT NULL REFERENCES organizations (id),
    server_id           uuid        REFERENCES mcp_servers (id) ON DELETE CASCADE,
    agent_id            uuid        REFERENCES agents (id) ON DELETE CASCADE,
    name                text        NOT NULL CHECK (name ~ '^[A-Za-z0-9_.-]{1,128}$'),
    -- Каноническая форма последнего увиденного и одобренного описания.
    descriptor          text        NOT NULL CHECK (octet_length(descriptor) BETWEEN 2 AND 65536),
    descriptor_hash     bytea       NOT NULL CHECK (octet_length(descriptor_hash) BETWEEN 16 AND 64),
    approved_descriptor text        CHECK (octet_length(approved_descriptor) BETWEEN 2 AND 65536),
    approved_hash       bytea       CHECK (octet_length(approved_hash) BETWEEN 16 AND 64),
    hash_alg            text        NOT NULL CHECK (char_length(hash_alg) BETWEEN 1 AND 32),
    risk                text        NOT NULL CHECK (risk IN ('low', 'medium', 'high', 'critical')),
    status              text        NOT NULL CHECK (status IN ('new', 'approved', 'changed', 'suspicious', 'revoked')),
    first_seen          timestamptz NOT NULL,
    last_seen           timestamptz NOT NULL,
    decided_by          text        CHECK (char_length(decided_by) BETWEEN 1 AND 128),
    decided_at          timestamptz,
    comment             text        NOT NULL DEFAULT '' CHECK (char_length(comment) <= 500),
    updated_at          timestamptz NOT NULL,
    CHECK ((server_id IS NULL) <> (agent_id IS NULL)),
    CHECK ((approved_hash IS NULL) = (approved_descriptor IS NULL)),
    -- Одобренный инструмент всегда с одобренным хешем, совпадающим с
    -- увиденным (DM-25).
    CHECK (status <> 'approved' OR approved_hash = descriptor_hash),
    CHECK ((decided_by IS NULL) = (decided_at IS NULL))
);

CREATE UNIQUE INDEX agent_tools_server_name ON agent_tools (server_id, name) WHERE server_id IS NOT NULL;
CREATE UNIQUE INDEX agent_tools_agent_name ON agent_tools (agent_id, name) WHERE agent_id IS NOT NULL;
CREATE INDEX agent_tools_org ON agent_tools (org_id);

-- Привязка ключа приложения к агенту (ADR-0023, раздел 1).
ALTER TABLE app_keys ADD COLUMN agent_id uuid;
ALTER TABLE app_keys ADD CONSTRAINT app_keys_agent_fkey FOREIGN KEY (agent_id, app_id) REFERENCES agents (id, app_id);
CREATE INDEX app_keys_agent ON app_keys (agent_id) WHERE agent_id IS NOT NULL;

-- Ключ: привязка к агенту, как и прочие поля, кроме срока и отзыва, не
-- меняется (задача 2.11, миграция 0014).
CREATE OR REPLACE FUNCTION app_keys_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'app_keys: ключи не удаляются, только отзываются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'app_keys: отозванный ключ не меняется'
            USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.org_id, NEW.app_id, NEW.name, NEW.prefix, NEW.key_hash, NEW.hash_alg, NEW.allowed_cidrs,
        NEW.created_at, NEW.created_by, NEW.rotated_from, NEW.agent_id) IS DISTINCT FROM
       (OLD.id, OLD.org_id, OLD.app_id, OLD.name, OLD.prefix, OLD.key_hash, OLD.hash_alg, OLD.allowed_cidrs,
        OLD.created_at, OLD.created_by, OLD.rotated_from, OLD.agent_id) THEN
        RAISE EXCEPTION 'app_keys: меняются только срок и отметка отзыва'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.expires_at > OLD.expires_at THEN
        RAISE EXCEPTION 'app_keys: срок ключа не продлевается — выпустите новый ключ'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

-- ID, организация, slug, приложение и сведения о создании неизменны.
CREATE FUNCTION agents_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF (NEW.id, NEW.org_id, NEW.app_id, NEW.slug, NEW.created_at, NEW.created_by)
        IS DISTINCT FROM (OLD.id, OLD.org_id, OLD.app_id, OLD.slug, OLD.created_at, OLD.created_by) THEN
        RAISE EXCEPTION 'agents: ID, приложение, slug и сведения о создании не меняются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION mcp_servers_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF (NEW.id, NEW.org_id, NEW.slug, NEW.created_at, NEW.created_by) IS DISTINCT FROM
       (OLD.id, OLD.org_id, OLD.slug, OLD.created_at, OLD.created_by) THEN
        RAISE EXCEPTION 'mcp_servers: ID, slug и сведения о создании не меняются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION agent_tools_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF (NEW.id, NEW.org_id, NEW.server_id, NEW.agent_id, NEW.name, NEW.first_seen) IS DISTINCT FROM
       (OLD.id, OLD.org_id, OLD.server_id, OLD.agent_id, OLD.name, OLD.first_seen) THEN
        RAISE EXCEPTION 'agent_tools: ID, владелец, имя и время появления не меняются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER agents_guard BEFORE UPDATE ON agents FOR EACH ROW EXECUTE FUNCTION agents_guard();
CREATE TRIGGER mcp_servers_guard BEFORE UPDATE ON mcp_servers FOR EACH ROW EXECUTE FUNCTION mcp_servers_guard();
CREATE TRIGGER agent_tools_guard BEFORE UPDATE ON agent_tools FOR EACH ROW EXECUTE FUNCTION agent_tools_guard();

-- Счётчик изменений конфигурации шлюзов (миграция 0030): разделы пакета
-- agents, mcp_servers и agent_tools. У инструментов — только поля пакета:
-- время last_seen и описание пересборку не вызывают.
CREATE TRIGGER mcp_servers_revision AFTER INSERT OR DELETE ON mcp_servers
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER mcp_servers_revision_update AFTER UPDATE ON mcp_servers
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER agents_revision AFTER INSERT OR DELETE ON agents
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER agents_revision_update AFTER UPDATE ON agents
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER agent_servers_revision AFTER INSERT OR DELETE ON agent_servers
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER agent_tools_revision AFTER INSERT OR DELETE ON agent_tools
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER agent_tools_revision_update AFTER UPDATE ON agent_tools
    FOR EACH ROW WHEN ((OLD.status, OLD.approved_hash, OLD.risk, OLD.hash_alg) IS DISTINCT FROM
                       (NEW.status, NEW.approved_hash, NEW.risk, NEW.hash_alg))
    EXECUTE FUNCTION config_revision_bump();

REVOKE ALL ON mcp_servers, agents, agent_servers, agent_tools FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_servers, agents, agent_servers, agent_tools TO aisec_app;
