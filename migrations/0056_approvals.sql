-- Очередь подтверждений вызовов инструментов агентов (require_approval,
-- DM-22; ТЗ 5.10; задача 4.10 этапа 4, ADR-0023, раздел 5). Запрос создаёт
-- шлюз и ждёт решения долгим опросом; решает пользователь консоли с правом
-- approvals.decide. Аргументы — маскированные шлюзом, до 16 КиБ —
-- шифруются ключом данных с AAD approval_requests|args|<id> (ADR-0007) и
-- удаляются через 30 суток после закрытия; запрос — по сроку метаданных
-- событий. Закрытый запрос не меняется и не открывается снова.

CREATE TABLE approval_requests (
    id               uuid        PRIMARY KEY,
    org_id           uuid        NOT NULL REFERENCES organizations (id),
    gateway_id       uuid        NOT NULL REFERENCES gateways (id),
    path             text        NOT NULL CHECK (path IN ('mcp', 'chat')),
    app              text        NOT NULL CHECK (app ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    -- Агент; пусто — путь chat без агента.
    agent            text        NOT NULL DEFAULT '' CHECK (agent = '' OR agent ~ '^[a-z0-9-]{1,64}$'),
    user_alias       text        NOT NULL DEFAULT '' CHECK (char_length(user_alias) <= 256),
    session          text        NOT NULL DEFAULT '' CHECK (char_length(session) <= 256),
    -- Slug MCP-сервера или function (функции пути chat).
    server           text        NOT NULL CHECK (server ~ '^[a-z0-9-]{1,64}$'),
    tool             text        NOT NULL CHECK (tool ~ '^[A-Za-z0-9_.-]{1,128}$'),
    approved_hash    text        NOT NULL DEFAULT '' CHECK (approved_hash = '' OR approved_hash ~ '^[0-9a-f]{64}$'),
    risk             text        NOT NULL CHECK (risk IN ('low', 'medium', 'high', 'critical')),
    rule             text        NOT NULL CHECK (char_length(rule) BETWEEN 1 AND 128),
    message          text        NOT NULL DEFAULT '' CHECK (char_length(message) <= 500),
    severity         text        NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    -- Хеш аргументов, которые шлюз передаст дальше после одобрения.
    args_hash        text        NOT NULL CHECK (args_hash ~ '^[0-9a-f]{64}$'),
    args             bytea       CHECK (octet_length(args) BETWEEN 16 AND 17408),
    args_key_id      uuid        REFERENCES data_keys (id),
    args_alg         text        CHECK (char_length(args_alg) BETWEEN 1 AND 32),
    request_event_id uuid,
    state            text        NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'timeout', 'cancelled', 'interrupted')),
    created_at       timestamptz NOT NULL,
    deadline         timestamptz NOT NULL CHECK (deadline > created_at AND deadline <= created_at + interval '60 minutes'),
    closed_at        timestamptz,
    -- Пользователь консоли (approved, denied).
    decided_by       uuid,
    decided_by_name  text        NOT NULL DEFAULT '' CHECK (char_length(decided_by_name) <= 256),
    comment          text        NOT NULL DEFAULT '' CHECK (char_length(comment) <= 500),
    CHECK ((state = 'pending') = (closed_at IS NULL)),
    CHECK ((state IN ('approved', 'denied')) = (decided_by IS NOT NULL)),
    CHECK ((args IS NULL) = (args_key_id IS NULL) AND (args IS NULL) = (args_alg IS NULL)),
    -- Аргументы удаляются только у закрытого запроса.
    CHECK (args IS NOT NULL OR state <> 'pending'),
    CHECK (path = 'mcp' AND agent <> '' OR path = 'chat' AND server = 'function')
);

-- Ожидающие запросы шлюза: пределы очереди и сверка с heartbeat.
CREATE INDEX approval_requests_pending ON approval_requests (gateway_id, app, agent) WHERE state = 'pending';
CREATE INDEX approval_requests_deadline ON approval_requests (deadline) WHERE state = 'pending';
-- Список в консоли, новые первыми.
CREATE INDEX approval_requests_created ON approval_requests (org_id, created_at DESC, id DESC);
CREATE INDEX approval_requests_closed ON approval_requests (closed_at) WHERE closed_at IS NOT NULL;
CREATE INDEX approval_requests_args_key ON approval_requests (args_key_id) WHERE args_key_id IS NOT NULL;

-- Закрытый запрос неизменен: решение, срок и аргументы не переписываются
-- (кроме удаления аргументов по сроку и перешифрования при ротации ключа).
CREATE FUNCTION approval_requests_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF OLD.state <> 'pending' THEN
        IF (NEW.state, NEW.closed_at, NEW.decided_by, NEW.decided_by_name, NEW.comment, NEW.args_hash, NEW.deadline)
           IS DISTINCT FROM
           (OLD.state, OLD.closed_at, OLD.decided_by, OLD.decided_by_name, OLD.comment, OLD.args_hash, OLD.deadline) THEN
            RAISE EXCEPTION 'approval_requests: закрытый запрос не меняется';
        END IF;
        IF NEW.args IS NOT NULL AND OLD.args IS NULL THEN
            RAISE EXCEPTION 'approval_requests: удалённые аргументы не возвращаются';
        END IF;
    END IF;
    IF (NEW.id, NEW.org_id, NEW.gateway_id, NEW.path, NEW.app, NEW.agent, NEW.user_alias, NEW.session, NEW.server, NEW.tool,
        NEW.approved_hash, NEW.risk, NEW.rule, NEW.message, NEW.severity, NEW.args_hash, NEW.request_event_id, NEW.created_at,
        NEW.deadline)
       IS DISTINCT FROM
       (OLD.id, OLD.org_id, OLD.gateway_id, OLD.path, OLD.app, OLD.agent, OLD.user_alias, OLD.session, OLD.server, OLD.tool,
        OLD.approved_hash, OLD.risk, OLD.rule, OLD.message, OLD.severity, OLD.args_hash, OLD.request_event_id, OLD.created_at,
        OLD.deadline) THEN
        RAISE EXCEPTION 'approval_requests: поля запроса не меняются';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER approval_requests_guard BEFORE UPDATE ON approval_requests
    FOR EACH ROW EXECUTE FUNCTION approval_requests_guard();

REVOKE ALL ON approval_requests FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON approval_requests TO aisec_app;
GRANT UPDATE (state, closed_at, decided_by, decided_by_name, comment, args, args_key_id, args_alg) ON approval_requests TO aisec_app;
