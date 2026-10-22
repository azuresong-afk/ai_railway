-- Инциденты (ТЗ 5.7, 1.4 S4 и S8; задача 3.16 этапа 3; ADR-0020, п. 4–5).
--
-- Инцидент создаётся из оповещения (кнопка в консоли или API) или
-- автоматически — по оповещению встроенного правила с признаком «инцидент»
-- (канарейка в ответе, DM-08) в транзакции приёма событий. Содержимое
-- запросов и ответов сюда не копируется: только ссылки на события (ID и
-- ключ секции). Хронология, комментарии, ссылки и версии инструкций только
-- добавляются; закрытый инцидент не меняется (повторное открытие — новый
-- инцидент со ссылкой на прежний).

-- Сквозной номер инцидента в организации: строка блокируется до конца
-- транзакции создания, поэтому номера идут без пропусков и повторов.
CREATE TABLE incident_counters (
    org_id      uuid   PRIMARY KEY REFERENCES organizations (id),
    last_number bigint NOT NULL CHECK (last_number >= 1)
);

CREATE TABLE incidents (
    id                 uuid        PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES organizations (id),
    number             bigint      NOT NULL CHECK (number >= 1),
    title              text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 300),
    severity           text        NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    -- Категория — справочник в коде (internal/incidents, ТЗ 5.7).
    category           text        NOT NULL CHECK (category ~ '^[a-z][a-z_]{1,39}$'),
    status             text        NOT NULL CHECK (status IN ('new', 'in_progress', 'contained', 'closed')),
    resolution         text        CHECK (resolution IN ('resolved', 'false_positive', 'risk_accepted')),
    resolution_comment text        NOT NULL DEFAULT '' CHECK (char_length(resolution_comment) <= 2000),
    -- manual — вручную, alert — из оповещения, auto — правилом в приёме событий, reopen — повторное открытие.
    source             text        NOT NULL CHECK (source IN ('manual', 'alert', 'auto', 'reopen')),
    reopened_from      uuid        REFERENCES incidents (id),
    assignee_id        uuid,
    -- Срок реакции: создание плюс норматив по серьёзности; reacted_at —
    -- первый уход из статуса «новый».
    reaction_due_at    timestamptz NOT NULL,
    reacted_at         timestamptz,
    contained_at       timestamptz,
    created_at         timestamptz NOT NULL,
    created_by         text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at         timestamptz NOT NULL,
    updated_by         text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    closed_at          timestamptz,
    closed_by          text        CHECK (char_length(closed_by) BETWEEN 1 AND 128),
    version            integer     NOT NULL CHECK (version >= 1),
    UNIQUE (org_id, number),
    CHECK ((status = 'closed') = (resolution IS NOT NULL)),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK ((closed_at IS NULL) = (closed_by IS NULL)),
    CHECK ((source = 'reopen') = (reopened_from IS NOT NULL)),
    CHECK (status = 'new' OR reacted_at IS NOT NULL)
);

CREATE INDEX incidents_org_created ON incidents (org_id, created_at DESC, id DESC);
CREATE INDEX incidents_org_status ON incidents (org_id, status, created_at DESC);
-- Закрытый инцидент открывается заново не больше одного раза.
CREATE UNIQUE INDEX incidents_reopened_from ON incidents (reopened_from) WHERE reopened_from IS NOT NULL;

-- Закрытый инцидент не меняется (ТЗ 5.7): защита на уровне СУБД, кроме
-- проверки в коде сервера.
CREATE FUNCTION incidents_closed_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'закрытый инцидент не меняется' USING ERRCODE = 'check_violation';
END;
$$;
CREATE TRIGGER incidents_closed_immutable BEFORE UPDATE ON incidents
    FOR EACH ROW WHEN (OLD.status = 'closed') EXECUTE FUNCTION incidents_closed_immutable();

-- Этапы реагирования по шаблону ТЗ 5.7; отмеченный этап не снимается.
CREATE TABLE incident_stages (
    incident_id uuid        NOT NULL REFERENCES incidents (id),
    key         text        NOT NULL CHECK (key ~ '^[a-z][a-z_]{1,31}$'),
    position    smallint    NOT NULL CHECK (position BETWEEN 1 AND 20),
    done_at     timestamptz,
    done_by     text        CHECK (char_length(done_by) BETWEEN 1 AND 128),
    note        text        NOT NULL DEFAULT '' CHECK (char_length(note) <= 2000),
    PRIMARY KEY (incident_id, key),
    CHECK ((done_at IS NULL) = (done_by IS NULL))
);

CREATE FUNCTION incident_stages_done_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'отмеченный этап не меняется' USING ERRCODE = 'check_violation';
END;
$$;
CREATE TRIGGER incident_stages_done_immutable BEFORE UPDATE ON incident_stages
    FOR EACH ROW WHEN (OLD.done_at IS NOT NULL) EXECUTE FUNCTION incident_stages_done_immutable();

-- Ссылки на события: ID и ключ секции (время из UUIDv7) для перехода к событию.
CREATE TABLE incident_events (
    incident_id uuid        NOT NULL REFERENCES incidents (id),
    event_id    uuid        NOT NULL,
    event_ts    timestamptz NOT NULL,
    added_at    timestamptz NOT NULL,
    PRIMARY KEY (incident_id, event_id)
);

-- Хронология: автоматические и ручные записи, только добавление.
CREATE TABLE incident_timeline (
    id          uuid        PRIMARY KEY,
    incident_id uuid        NOT NULL REFERENCES incidents (id),
    at          timestamptz NOT NULL,
    actor       text        NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 128),
    kind        text        NOT NULL CHECK (kind ~ '^[a-z][a-z_]{1,39}$'),
    details     jsonb       NOT NULL CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 16384)
);

CREATE INDEX incident_timeline_incident ON incident_timeline (incident_id, at, id);

-- Комментарии: только добавление; правка — новая запись со ссылкой на прежнюю.
CREATE TABLE incident_comments (
    id          uuid        PRIMARY KEY,
    incident_id uuid        NOT NULL REFERENCES incidents (id),
    at          timestamptz NOT NULL,
    author      text        NOT NULL CHECK (char_length(author) BETWEEN 1 AND 128),
    author_name text        NOT NULL CHECK (char_length(author_name) BETWEEN 1 AND 128),
    body        text        NOT NULL CHECK (char_length(body) BETWEEN 1 AND 4000),
    replaces    uuid        REFERENCES incident_comments (id)
);

CREATE INDEX incident_comments_incident ON incident_comments (incident_id, at, id);
-- Правка комментария — не больше одной следующей версии на запись.
CREATE UNIQUE INDEX incident_comments_replaces ON incident_comments (replaces) WHERE replaces IS NOT NULL;

-- Инструкции реагирования по категориям: каждая правка — новая версия,
-- прежние версии хранятся (значение «до» для журнала аудита). Нет строки —
-- действует текст по умолчанию из кода.
CREATE TABLE incident_instructions (
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    category   text        NOT NULL CHECK (category ~ '^[a-z][a-z_]{1,39}$'),
    version    integer     NOT NULL CHECK (version >= 2),
    body       text        NOT NULL CHECK (char_length(body) <= 8000),
    created_at timestamptz NOT NULL,
    created_by text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    PRIMARY KEY (org_id, category, version)
);

-- Закрытый инцидент не дополняется и прямым запросом: хронология,
-- комментарии, ссылки на события и этапы. Исключение — запись «открыт
-- заново» в хронологии закрытого инцидента.
CREATE FUNCTION incident_child_of_closed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'incident_timeline' THEN
        IF NEW.kind = 'reopened' THEN
            RETURN NEW;
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM incidents WHERE id = NEW.incident_id AND status = 'closed') THEN
        RAISE EXCEPTION 'закрытый инцидент не дополняется' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER incident_timeline_closed BEFORE INSERT ON incident_timeline
    FOR EACH ROW EXECUTE FUNCTION incident_child_of_closed();
CREATE TRIGGER incident_comments_closed BEFORE INSERT ON incident_comments
    FOR EACH ROW EXECUTE FUNCTION incident_child_of_closed();
CREATE TRIGGER incident_events_closed BEFORE INSERT ON incident_events
    FOR EACH ROW EXECUTE FUNCTION incident_child_of_closed();
CREATE TRIGGER incident_stages_closed BEFORE INSERT OR UPDATE ON incident_stages
    FOR EACH ROW EXECUTE FUNCTION incident_child_of_closed();

-- Связь оповещения с инцидентом (ADR-0020, п. 4): внешний ключ, обещанный
-- миграцией 0028.
ALTER TABLE alerts ADD CONSTRAINT alerts_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES incidents (id);
CREATE INDEX alerts_incident ON alerts (incident_id) WHERE incident_id IS NOT NULL;

-- Права роли сервера: ничего не удаляется; у инцидента меняются только
-- изменяемые столбцы, у этапа — отметка о выполнении; хронология,
-- комментарии, ссылки и версии инструкций только добавляются.
REVOKE ALL ON incident_counters, incidents, incident_stages, incident_events, incident_timeline, incident_comments,
    incident_instructions FROM PUBLIC;
GRANT SELECT, INSERT ON incident_counters, incidents, incident_stages, incident_events, incident_timeline,
    incident_comments, incident_instructions TO aisec_app;
GRANT UPDATE (last_number) ON incident_counters TO aisec_app;
GRANT UPDATE (status, resolution, resolution_comment, assignee_id, reacted_at, contained_at, updated_at, updated_by,
    closed_at, closed_by, version) ON incidents TO aisec_app;
GRANT UPDATE (done_at, done_by, note) ON incident_stages TO aisec_app;
