-- Ответы, выданные в сессиях чата, для history.integrity (ТЗ 5.16 DM-03;
-- задача 4.14 этапа 4). Сервер при приёме событий сверяет реплики
-- ассистента из истории запроса с ответами, которые шлюз выдал в этой
-- сессии раньше. Хранятся только хеши: псевдоним сессии и HMAC
-- нормализованного текста ответа на ключе шлюза, без самого текста.
-- Строки старше 7 суток сервер удаляет при приёме не чаще раза в час:
-- реплику из истории старше срока он принимает за известную только в
-- новой (впервые увиденной) сессии.

-- Сессии, в которых сервер уже видел ход с правилом history.integrity:
-- в первом ходе реплики истории принимаются как известные (сессия могла
-- начаться до включения правила или до перезапуска шлюза).
CREATE TABLE session_history (
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    app        text        NOT NULL CHECK (app ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    session    text        NOT NULL CHECK (session ~ '^[0-9a-f]{32}$'),
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    PRIMARY KEY (org_id, app, session)
);

CREATE INDEX session_history_last_seen ON session_history (last_seen);

CREATE TABLE session_replies (
    org_id    uuid        NOT NULL,
    app       text        NOT NULL,
    session   text        NOT NULL,
    hash      text        NOT NULL CHECK (hash ~ '^[0-9a-f]{32}$'),
    -- issued — ответ выдан шлюзом; history — реплика из истории первого
    -- хода, принятая как известная.
    source    text        NOT NULL CHECK (source IN ('issued', 'history')),
    seen_at   timestamptz NOT NULL,
    PRIMARY KEY (org_id, app, session, hash),
    FOREIGN KEY (org_id, app, session) REFERENCES session_history (org_id, app, session) ON DELETE CASCADE
);

CREATE INDEX session_replies_seen ON session_replies (seen_at);

REVOKE ALL ON session_history, session_replies FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON session_history, session_replies TO aisec_app;
GRANT UPDATE (last_seen) ON session_history TO aisec_app;
GRANT UPDATE (seen_at) ON session_replies TO aisec_app;
