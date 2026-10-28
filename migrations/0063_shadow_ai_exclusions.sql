-- Теневой ИИ: исключения и счётчик исключённых строк импорта (задача 4.23
-- этапа 4, ADR-0027, дополнение 1).
--
-- Исключение — пользователь или сервис, которые не учитываются в сводках и
-- оповещениях: например, учётная запись самого шлюза, которая ходит к
-- провайдерам (ADR-0027, «Последствия»). Пользователь хранится только
-- псевдонимом (HMAC на ключе псевдонимов, как в сводках): логин, введённый
-- администратором, в БД не попадает. Сервис — ID сервиса каталога.

CREATE TABLE shadow_ai_exclusions (
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    kind       text        NOT NULL CHECK (kind IN ('user', 'service')),
    value      text        NOT NULL,
    comment    text        NOT NULL DEFAULT '' CHECK (char_length(comment) <= 200),
    created_at timestamptz NOT NULL,
    created_by text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    PRIMARY KEY (org_id, kind, value),
    CHECK ((kind = 'user' AND value ~ '^[0-9a-f]{32}$') OR (kind = 'service' AND value ~ '^[a-z0-9][a-z0-9-]{0,63}$'))
);

-- Строки импорта, отброшенные исключениями.
ALTER TABLE shadow_ai_imports
    ADD COLUMN excluded bigint NOT NULL DEFAULT 0 CHECK (excluded >= 0);

-- Поиск сводок пользователя при добавлении исключения.
CREATE INDEX shadow_ai_hour_user ON shadow_ai_hour (org_id, user_alias) WHERE user_alias <> '';

REVOKE ALL ON shadow_ai_exclusions FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON shadow_ai_exclusions TO aisec_app;
