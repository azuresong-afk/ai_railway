-- Ключи установки (ТЗ 7.9 ЗИ.1, ЗИ.4, 10.4; решение Р4 этапа 2; ADR-0007).
-- Создаёт aisec-cli init; мастер-ключ, ключ подписи пакетов и внутренний УЦ
-- лежат в файлах, в БД — только то, что без мастер-ключа бесполезно.

-- Ключ данных: шифрует секреты (ЗИ.1). Хранится зашифрованным мастер-ключом
-- (AES-256-GCM, AAD — таблица, столбец и id строки). version — задел под
-- ротацию: действующий ключ один, прежние помечаются retired_at и остаются,
-- пока ими зашифровано хоть что-то. sealed — число шифрований этим ключом:
-- у AES-GCM со случайным nonce предел 2^32 сообщений на ключ (ADR-0006), рабочий
-- предел — 2^31; потребители резервируют шифрования увеличением счётчика
-- до самого шифрования (ADR-0007).
CREATE TABLE data_keys (
    id         uuid        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    version    integer     NOT NULL CHECK (version > 0),
    profile    text        NOT NULL CHECK (profile IN ('standard', 'gost')),
    alg        text        NOT NULL CHECK (char_length(alg) BETWEEN 1 AND 32),
    wrapped    bytea       NOT NULL CHECK (octet_length(wrapped) BETWEEN 16 AND 256),
    sealed     bigint      NOT NULL DEFAULT 0 CHECK (sealed BETWEEN 0 AND 2147483648),
    created_at timestamptz NOT NULL,
    retired_at timestamptz,
    UNIQUE (org_id, version)
);

-- Не больше одного действующего ключа данных на организацию: два
-- одновременных init не создадут два ключа.
CREATE UNIQUE INDEX data_keys_active ON data_keys (org_id) WHERE retired_at IS NULL;

-- Одноразовый токен первичной настройки (ЗИ.4): хранится только хеш, сам
-- токен показывается один раз. Гасит его сервер (задача 2.7), отмечая used_at.
CREATE TABLE setup_tokens (
    id         uuid        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    hash_alg   text        NOT NULL CHECK (char_length(hash_alg) BETWEEN 1 AND 32),
    token_hash bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) BETWEEN 16 AND 64),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    used_at    timestamptz CHECK (used_at IS NULL OR used_at >= created_at)
);

-- Права на столбцы не ограничивают значения: роль сервера могла бы сбросить
-- счётчик шифрований и обойти предел или снять отметку о погашении и
-- использовать токен снова. Триггеры запрещают это всем, включая владельца.
CREATE FUNCTION data_keys_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF NEW.sealed < OLD.sealed THEN
        RAISE EXCEPTION 'data_keys: счётчик шифрований не уменьшается'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id <> OLD.id OR NEW.org_id <> OLD.org_id OR NEW.version <> OLD.version
        OR NEW.profile <> OLD.profile OR NEW.alg <> OLD.alg OR NEW.wrapped <> OLD.wrapped
        OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'data_keys: ключ не меняется, ротация — новой версией'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
        RAISE EXCEPTION 'data_keys: выведенный ключ не возвращается'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER data_keys_guard BEFORE UPDATE ON data_keys
    FOR EACH ROW EXECUTE FUNCTION data_keys_guard();

CREATE FUNCTION setup_tokens_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF OLD.used_at IS NOT NULL OR NEW.used_at IS NULL THEN
        RAISE EXCEPTION 'setup_tokens: токен гасится один раз'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id <> OLD.id OR NEW.org_id <> OLD.org_id OR NEW.hash_alg <> OLD.hash_alg
        OR NEW.token_hash <> OLD.token_hash OR NEW.created_at <> OLD.created_at
        OR NEW.expires_at <> OLD.expires_at THEN
        RAISE EXCEPTION 'setup_tokens: меняется только отметка о погашении'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER setup_tokens_guard BEFORE UPDATE ON setup_tokens
    FOR EACH ROW EXECUTE FUNCTION setup_tokens_guard();

-- Права: сервер читает ключ данных, резервирует шифрования и гасит токен;
-- ключи и токены создаёт только aisec-cli init под логином владельца схемы.
REVOKE ALL ON data_keys, setup_tokens FROM PUBLIC;
GRANT SELECT, UPDATE (sealed) ON data_keys TO aisec_app;
GRANT SELECT, UPDATE (used_at) ON setup_tokens TO aisec_app;
