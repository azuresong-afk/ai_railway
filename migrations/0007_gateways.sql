-- Шлюзы и их регистрация (ТЗ 7.2 ИАФ.10, 11.1; решение Р8 этапа 2;
-- задача 2.14, ADR-0009). Шлюз получает клиентский сертификат внутреннего УЦ
-- по одноразовому токену регистрации; сервер при каждом запросе сверяет
-- серийный номер сертификата с действующей строкой gateways, поэтому отзыв
-- и перерегистрация действуют сразу, без списков отзыва.

CREATE TABLE gateways (
    id             uuid        PRIMARY KEY,
    org_id         uuid        NOT NULL REFERENCES organizations (id),
    name           text        NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    -- pending — токен выпущен, сертификата ещё нет; revoked — окончательно.
    status         text        NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    created_at     timestamptz NOT NULL,
    created_by     text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    registered_at  timestamptz,
    revoked_at     timestamptz,
    -- Действующий сертификат: серийный номер в шестнадцатеричном виде.
    cert_serial    text        UNIQUE CHECK (cert_serial ~ '^[0-9a-f]{1,40}$'),
    cert_not_after timestamptz,
    -- Последний контакт (heartbeat): время, адрес, версия шлюза и пакета.
    last_seen_at   timestamptz,
    last_addr      inet,
    version        text        CHECK (char_length(version) BETWEEN 1 AND 64),
    bundle_etag    text        CHECK (char_length(bundle_etag) BETWEEN 1 AND 128),
    UNIQUE (org_id, name),
    CHECK (status <> 'pending' OR (registered_at IS NULL AND cert_serial IS NULL)),
    CHECK (status <> 'active' OR (registered_at IS NOT NULL AND cert_serial IS NOT NULL AND cert_not_after IS NOT NULL)),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

-- Токен регистрации: хранится только хеш профиля, сам токен показывается
-- один раз (как setup_tokens, ADR-0007). Выпускает aisec-cli, гасит сервер.
CREATE TABLE gateway_tokens (
    id         uuid        PRIMARY KEY,
    gateway_id uuid        NOT NULL REFERENCES gateways (id),
    hash_alg   text        NOT NULL CHECK (char_length(hash_alg) BETWEEN 1 AND 32),
    token_hash bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) BETWEEN 16 AND 64),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    used_at    timestamptz CHECK (used_at IS NULL OR used_at >= created_at)
);

CREATE INDEX gateway_tokens_gateway ON gateway_tokens (gateway_id) WHERE used_at IS NULL;

-- Права на столбцы не ограничивают значения: триггеры не дают никому,
-- включая владельца, вернуть отозванный шлюз, переименовать шлюз или
-- повторно использовать погашенный токен.
CREATE FUNCTION gateways_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF OLD.status = 'revoked' THEN
        RAISE EXCEPTION 'gateways: отозванный шлюз не меняется'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id <> OLD.id OR NEW.org_id <> OLD.org_id OR NEW.name <> OLD.name
        OR NEW.created_at <> OLD.created_at OR NEW.created_by <> OLD.created_by THEN
        RAISE EXCEPTION 'gateways: ID, организация, имя и создание не меняются'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'active' AND NEW.status = 'pending' THEN
        RAISE EXCEPTION 'gateways: зарегистрированный шлюз не возвращается в pending'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER gateways_guard BEFORE UPDATE ON gateways
    FOR EACH ROW EXECUTE FUNCTION gateways_guard();

CREATE FUNCTION gateway_tokens_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF OLD.used_at IS NOT NULL OR NEW.used_at IS NULL THEN
        RAISE EXCEPTION 'gateway_tokens: токен гасится один раз'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id <> OLD.id OR NEW.gateway_id <> OLD.gateway_id OR NEW.hash_alg <> OLD.hash_alg
        OR NEW.token_hash <> OLD.token_hash OR NEW.created_at <> OLD.created_at
        OR NEW.expires_at <> OLD.expires_at THEN
        RAISE EXCEPTION 'gateway_tokens: меняется только отметка о погашении'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER gateway_tokens_guard BEFORE UPDATE ON gateway_tokens
    FOR EACH ROW EXECUTE FUNCTION gateway_tokens_guard();

-- Строки не удаляются никем: ссылки в журнале аудита остаются действительными.
CREATE FUNCTION gateways_no_delete() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    RAISE EXCEPTION '%: % запрещено (шлюзы отзываются, а не удаляются)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER gateways_no_delete BEFORE DELETE ON gateways
    FOR EACH ROW EXECUTE FUNCTION gateways_no_delete();
CREATE TRIGGER gateways_no_truncate BEFORE TRUNCATE ON gateways
    FOR EACH STATEMENT EXECUTE FUNCTION gateways_no_delete();
CREATE TRIGGER gateway_tokens_no_delete BEFORE DELETE ON gateway_tokens
    FOR EACH ROW EXECUTE FUNCTION gateways_no_delete();
CREATE TRIGGER gateway_tokens_no_truncate BEFORE TRUNCATE ON gateway_tokens
    FOR EACH STATEMENT EXECUTE FUNCTION gateways_no_delete();

-- Права: сервер гасит токен, регистрирует шлюз и отмечает контакт; шлюзы,
-- токены и отзыв создаёт aisec-cli под логином владельца схемы (до задачи
-- 2.9 — только так).
REVOKE ALL ON gateways, gateway_tokens FROM PUBLIC;
GRANT SELECT ON gateways, gateway_tokens TO aisec_app;
GRANT UPDATE (status, registered_at, cert_serial, cert_not_after, last_seen_at, last_addr, version, bundle_etag)
    ON gateways TO aisec_app;
GRANT UPDATE (used_at) ON gateway_tokens TO aisec_app;
