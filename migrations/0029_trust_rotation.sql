-- Ротация ключа подписи пакетов, ключа аудита и корня внутреннего УЦ
-- (задача 3.3 этапа 3; ADR-0018, п. 4–7). Ключ данных и мастер-ключ —
-- миграция 0027_key_rotation.

-- Заявления о доверии aisec-trust/1 (ADR-0018, п. 4): подписанный список
-- ключей подписи пакетов и корней УЦ. statement — подписанное заявление как
-- есть: его проверяет internal/policy/bundle по цепочке от файла-якоря,
-- таблица только хранит. Пишет aisec-cli keys под логином владельца схемы.
CREATE TABLE trust_statements (
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    seq        bigint      NOT NULL CHECK (seq > 0),
    statement  bytea       NOT NULL CHECK (octet_length(statement) BETWEEN 1 AND 16384),
    signed_by  text        NOT NULL CHECK (signed_by ~ '^[0-9a-f]{16}$'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    created_by text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    PRIMARY KEY (org_id, seq)
);

-- Смены ключа подписи контрольных точек аудита (ADR-0018, п. 5): точки с
-- номером до checkpoint_seq включительно подписаны прежним ключом, следующие
-- — новым. Две подписи: прежним ключом (передача доверия) и новым
-- (владение ключом); их проверяет internal/audit.
CREATE TABLE audit_key_rotations (
    org_id         uuid        NOT NULL REFERENCES organizations (id),
    seq            integer     NOT NULL CHECK (seq > 0),
    prev_key_id    text        NOT NULL CHECK (prev_key_id ~ '^[0-9a-f]{16}$'),
    key_id         text        NOT NULL CHECK (key_id ~ '^[0-9a-f]{16}$' AND key_id <> prev_key_id),
    public_key     bytea       NOT NULL CHECK (octet_length(public_key) BETWEEN 16 AND 256),
    checkpoint_seq bigint      NOT NULL CHECK (checkpoint_seq >= 0),
    rotated_at     timestamptz NOT NULL CHECK (isfinite(rotated_at)),
    sig_alg        text        NOT NULL CHECK (char_length(sig_alg) BETWEEN 1 AND 32),
    prev_signature bytea       NOT NULL CHECK (octet_length(prev_signature) BETWEEN 32 AND 256),
    signature      bytea       NOT NULL CHECK (octet_length(signature) BETWEEN 32 AND 256),
    PRIMARY KEY (org_id, seq)
);

-- Обе таблицы только добавляются: подмена записи меняла бы доверие задним
-- числом. Функция audit_append_only — из 0002_audit.
CREATE TRIGGER trust_statements_no_update BEFORE UPDATE ON trust_statements
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER trust_statements_no_delete BEFORE DELETE ON trust_statements
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER trust_statements_no_truncate BEFORE TRUNCATE ON trust_statements
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_key_rotations_no_update BEFORE UPDATE ON audit_key_rotations
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_key_rotations_no_delete BEFORE DELETE ON audit_key_rotations
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_key_rotations_no_truncate BEFORE TRUNCATE ON audit_key_rotations
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();

-- Шлюзы (ADR-0018, п. 6–7): корень УЦ действующего сертификата, следующий
-- сертификат после перевыпуска (до первого запроса с ним) и закреплённый
-- ключ получателя HPKE (Н27). NULL в cert_ca — корень из -ca-cert
-- (сертификат выпущен до ротаций).
ALTER TABLE gateways
    ADD COLUMN cert_ca             text CHECK (cert_ca ~ '^[0-9a-f]{16}$'),
    ADD COLUMN next_cert_serial    text CHECK (char_length(next_cert_serial) BETWEEN 1 AND 64),
    ADD COLUMN next_cert_not_after timestamptz CHECK (isfinite(next_cert_not_after)),
    ADD COLUMN next_cert_ca        text CHECK (next_cert_ca ~ '^[0-9a-f]{16}$'),
    ADD COLUMN bundle_key          bytea CHECK (octet_length(bundle_key) = 32),
    ADD CONSTRAINT gateways_next_cert CHECK ((next_cert_serial IS NULL) = (next_cert_not_after IS NULL)
        AND (next_cert_serial IS NULL) = (next_cert_ca IS NULL));

CREATE UNIQUE INDEX gateways_next_cert_serial ON gateways (next_cert_serial) WHERE next_cert_serial IS NOT NULL;

-- Закреплённый ключ получателя не меняется на другой: только с NULL или
-- вместе с новой регистрацией шлюза (registered_at меняется).
CREATE FUNCTION gateways_bundle_key_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.bundle_key IS NOT NULL AND NEW.bundle_key IS DISTINCT FROM OLD.bundle_key
        AND NEW.registered_at IS NOT DISTINCT FROM OLD.registered_at THEN
        RAISE EXCEPTION 'gateways: закреплённый ключ получателя меняется только перерегистрацией'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER gateways_bundle_key_guard BEFORE UPDATE ON gateways
    FOR EACH ROW EXECUTE FUNCTION gateways_bundle_key_guard();

-- Права: сервер читает доверие и перевыпускает сертификаты; заявления и
-- смены ключа аудита пишет только aisec-cli под логином владельца схемы.
-- Архивация (SET ROLE aisec_audit_archiver) подписывает точки ключом
-- последней смены.
REVOKE ALL ON trust_statements, audit_key_rotations FROM PUBLIC;
GRANT SELECT ON trust_statements, audit_key_rotations TO aisec_app;
GRANT SELECT ON audit_key_rotations TO aisec_audit_archiver;
GRANT UPDATE (cert_ca, next_cert_serial, next_cert_not_after, next_cert_ca, bundle_key) ON gateways TO aisec_app;
