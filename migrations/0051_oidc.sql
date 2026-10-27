-- Вход в консоль через внешний IdP по OpenID Connect (ТЗ 5.14, 7.2 ИАФ.7;
-- ADR-0025, задача 4.17 этапа 4).
--
-- Внешний пользователь привязан к паре «издатель, sub», а не к логину:
-- локальную запись нельзя захватить, заведя в IdP пользователя с тем же
-- именем. Пароля у него нет — в password_hash заглушка '!external', которую
-- не принимает ни один разборщик PHC; столбцы источника приложению не
-- меняются (нет UPDATE), поэтому внешняя запись не становится локальной.

ALTER TABLE users
    ADD COLUMN auth_source text NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'oidc')),
    ADD COLUMN idp_issuer  text CHECK (char_length(idp_issuer) BETWEEN 1 AND 512),
    ADD COLUMN idp_subject text CHECK (char_length(idp_subject) BETWEEN 1 AND 255),
    ADD CONSTRAINT users_idp_identity CHECK ((auth_source = 'local') = (idp_issuer IS NULL)
        AND (idp_issuer IS NULL) = (idp_subject IS NULL)),
    ADD CONSTRAINT users_external_password CHECK ((auth_source = 'local') = (password_hash <> '!external'));

CREATE UNIQUE INDEX users_idp_identity_key ON users (org_id, idp_issuer, idp_subject) WHERE idp_subject IS NOT NULL;

-- Сессии внешних пользователей завершаются при изменении настроек IdP
-- (роли пересчитываются при следующем входе) и при смене роли по группам.
ALTER TABLE sessions DROP CONSTRAINT sessions_revoke_reason_check,
    ADD CONSTRAINT sessions_revoke_reason_check CHECK (revoke_reason IN ('logout', 'idle', 'expired', 'limit', 'admin',
        'password_changed', 'password_reset', 'deactivated', 'locked', 'mfa_reset', 'mfa_passed', 'mfa_required',
        'backup_restore', 'idp_changed', 'idp_role_changed'));

-- Настройки IdP: одна строка на организацию (один IdP на установку,
-- ADR-0025, 3.1). Секрет клиента — под ключом данных
-- (AAD oidc_settings|client_secret|<org_id>), перешифровывается при
-- ротации ключа данных (ADR-0018).
CREATE TABLE oidc_settings (
    org_id               uuid        PRIMARY KEY REFERENCES organizations (id),
    enabled              boolean     NOT NULL,
    display_name         text        NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
    issuer               text        NOT NULL CHECK (issuer ~ '^https://' AND char_length(issuer) <= 512),
    client_id            text        NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 256),
    client_secret        bytea       NOT NULL CHECK (octet_length(client_secret) BETWEEN 1 AND 4096),
    client_secret_key_id uuid        NOT NULL REFERENCES data_keys (id),
    console_url          text        NOT NULL CHECK (console_url ~ '^https://' AND char_length(console_url) <= 512),
    ca_pem               text        NOT NULL CHECK (char_length(ca_pem) BETWEEN 1 AND 65536),
    scopes               text[]      NOT NULL CHECK (cardinality(scopes) <= 16),
    groups_claim         text        NOT NULL CHECK (char_length(groups_claim) BETWEEN 1 AND 64),
    required_acr         text[]      NOT NULL CHECK (cardinality(required_acr) <= 16),
    required_amr         text[]      NOT NULL CHECK (cardinality(required_amr) <= 16),
    version              integer     NOT NULL CHECK (version >= 1),
    updated_at           timestamptz NOT NULL,
    updated_by           uuid        NOT NULL REFERENCES users (id)
);

CREATE INDEX oidc_settings_key ON oidc_settings (client_secret_key_id);

-- Сопоставление групп IdP с ролями: явная таблица (ADR-0025, 1.4). Роль
-- нельзя удалить, пока на неё ссылается группа.
CREATE TABLE oidc_group_roles (
    org_id     uuid NOT NULL REFERENCES oidc_settings (org_id) ON DELETE CASCADE,
    group_name text NOT NULL CHECK (char_length(group_name) BETWEEN 1 AND 256),
    role       text NOT NULL,
    PRIMARY KEY (org_id, group_name),
    FOREIGN KEY (org_id, role) REFERENCES roles (org_id, id)
);

-- Незавершённые входы: только хеш одноразового значения из cookie
-- браузера и срок. state, nonce и code_verifier выводятся из этого
-- значения и в БД не хранятся (ADR-0025, 3.3).
CREATE TABLE oidc_logins (
    id_hash    bytea       PRIMARY KEY CHECK (octet_length(id_hash) BETWEEN 16 AND 64),
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);

CREATE INDEX oidc_logins_expires ON oidc_logins (org_id, expires_at);

REVOKE ALL ON oidc_settings, oidc_group_roles, oidc_logins FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON oidc_settings, oidc_group_roles, oidc_logins TO aisec_app;
GRANT UPDATE (enabled, display_name, issuer, client_id, client_secret, client_secret_key_id, console_url, ca_pem,
    scopes, groups_claim, required_acr, required_amr, version, updated_at, updated_by) ON oidc_settings TO aisec_app;
