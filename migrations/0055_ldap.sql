-- Вход в консоль по учётной записи каталога LDAP (ТЗ 5.14, 7.2 ИАФ.7;
-- ADR-0025, раздел 2; задача 4.16 этапа 4).
--
-- Пользователь каталога — внешняя запись, как у OIDC (миграция 0051):
-- привязан к паре («ldap», неизменяемый идентификатор записи — entryUUID,
-- ipaUniqueID, nsUniqueId или objectGUID), пароля консоли у него нет
-- (заглушка '!external'). Пароль проверяет каталог; второй фактор — свой
-- TOTP консоли (ADR-0025, 2.5).

ALTER TABLE users DROP CONSTRAINT users_auth_source_check,
    ADD CONSTRAINT users_auth_source_check CHECK (auth_source IN ('local', 'oidc', 'ldap'));

-- Сессии пользователей каталога завершаются при изменении настроек LDAP
-- (роли пересчитываются при следующем входе).
ALTER TABLE sessions DROP CONSTRAINT sessions_revoke_reason_check,
    ADD CONSTRAINT sessions_revoke_reason_check CHECK (revoke_reason IN ('logout', 'idle', 'expired', 'limit', 'admin',
        'password_changed', 'password_reset', 'deactivated', 'locked', 'mfa_reset', 'mfa_passed', 'mfa_required',
        'backup_restore', 'idp_changed', 'idp_role_changed', 'ldap_changed'));

-- Настройки каталога: одна строка на организацию (один каталог на
-- установку). Пароль сервисной учётной записи — под ключом данных
-- (AAD ldap_settings|bind_password|<org_id>), перешифровывается при
-- ротации ключа данных (ADR-0018). Адрес — только ldaps:// или ldap://
-- (тогда StartTLS обязателен): соединения без TLS нет.
CREATE TABLE ldap_settings (
    org_id                uuid        PRIMARY KEY REFERENCES organizations (id),
    enabled               boolean     NOT NULL,
    url                   text        NOT NULL CHECK (url ~ '^ldaps?://' AND char_length(url) <= 512),
    ca_pem                text        NOT NULL CHECK (char_length(ca_pem) BETWEEN 1 AND 65536),
    bind_dn               text        NOT NULL CHECK (char_length(bind_dn) BETWEEN 1 AND 1024),
    bind_password         bytea       NOT NULL CHECK (octet_length(bind_password) BETWEEN 1 AND 4096),
    bind_password_key_id  uuid        NOT NULL REFERENCES data_keys (id),
    user_base_dn          text        NOT NULL CHECK (char_length(user_base_dn) BETWEEN 1 AND 1024),
    user_filter           text        NOT NULL CHECK (char_length(user_filter) BETWEEN 1 AND 512),
    id_attribute          text        NOT NULL CHECK (id_attribute IN ('entryUUID', 'ipaUniqueID', 'nsUniqueId', 'objectGUID')),
    display_attribute     text        NOT NULL CHECK (char_length(display_attribute) BETWEEN 1 AND 64),
    group_mode            text        NOT NULL CHECK (group_mode IN ('member_of', 'member', 'ad_nested')),
    group_base_dn         text        NOT NULL CHECK (char_length(group_base_dn) <= 1024),
    version               integer     NOT NULL CHECK (version >= 1),
    updated_at            timestamptz NOT NULL,
    updated_by            uuid        NOT NULL REFERENCES users (id)
);

CREATE INDEX ldap_settings_key ON ldap_settings (bind_password_key_id);

-- Сопоставление групп каталога (DN) с ролями: явная таблица
-- (ADR-0025, 1.4). DN сравнивается без учёта регистра при входе.
CREATE TABLE ldap_group_roles (
    org_id   uuid NOT NULL REFERENCES ldap_settings (org_id) ON DELETE CASCADE,
    group_dn text NOT NULL CHECK (char_length(group_dn) BETWEEN 1 AND 1024),
    role     text NOT NULL,
    PRIMARY KEY (org_id, group_dn),
    FOREIGN KEY (org_id, role) REFERENCES roles (org_id, id)
);

REVOKE ALL ON ldap_settings, ldap_group_roles FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON ldap_settings, ldap_group_roles TO aisec_app;
GRANT UPDATE (enabled, url, ca_pem, bind_dn, bind_password, bind_password_key_id, user_base_dn, user_filter,
    id_attribute, display_attribute, group_mode, group_base_dn, version, updated_at, updated_by) ON ldap_settings TO aisec_app;
