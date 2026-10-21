-- Роли и разрешения консоли (ТЗ 7.3: УПД.1–3, 8; задача 2.9). Права
-- предустановленных ролей задаются кодом (internal/auth/permissions.go) и
-- обновляются вместе с продуктом; здесь у них только строки, на которые
-- ссылается users.role. Свои роли хранят набор разрешений в role_permissions.

CREATE TABLE roles (
    org_id       uuid        NOT NULL REFERENCES organizations (id),
    id           text        NOT NULL CHECK (id ~ '^[a-z][a-z0-9_]{2,47}$'),
    display_name text        NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    description  text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    builtin      boolean     NOT NULL DEFAULT false,
    -- Роль требует второй фактор (ИАФ.5, задача 2.8).
    mfa_required boolean     NOT NULL,
    created_at   timestamptz NOT NULL,
    created_by   text        NOT NULL CHECK (char_length(created_by) <= 128),
    updated_at   timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    -- ID предустановленных ролей не занимает своя роль (например, в
    -- организации, созданной позже этой миграции).
    CONSTRAINT roles_builtin_ids CHECK (builtin OR id NOT IN
        ('security_admin', 'system_admin', 'analyst', 'auditor', 'app_owner'))
);

CREATE TABLE role_permissions (
    org_id     uuid NOT NULL,
    role_id    text NOT NULL,
    permission text NOT NULL CHECK (permission ~ '^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$' AND char_length(permission) <= 64),
    scope      text NOT NULL CHECK (scope IN ('all', 'own')),
    PRIMARY KEY (org_id, role_id, permission),
    FOREIGN KEY (org_id, role_id) REFERENCES roles (org_id, id)
);

-- Предустановленные роли каждой организации.
INSERT INTO roles (org_id, id, display_name, builtin, mfa_required, created_at, created_by, updated_at)
SELECT o.id, r.id, r.name, true, r.mfa, now(), 'migration', now()
FROM organizations o
CROSS JOIN (VALUES
    ('security_admin', 'Администратор безопасности', true),
    ('system_admin', 'Администратор системы', true),
    ('analyst', 'Аналитик', false),
    ('auditor', 'Аудитор', false),
    ('app_owner', 'Владелец приложения', false)
) AS r (id, name, mfa);

-- Предустановленную роль не меняет и не удаляет никто, включая владельца
-- таблицы; разрешений в БД у неё нет.
CREATE FUNCTION roles_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF OLD.builtin THEN
        RAISE EXCEPTION 'roles: предустановленная роль % не изменяется', OLD.id
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF TG_OP = 'UPDATE' AND (NEW.builtin OR NEW.id <> OLD.id OR NEW.org_id <> OLD.org_id) THEN
        RAISE EXCEPTION 'roles: ID, организация и признак предустановленной роли неизменны'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER roles_guard BEFORE UPDATE OR DELETE ON roles
    FOR EACH ROW EXECUTE FUNCTION roles_guard();

CREATE FUNCTION role_permissions_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE
    r_org  uuid;
    r_role text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        r_org := OLD.org_id;
        r_role := OLD.role_id;
    ELSE
        r_org := NEW.org_id;
        r_role := NEW.role_id;
    END IF;
    IF EXISTS (SELECT 1 FROM roles WHERE org_id = r_org AND id = r_role AND builtin) THEN
        RAISE EXCEPTION 'role_permissions: права предустановленной роли % задаются кодом', r_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER role_permissions_guard BEFORE INSERT OR UPDATE OR DELETE ON role_permissions
    FOR EACH ROW EXECUTE FUNCTION role_permissions_guard();

-- Роль пользователя — ссылка на роль организации вместо перечня из пяти
-- предустановленных; роль с пользователями не удаляется.
ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_fkey FOREIGN KEY (org_id, role) REFERENCES roles (org_id, id);
CREATE INDEX users_role ON users (org_id, role);

-- Права роли приложения. Признак builtin при вставке не задаётся (по
-- умолчанию false): предустановленные роли создаёт только миграция.
REVOKE ALL ON roles, role_permissions FROM PUBLIC;
GRANT SELECT, DELETE ON roles TO aisec_app;
GRANT INSERT (org_id, id, display_name, description, mfa_required, created_at, created_by, updated_at) ON roles TO aisec_app;
GRANT UPDATE (display_name, description, mfa_required, updated_at) ON roles TO aisec_app;
GRANT SELECT, INSERT, DELETE ON role_permissions TO aisec_app;
GRANT UPDATE (role) ON users TO aisec_app;
