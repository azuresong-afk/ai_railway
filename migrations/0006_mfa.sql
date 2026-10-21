-- Второй фактор входа в консоль — TOTP (ТЗ 7.2 ИАФ.5; решения Р1, Р2 этапа 2;
-- ADR-0006; задача 2.8). Секрет TOTP хранится только шифротекстом ключа
-- данных (ADR-0007, AAD — user_mfa|secret|<user_id>); коды восстановления —
-- только хешами профиля.

-- Второй фактор пользователя. pending — секрет выдан, но ещё не подтверждён
-- кодом; enabled — подключён. last_step — шаг последнего принятого кода:
-- код того же или более раннего шага не принимается (защита от повтора),
-- обновляется условием last_step < $шаг в той же записи.
CREATE TABLE user_mfa (
    user_id     uuid        PRIMARY KEY REFERENCES users (id),
    state       text        NOT NULL CHECK (state IN ('pending', 'enabled')),
    secret      bytea       NOT NULL CHECK (octet_length(secret) BETWEEN 16 AND 256),
    data_key_id uuid        NOT NULL REFERENCES data_keys (id),
    alg         text        NOT NULL CHECK (char_length(alg) BETWEEN 1 AND 32),
    last_step   bigint      NOT NULL DEFAULT 0 CHECK (last_step >= 0),
    created_at  timestamptz NOT NULL,
    enabled_at  timestamptz,
    CHECK ((state = 'enabled') = (enabled_at IS NOT NULL))
);

-- Шаг не уменьшается (иначе перехваченный код можно повторить), а у
-- подключённого фактора не меняются секрет и состояние: заменить их можно
-- только сбросом (удаление строки с записью аудита). Для всех, включая владельца.
CREATE FUNCTION user_mfa_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF NEW.user_id <> OLD.user_id THEN
        RAISE EXCEPTION 'user_mfa: пользователь не меняется' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.last_step < OLD.last_step THEN
        RAISE EXCEPTION 'user_mfa: шаг кода не уменьшается' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'enabled' AND (NEW.state <> OLD.state OR NEW.secret <> OLD.secret
        OR NEW.data_key_id <> OLD.data_key_id OR NEW.alg <> OLD.alg
        OR NEW.created_at <> OLD.created_at OR NEW.enabled_at IS DISTINCT FROM OLD.enabled_at) THEN
        RAISE EXCEPTION 'user_mfa: подключённый фактор меняется только сбросом' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER user_mfa_guard BEFORE UPDATE ON user_mfa
    FOR EACH ROW EXECUTE FUNCTION user_mfa_guard();

-- Коды восстановления: 80 случайных бит, показываются один раз, здесь —
-- хеш профиля. Использованный или заменённый код помечается used_at.
CREATE TABLE recovery_codes (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id),
    code_hash  bytea       NOT NULL CHECK (octet_length(code_hash) BETWEEN 16 AND 64),
    created_at timestamptz NOT NULL,
    used_at    timestamptz CHECK (used_at IS NULL OR used_at >= created_at),
    UNIQUE (user_id, code_hash)
);

CREATE INDEX recovery_codes_unused ON recovery_codes (user_id) WHERE used_at IS NULL;

-- Погашенный код не возвращается, остальные поля не меняются.
CREATE FUNCTION recovery_codes_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF OLD.used_at IS NOT NULL OR NEW.used_at IS NULL OR NEW.user_id <> OLD.user_id
        OR NEW.code_hash <> OLD.code_hash OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'recovery_codes: код только гасится, один раз' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER recovery_codes_guard BEFORE UPDATE ON recovery_codes
    FOR EACH ROW EXECUTE FUNCTION recovery_codes_guard();

-- Состояния сессии второго фактора и причины завершения: «сброс фактора» и
-- «второй фактор пройден» (сессия до фактора заменяется полной с новыми
-- токенами — токены сессии по-прежнему неизменны).
ALTER TABLE sessions DROP CONSTRAINT sessions_state_check,
    ADD CONSTRAINT sessions_state_check CHECK (state IN ('active', 'password_change', 'mfa_pending', 'mfa_setup'));
ALTER TABLE sessions DROP CONSTRAINT sessions_revoke_reason_check,
    ADD CONSTRAINT sessions_revoke_reason_check CHECK (revoke_reason IN ('logout', 'idle', 'expired', 'limit', 'admin',
        'password_changed', 'password_reset', 'deactivated', 'locked', 'mfa_reset', 'mfa_passed'));

-- Второй фактор обязателен для всех ролей (кроме ролей, где он обязателен всегда).
ALTER TABLE auth_settings ADD COLUMN mfa_required_all boolean NOT NULL DEFAULT false;

-- Права роли приложения: фактор удаляется только при сбросе (с аудитом);
-- коды восстановления не удаляются, а гасятся.
REVOKE ALL ON user_mfa, recovery_codes FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON user_mfa TO aisec_app;
GRANT UPDATE (state, secret, data_key_id, alg, last_step, created_at, enabled_at) ON user_mfa TO aisec_app;
GRANT SELECT, INSERT ON recovery_codes TO aisec_app;
GRANT UPDATE (used_at) ON recovery_codes TO aisec_app;
GRANT UPDATE (mfa_required_all) ON auth_settings TO aisec_app;
