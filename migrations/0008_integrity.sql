-- Результаты контроля целостности (ТЗ 7.5 ОЦЛ.2, ОЦЛ.5; решение Р10 этапа 2;
-- ADR-0012; задача 2.17): проверки при запуске, по расписанию и по команде.
-- Экран «Состояние системы» (задача 2.20) показывает последнюю проверку
-- каждого компонента. Каждый итог дублируется записью integrity.check в
-- журнале аудита.
CREATE TABLE integrity_checks (
    id               uuid        PRIMARY KEY,
    org_id           uuid        NOT NULL REFERENCES organizations (id),
    ts               timestamptz NOT NULL,
    component        text        NOT NULL CHECK (component ~ '^[a-z][a-z0-9_-]{0,31}$'),
    trigger_kind     text        NOT NULL CHECK (trigger_kind IN ('startup', 'periodic', 'manual')),
    ok               boolean     NOT NULL,
    reason           text        NOT NULL CHECK (reason IN ('ok', 'manifest_missing', 'manifest_invalid',
                                     'signature_invalid', 'files_mismatch')),
    manifest_version text        NOT NULL CHECK (char_length(manifest_version) <= 128),
    test_signed      boolean     NOT NULL,
    checked          integer     NOT NULL CHECK (checked >= 0),
    failures         json        NOT NULL,
    omitted          integer     NOT NULL CHECK (omitted >= 0),
    actor_type       text        NOT NULL CHECK (actor_type IN ('user', 'api_token', 'system', 'cli')),
    actor_id         text        NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 128),
    CHECK (ok = (reason = 'ok'))
);

CREATE INDEX integrity_checks_component_ts ON integrity_checks (org_id, component, ts DESC);

-- История проверок только дополняется: подмена итога скрыла бы нарушение.
-- Функция audit_append_only — из 0002_audit.
CREATE TRIGGER integrity_checks_no_update BEFORE UPDATE ON integrity_checks
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER integrity_checks_no_delete BEFORE DELETE ON integrity_checks
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER integrity_checks_no_truncate BEFORE TRUNCATE ON integrity_checks
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();

REVOKE ALL ON integrity_checks FROM PUBLIC;
GRANT SELECT, INSERT ON integrity_checks TO aisec_app;
