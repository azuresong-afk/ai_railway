-- Откат выпуска и конфигурация шлюза под контролем целостности (ревью 2.r4
-- этапа 2: В19, В20, Н34; ТЗ 7.5 ОЦЛ.3, ОЦЛ.5; DM-42).
--
-- 1. integrity_checks: время сборки манифеста (поле created, время
--    коммита — упорядочено, в отличие от версии). Успешная проверка
--    манифестом старше последней успешной — нарушение manifest_rollback.
--    Намеренный откат (aisec-cli verify -accept-rollback) — успешная строка
--    с rollback_accepted: после неё максимум считается заново.
-- 2. gateways: версия и время манифеста из heartbeat шлюза и их максимум
--    (уменьшение — откат шлюза), признак тестового ключа манифеста и итог
--    сверки ключей проверки пакетов шлюза с ключом подписи сервера.
-- 3. Условие «Состояния системы» test_build — сборка с тестовым ключом.

ALTER TABLE integrity_checks
    ADD COLUMN manifest_created  timestamptz CHECK (isfinite(manifest_created)),
    ADD COLUMN rollback_accepted boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT integrity_checks_rollback_ok CHECK (NOT rollback_accepted OR (ok AND manifest_created IS NOT NULL));

ALTER TABLE integrity_checks DROP CONSTRAINT integrity_checks_reason_check;
ALTER TABLE integrity_checks ADD CONSTRAINT integrity_checks_reason_check
    CHECK (reason IN ('ok', 'manifest_missing', 'manifest_invalid', 'signature_invalid', 'files_mismatch',
                      'manifest_rollback'));

-- Максимум по успешным проверкам компонента и последний принятый откат.
CREATE INDEX integrity_checks_created ON integrity_checks (org_id, component, manifest_created DESC) WHERE ok;
CREATE INDEX integrity_checks_rollback_accepted ON integrity_checks (org_id, ts DESC) WHERE rollback_accepted;

ALTER TABLE gateways
    ADD COLUMN manifest_version     text        CHECK (char_length(manifest_version) BETWEEN 1 AND 128),
    ADD COLUMN manifest_created     timestamptz CHECK (isfinite(manifest_created)),
    ADD COLUMN manifest_max_version text        CHECK (char_length(manifest_max_version) BETWEEN 1 AND 128),
    ADD COLUMN manifest_max_created timestamptz CHECK (isfinite(manifest_max_created)),
    ADD COLUMN test_signed          boolean,
    ADD COLUMN bundle_keys_ok       boolean,
    ADD CONSTRAINT gateways_manifest_pair CHECK ((manifest_version IS NULL) = (manifest_created IS NULL)),
    ADD CONSTRAINT gateways_manifest_max_pair CHECK ((manifest_max_version IS NULL) = (manifest_max_created IS NULL));

GRANT UPDATE (manifest_version, manifest_created, manifest_max_version, manifest_max_created, test_signed, bundle_keys_ok)
    ON gateways TO aisec_app;

ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server',
                      'test_build')
        OR condition ~ '^(integrity:gateway|config_bundle_lag):[0-9a-f-]{1,64}$'));
