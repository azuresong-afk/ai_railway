-- Тестирование устойчивости (ТЗ 5.13; задача 5.32 этапа 5, ADR-0031).
--
-- Цели, запуски и итоги сценариев. Промпты атак — в служебной базе
-- сценариев (service_dbs, вид redteam_scenarios), ответы целей не
-- хранятся: только итоги, находки без позиций и (цель endpoint в режиме
-- masked) выдержка до 1 КиБ с замаскированными ПДн и секретами (ТЗ 5.5).
-- Ключ запуска (цель gateway) — только префикс и хеш профиля; сам ключ
-- живёт в памяти исполнителя до конца запуска.

-- Цели. Цель gateway — приложение продукта и модель; цель endpoint —
-- точный адрес заказчика, шаблон тела, путь к ответу, заголовки без
-- секретов (значение секретного заголовка в БД не попадает), корневой
-- сертификат и основание для тестирования адреса.
CREATE TABLE redteam_targets (
    id                 uuid        PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES organizations (id),
    name               text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    kind               text        NOT NULL CHECK (kind IN ('gateway', 'endpoint')),
    app_id             uuid        REFERENCES applications (id) ON DELETE CASCADE,
    model              text        NOT NULL CHECK (char_length(model) <= 128),
    url                text        NOT NULL CHECK (octet_length(url) <= 2048),
    request_template   text        NOT NULL CHECK (octet_length(request_template) <= 16384),
    response_path      text        NOT NULL CHECK (octet_length(response_path) <= 256),
    headers            jsonb       NOT NULL CHECK (jsonb_typeof(headers) = 'array' AND jsonb_array_length(headers) <= 8),
    auth_header        text        NOT NULL CHECK (octet_length(auth_header) <= 64),
    ca_pem             text        NOT NULL CHECK (octet_length(ca_pem) <= 65536),
    authorization_note text        NOT NULL CHECK (char_length(authorization_note) <= 500),
    storage            text        NOT NULL CHECK (storage IN ('', 'none', 'masked')),
    judge_provider     text        NOT NULL CHECK (char_length(judge_provider) <= 63),
    judge_model        text        NOT NULL CHECK (char_length(judge_model) <= 128),
    limits             jsonb       NOT NULL CHECK (jsonb_typeof(limits) = 'object'),
    created_at         timestamptz NOT NULL,
    created_by         text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at         timestamptz NOT NULL,
    updated_by         text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    CHECK ((kind = 'gateway') = (app_id IS NOT NULL)),
    CHECK (kind = 'gateway' OR (url <> '' AND authorization_note <> ''))
);
CREATE INDEX redteam_targets_org ON redteam_targets (org_id, name);

-- Запуски. target_id обнуляется при удалении цели: запуск и его итоги
-- остаются (имя и вид цели скопированы).
CREATE TABLE redteam_runs (
    id          uuid        PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES organizations (id),
    target_id   uuid        REFERENCES redteam_targets (id) ON DELETE SET NULL,
    target_name text        NOT NULL CHECK (char_length(target_name) BETWEEN 1 AND 100),
    target_kind text        NOT NULL CHECK (target_kind IN ('gateway', 'endpoint')),
    app_id      uuid,
    status      text        NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
    reason      text        NOT NULL CHECK (char_length(reason) <= 64),
    scenarios   integer     NOT NULL CHECK (scenarios BETWEEN 0 AND 1000),
    counts      jsonb       NOT NULL CHECK (jsonb_typeof(counts) = 'object'),
    db_version  bigint      NOT NULL CHECK (db_version >= 0),
    started_at  timestamptz NOT NULL,
    started_by  text        NOT NULL CHECK (char_length(started_by) BETWEEN 1 AND 128),
    finished_at timestamptz,
    deadline    timestamptz NOT NULL,
    key_prefix  text,
    key_hash    bytea,
    CHECK ((key_prefix IS NULL) = (key_hash IS NULL)),
    CHECK ((status IN ('queued', 'running')) = (finished_at IS NULL))
);
CREATE INDEX redteam_runs_started ON redteam_runs (org_id, started_at DESC, id DESC);
CREATE INDEX redteam_runs_active ON redteam_runs (org_id) WHERE status IN ('queued', 'running');

-- Итоги сценариев запуска.
CREATE TABLE redteam_results (
    run_id      uuid        NOT NULL REFERENCES redteam_runs (id) ON DELETE CASCADE,
    scenario_id text        NOT NULL CHECK (scenario_id ~ '^[A-Z][A-Z0-9-]{2,63}$'),
    lang        text        NOT NULL CHECK (lang IN ('ru', 'en')),
    threat      text        NOT NULL CHECK (threat ~ '^DM-[0-9]{2}$'),
    category    text        NOT NULL CHECK (char_length(category) <= 64),
    verdict     text        NOT NULL CHECK (verdict IN ('succeeded', 'blocked', 'defended', 'unchecked', 'error', 'skipped')),
    step        integer     NOT NULL CHECK (step BETWEEN 0 AND 8),
    matched     jsonb       NOT NULL CHECK (jsonb_typeof(matched) = 'array'),
    findings    jsonb       NOT NULL CHECK (jsonb_typeof(findings) = 'array'),
    judge       text        NOT NULL CHECK (char_length(judge) <= 32),
    event_ids   jsonb       NOT NULL CHECK (jsonb_typeof(event_ids) = 'array' AND jsonb_array_length(event_ids) <= 8),
    http_status integer     NOT NULL CHECK (http_status BETWEEN 0 AND 999),
    latency_ms  bigint      NOT NULL CHECK (latency_ms >= 0),
    error_code  text        NOT NULL CHECK (char_length(error_code) <= 32),
    example     text        NOT NULL CHECK (octet_length(example) <= 1100),
    created_at  timestamptz NOT NULL,
    PRIMARY KEY (run_id, scenario_id)
);
CREATE INDEX redteam_results_created ON redteam_results (created_at);

-- Ключ запуска входит в пакет шлюзов, пока запуск идёт: начало и конец
-- запуска цели gateway растят счётчик изменений конфигурации (0030).
CREATE TRIGGER redteam_runs_revision AFTER INSERT ON redteam_runs
    FOR EACH ROW WHEN (NEW.key_prefix IS NOT NULL) EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER redteam_runs_revision_update AFTER UPDATE ON redteam_runs
    FOR EACH ROW WHEN (NEW.key_prefix IS NOT NULL AND OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION config_revision_bump();

REVOKE ALL ON redteam_targets, redteam_runs, redteam_results FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON redteam_targets, redteam_runs, redteam_results TO aisec_app;
