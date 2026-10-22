-- Цены моделей, бюджеты приложений и расход (ТЗ 5.8, 4.2; решение Р7
-- этапа 3, задача 3.18). Деньги — целые числа без плавающей точки:
--   цена — десятитысячные доли рубля за 1 000 токенов (0,0001 ₽);
--   бюджет — копейки в месяц;
--   расход — десятимиллионные доли рубля (1e-7 ₽): ровно токены × цена.
-- Расход считают шлюзы по usage ответов провайдера (то же, что попадает в
-- события) и присылают с heartbeat: каждый процесс шлюза — свои
-- нарастающие счётчики за месяц (запуск — started_at), сервер берёт
-- наибольшее значение, поэтому повтор heartbeat ничего не удваивает, а
-- перезапуск шлюза не обнуляет расход месяца.

CREATE TABLE model_prices (
    id           uuid        PRIMARY KEY,
    org_id       uuid        NOT NULL REFERENCES organizations (id),
    -- Цены удалённого провайдера бессмысленны и удаляются вместе с ним.
    provider_id  uuid        NOT NULL REFERENCES providers (id) ON DELETE CASCADE,
    -- model — имя модели у провайдера (после псевдонима приложения).
    model        text        NOT NULL CHECK (char_length(model) BETWEEN 1 AND 128),
    input_price  bigint      NOT NULL CHECK (input_price BETWEEN 0 AND 10000000000),
    output_price bigint      NOT NULL CHECK (output_price BETWEEN 0 AND 10000000000),
    created_at   timestamptz NOT NULL,
    created_by   text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at   timestamptz NOT NULL,
    updated_by   text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    UNIQUE (org_id, provider_id, model)
);

CREATE TABLE app_budgets (
    app_id        uuid        PRIMARY KEY REFERENCES applications (id),
    org_id        uuid        NOT NULL REFERENCES organizations (id),
    -- soft — только оповещения 80 % и 100 % (задача 3.12); hard — шлюз
    -- отклоняет запросы сверх бюджета (429 budget_exceeded).
    mode          text        NOT NULL CHECK (mode IN ('soft', 'hard')),
    -- Месячный бюджет, копейки: от 0,01 ₽ до 1 000 000 000 ₽.
    monthly_limit bigint      NOT NULL CHECK (monthly_limit BETWEEN 1 AND 100000000000),
    created_at    timestamptz NOT NULL,
    created_by    text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at    timestamptz NOT NULL,
    updated_by    text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128)
);

CREATE TABLE budget_usage (
    org_id            uuid        NOT NULL REFERENCES organizations (id),
    -- Шлюз (CN сертификата) и запуск его процесса.
    gateway_id        text        NOT NULL CHECK (char_length(gateway_id) BETWEEN 1 AND 128),
    started_at        timestamptz NOT NULL CHECK (isfinite(started_at)),
    app_slug          text        NOT NULL CHECK (app_slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    -- Месяц в часовом поясе установки (install_settings.timezone).
    month             text        NOT NULL CHECK (month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    cost              bigint      NOT NULL CHECK (cost >= 0),
    priced_tokens     bigint      NOT NULL CHECK (priced_tokens >= 0),
    unpriced_tokens   bigint      NOT NULL CHECK (unpriced_tokens >= 0),
    requests          bigint      NOT NULL CHECK (requests >= 0),
    unpriced_requests bigint      NOT NULL CHECK (unpriced_requests >= 0),
    updated_at        timestamptz NOT NULL,
    PRIMARY KEY (org_id, month, app_slug, gateway_id, started_at)
);

-- Цены и бюджеты входят в пакет конфигурации шлюзов (раздел budgets):
-- их изменение увеличивает счётчик изменений (миграция 0030). Расход в
-- пакет не входит.
CREATE TRIGGER model_prices_revision AFTER INSERT OR DELETE ON model_prices
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER model_prices_revision_update AFTER UPDATE ON model_prices
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER app_budgets_revision AFTER INSERT OR DELETE ON app_budgets
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER app_budgets_revision_update AFTER UPDATE ON app_budgets
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();

REVOKE ALL ON model_prices, app_budgets, budget_usage FROM PUBLIC;
-- UPDATE — только изменяемые столбцы: провайдер, модель, приложение,
-- авторы и время создания сервер не меняет.
GRANT SELECT, INSERT, DELETE ON model_prices TO aisec_app;
GRANT UPDATE (input_price, output_price, updated_at, updated_by) ON model_prices TO aisec_app;
GRANT SELECT, INSERT, DELETE ON app_budgets TO aisec_app;
GRANT UPDATE (mode, monthly_limit, updated_at, updated_by) ON app_budgets TO aisec_app;
GRANT SELECT, INSERT ON budget_usage TO aisec_app;
GRANT UPDATE (cost, priced_tokens, unpriced_tokens, requests, unpriced_requests, updated_at) ON budget_usage TO aisec_app;
