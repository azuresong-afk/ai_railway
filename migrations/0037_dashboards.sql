-- Почасовые агрегаты событий для дашбордов (ТЗ 5.8, 6.4; задача 3.19 этапа 3).
--
-- Содержимого запросов и ответов здесь нет: только измерения (приложение,
-- провайдер, модель, детектор, строка матрицы обнаружения, действие) и
-- счётчики. Строки добавляются в транзакции приёма событий (хук
-- events.IngestHook) по новым событиям — дубли пакета до них не доходят —
-- и пересчитываются по таблице events при досчёте прошлых периодов. Час —
-- по UTC; сутки и день недели считаются при чтении в часовом поясе
-- установки (install_settings). Стоимость — по ценам модели на момент
-- приёма события, единицы 1e-7 ₽ (миграция 0031); события моделей без
-- цены стоимость не получают и считаются отдельно (unpriced_*).
-- Минутные счётчики оповещений (alert_rule_counts) здесь не используются.

-- Запросы: решение, расход токенов и стоимость.
CREATE TABLE dash_req_hour (
    org_id             uuid        NOT NULL REFERENCES organizations (id),
    bucket             timestamptz NOT NULL CHECK (isfinite(bucket)),
    app                text        NOT NULL,
    provider           text        NOT NULL,
    model              text        NOT NULL,
    -- Итоговое действие политики (как в events.action); mode — режим политики
    -- (monitor/enforce): block в monitor — «заблокировал бы».
    action             text        NOT NULL,
    mode               text        NOT NULL,
    requests           bigint      NOT NULL CHECK (requests > 0),
    with_findings      bigint      NOT NULL CHECK (with_findings >= 0),
    non_text_unchecked bigint      NOT NULL CHECK (non_text_unchecked >= 0),
    tokens_prompt      bigint      NOT NULL CHECK (tokens_prompt >= 0),
    tokens_completion  bigint      NOT NULL CHECK (tokens_completion >= 0),
    cost               bigint      NOT NULL CHECK (cost >= 0),
    unpriced_requests  bigint      NOT NULL CHECK (unpriced_requests >= 0),
    PRIMARY KEY (org_id, bucket, app, provider, model, action, mode)
);

-- Находки детекторов: строка матрицы (threat, DM-NN), категория находки
-- (pii.snils, injection.override и т. п.), действие по событию.
CREATE TABLE dash_find_hour (
    org_id   uuid        NOT NULL REFERENCES organizations (id),
    bucket   timestamptz NOT NULL CHECK (isfinite(bucket)),
    app      text        NOT NULL,
    detector text        NOT NULL,
    category text        NOT NULL,
    threat   text        NOT NULL,
    action   text        NOT NULL,
    findings bigint      NOT NULL CHECK (findings > 0),
    PRIMARY KEY (org_id, bucket, app, detector, category, threat, action)
);

-- Расход по пользователям (псевдонимы, не исходные идентификаторы).
CREATE TABLE dash_user_hour (
    org_id            uuid        NOT NULL REFERENCES organizations (id),
    bucket            timestamptz NOT NULL CHECK (isfinite(bucket)),
    app               text        NOT NULL,
    user_alias        text        NOT NULL,
    requests          bigint      NOT NULL CHECK (requests > 0),
    tokens_prompt     bigint      NOT NULL CHECK (tokens_prompt >= 0),
    tokens_completion bigint      NOT NULL CHECK (tokens_completion >= 0),
    cost              bigint      NOT NULL CHECK (cost >= 0),
    PRIMARY KEY (org_id, bucket, app, user_alias)
);

-- Гистограмма задержки шлюза (всего минус провайдер), мс: le — верхняя
-- граница корзины, 2147483647 — «больше последней границы».
CREATE TABLE dash_latency_hour (
    org_id uuid        NOT NULL REFERENCES organizations (id),
    bucket timestamptz NOT NULL CHECK (isfinite(bucket)),
    app    text        NOT NULL,
    le     integer     NOT NULL CHECK (le > 0),
    n      bigint      NOT NULL CHECK (n > 0),
    PRIMARY KEY (org_id, bucket, app, le)
);

-- Отметка досчёта: хук включается с live_since; фоновая задача пересчитывает
-- по таблице events часы [backfill_cursor, backfill_until) частями. До первого
-- шага cursor пуст (начало — самое раннее событие). Сбой обновления агрегатов
-- в транзакции приёма расширяет интервал и снимает backfill_done — задача
-- досчитывает пропущенные часы. После backfill_done агрегаты полные.
CREATE TABLE dash_state (
    org_id          uuid        PRIMARY KEY REFERENCES organizations (id),
    live_since      timestamptz NOT NULL,
    backfill_cursor timestamptz,
    backfill_until  timestamptz NOT NULL,
    backfill_done   boolean     NOT NULL,
    updated_at      timestamptz NOT NULL
);

-- Агрегаты — производные данные: пересчёт заменяет строки, срок хранения
-- (как у метаданных событий) удаляет старые. Состояние меняет задача досчёта.
REVOKE ALL ON dash_req_hour, dash_find_hour, dash_user_hour, dash_latency_hour, dash_state FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON dash_req_hour, dash_find_hour, dash_user_hour, dash_latency_hour TO aisec_app;
GRANT SELECT, INSERT ON dash_state TO aisec_app;
GRANT UPDATE (backfill_cursor, backfill_until, backfill_done, updated_at) ON dash_state TO aisec_app;
