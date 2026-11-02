-- Реестр ИИ (ТЗ 5.11; задача 5.17 этапа 5, ADR-0029).
--
-- Приложения, ключи и провайдеры реестр не копирует: он читает их таблицы
-- (миграция 0014). Здесь — то, чего на сервере ещё не было: модели
-- (провайдера и заказчика), файлы моделей заказчика с хешами (эталон для
-- сверки сканером, DM-29), использование «приложение — провайдер — модель»
-- по трафику и состояние задачи пополнения. Весов, содержимого файлов и
-- содержимого запросов здесь нет.

-- Модель. kind: provider — модель провайдера продукта (имя — как в
-- событиях), customer — модель заказчика (веса у заказчика). Пара
-- «провайдер, имя» уникальна; у модели заказчика без провайдера провайдер —
-- пустая строка. origin: traffic — добавлена задачей пополнения, manual —
-- вручную. status: active; запрет использования (blocked) — задача 5.22.
CREATE TABLE inventory_models (
    id          uuid        PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES organizations (id),
    kind        text        NOT NULL CHECK (kind IN ('provider', 'customer')),
    provider    text        NOT NULL CHECK (provider = '' OR provider ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name        text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 256),
    version     text        NOT NULL DEFAULT '' CHECK (char_length(version) <= 128),
    title       text        NOT NULL DEFAULT '' CHECK (char_length(title) <= 200),
    description text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    owner       text        NOT NULL DEFAULT '' CHECK (char_length(owner) <= 200),
    origin      text        NOT NULL CHECK (origin IN ('traffic', 'manual')),
    status      text        NOT NULL DEFAULT 'active' CHECK (status IN ('active')),
    -- Первый и последний час, когда модель встречалась в трафике.
    first_seen  timestamptz CHECK (isfinite(first_seen)),
    last_seen   timestamptz CHECK (isfinite(last_seen)),
    created_at  timestamptz NOT NULL,
    created_by  text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at  timestamptz NOT NULL,
    updated_by  text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    UNIQUE (org_id, provider, name),
    CHECK (kind = 'customer' OR provider <> ''),
    CHECK ((first_seen IS NULL) = (last_seen IS NULL) AND (first_seen IS NULL OR first_seen <= last_seen))
);

CREATE INDEX inventory_models_list ON inventory_models (org_id, created_at, id);

-- Файлы модели: путь относительно каталога модели, размер, роль и хеш
-- (SHA-256 в обоих криптопрофилях — идентификатор для сверки с хешами
-- издателя и для AI-BOM, ADR-0029, п. 1). Не больше 256 на модель
-- (проверяет сервис).
CREATE TABLE inventory_model_files (
    model_id uuid    NOT NULL REFERENCES inventory_models (id) ON DELETE CASCADE,
    path     text    NOT NULL CHECK (octet_length(path) BETWEEN 1 AND 512),
    size     bigint  NOT NULL CHECK (size BETWEEN 0 AND 1125899906842624),
    role     text    NOT NULL CHECK (role IN ('weights', 'adapter', 'tokenizer', 'config', 'other')),
    hash_alg text    NOT NULL CHECK (hash_alg IN ('SHA-256')),
    hash     bytea   NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (model_id, path)
);

-- Использование по трафику: тройка из почасовых агрегатов дашбордов
-- (dash_req_hour, миграция 0037). Счётчиков нет — повторное чтение окна не
-- меняет реестр (ADR-0029, п. 2).
CREATE TABLE inventory_usage (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    app        text        NOT NULL CHECK (char_length(app) BETWEEN 1 AND 256),
    provider   text        NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 256),
    model      text        NOT NULL CHECK (char_length(model) BETWEEN 1 AND 256),
    first_seen timestamptz NOT NULL CHECK (isfinite(first_seen)),
    last_seen  timestamptz NOT NULL CHECK (isfinite(last_seen)),
    UNIQUE (org_id, app, provider, model),
    CHECK (first_seen <= last_seen)
);

CREATE INDEX inventory_usage_model ON inventory_usage (org_id, provider, model);

-- Состояние задачи пополнения: до какого часа прочитаны агрегаты, когда
-- был запуск, достигнут ли предел числа записей и сколько тогда пропущено.
CREATE TABLE inventory_sync_state (
    org_id        uuid        PRIMARY KEY REFERENCES organizations (id),
    synced_upto   timestamptz CHECK (isfinite(synced_upto)),
    run_at        timestamptz NOT NULL CHECK (isfinite(run_at)),
    limit_reached boolean     NOT NULL,
    skipped       bigint      NOT NULL CHECK (skipped >= 0)
);

REVOKE ALL ON inventory_models, inventory_model_files, inventory_usage, inventory_sync_state FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON inventory_models, inventory_model_files, inventory_usage, inventory_sync_state TO aisec_app;
