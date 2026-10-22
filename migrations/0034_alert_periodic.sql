-- Правила «частота», «аномалия» и «бюджет» (ТЗ 5.6; ADR-0020, п. 1 и 14;
-- решение Р3 этапа 3, задача 3.12). Считаются фоновой задачей сервера раз
-- в минуту. Содержимого запросов здесь нет: счётчики, ключи группировки из
-- столбцов событий и ссылки на события.

-- Поминутные счётчики правила «частота»: сколько подходящих событий пришло
-- по ключу группировки. Прибавляются в транзакции приёма событий (повтор
-- пакета до них не доходит); pending — ещё не учтённые в оповещении, их
-- обнуляет фоновая задача той же транзакцией, что поднимает оповещение.
CREATE TABLE alert_rule_counts (
    rule_id      uuid        NOT NULL REFERENCES alert_rules (id),
    group_key    text        NOT NULL CHECK (octet_length(group_key) <= 2048),
    -- Минута по времени события (часы шлюза).
    bucket       timestamptz NOT NULL CHECK (isfinite(bucket)),
    group_values jsonb       NOT NULL CHECK (jsonb_typeof(group_values) = 'object' AND octet_length(group_values::text) <= 4096),
    count        bigint      NOT NULL CHECK (count >= 1),
    pending      bigint      NOT NULL CHECK (pending BETWEEN 0 AND count),
    -- Примеры событий для оповещения: ID и ключ секции, не больше 20.
    event_refs   jsonb       NOT NULL CHECK (jsonb_typeof(event_refs) = 'array' AND jsonb_array_length(event_refs) <= 20),
    PRIMARY KEY (rule_id, group_key, bucket)
);

CREATE INDEX alert_rule_counts_bucket ON alert_rule_counts (bucket);

-- Состояние правила для API: последнее вычисление, обучение «аномалии»
-- (первые 14 суток данных ключа правило молчит), ключи.
-- Организация — через правило (3Н17 ревью 3.12).
CREATE TABLE alert_rule_state (
    rule_id      uuid        PRIMARY KEY REFERENCES alert_rules (id),
    evaluated_at timestamptz NOT NULL,
    state        jsonb       NOT NULL CHECK (jsonb_typeof(state) = 'object' AND octet_length(state::text) <= 16384)
);

-- Отметка последнего прохода фоновой задачи: второй экземпляр сервера не
-- считает ту же минуту повторно.
CREATE TABLE alert_job_runs (
    org_id uuid        NOT NULL REFERENCES organizations (id),
    job    text        NOT NULL CHECK (job IN ('periodic')),
    ran_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, job)
);

-- Счётчики — производные данные: удаляются по возрасту (старше наибольшего
-- окна правила), меняются только счётчики и примеры.
REVOKE ALL ON alert_rule_counts, alert_rule_state, alert_job_runs FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON alert_rule_counts TO aisec_app;
GRANT UPDATE (count, pending, event_refs) ON alert_rule_counts TO aisec_app;
GRANT SELECT, INSERT ON alert_rule_state, alert_job_runs TO aisec_app;
GRANT UPDATE (evaluated_at, state) ON alert_rule_state TO aisec_app;
GRANT UPDATE (ran_at) ON alert_job_runs TO aisec_app;
