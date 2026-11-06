-- Тестовые события (запуски тестирования устойчивости, details.test) в
-- агрегатах дашбордов отдельно от рабочего трафика (задача 6.11 этапа 6,
-- остаток 5Н31 ревью 5.r4; ADR-0031, дополнение 5).
--
-- Признак test входит в ключ всех четырёх почасовых таблиц: дашборды по
-- умолчанию читают строки без учений, фильтр «учения» — только их. Реестр
-- ИИ пополняется по строкам dash_req_hour без учений.
--
-- Строки, посчитанные до этой миграции, смешивали учения с рабочим
-- трафиком и получают test = false. Часы, в которых есть тестовые события,
-- помечаются к досчёту (dash_dirty_hours): задача досчёта сервера
-- пересчитывает их по таблице events уже с признаком. Пока она не
-- закончит, дашборды показывают «цифры неполные».

ALTER TABLE dash_req_hour ADD COLUMN test boolean NOT NULL DEFAULT false;
ALTER TABLE dash_req_hour DROP CONSTRAINT dash_req_hour_pkey;
ALTER TABLE dash_req_hour ADD PRIMARY KEY (org_id, bucket, app, provider, model, action, mode, test);

ALTER TABLE dash_find_hour ADD COLUMN test boolean NOT NULL DEFAULT false;
ALTER TABLE dash_find_hour DROP CONSTRAINT dash_find_hour_pkey;
ALTER TABLE dash_find_hour ADD PRIMARY KEY (org_id, bucket, app, detector, category, threat, action, test);

ALTER TABLE dash_user_hour ADD COLUMN test boolean NOT NULL DEFAULT false;
ALTER TABLE dash_user_hour DROP CONSTRAINT dash_user_hour_pkey;
ALTER TABLE dash_user_hour ADD PRIMARY KEY (org_id, bucket, app, user_alias, test);

ALTER TABLE dash_latency_hour ADD COLUMN test boolean NOT NULL DEFAULT false;
ALTER TABLE dash_latency_hour DROP CONSTRAINT dash_latency_hour_pkey;
ALTER TABLE dash_latency_hour ADD PRIMARY KEY (org_id, bucket, app, le, test);

INSERT INTO dash_dirty_hours (org_id, bucket, marked_at)
SELECT DISTINCT e.org_id, date_trunc('hour', e.ts, 'UTC'), clock_timestamp()
FROM events e
WHERE e.type IN ('gateway_request', 'check') AND COALESCE((e.details->>'test')::boolean, false);
