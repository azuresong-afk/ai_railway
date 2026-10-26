-- Разделы рассылки по правам автора расписания (3В31 ревью 3.r4 этапа 3,
-- УПД.2): получатели почтового канала — адреса, а не пользователи с
-- правами, поэтому отчёт рассылки не шире прав того, кто последним
-- создал или изменил расписание. У прежних расписаний разделы инцидентов,
-- оповещений и бюджетов выключены до следующего сохранения.
ALTER TABLE report_schedules
    ADD COLUMN scope_incidents boolean NOT NULL DEFAULT false,
    ADD COLUMN scope_alerts    boolean NOT NULL DEFAULT false,
    ADD COLUMN scope_budgets   boolean NOT NULL DEFAULT false,
    ADD CHECK (report <> 'incidents' OR scope_incidents);

GRANT UPDATE (scope_incidents, scope_alerts, scope_budgets) ON report_schedules TO aisec_app;
