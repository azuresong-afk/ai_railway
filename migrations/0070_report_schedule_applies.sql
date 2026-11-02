-- Применимость требований в расписании отчёта соответствия (задача 5.12
-- этапа 5, остаток ревью 4.r4): отчёт строится по пунктам выбранной
-- применимости (ГИС, КИИ, ИСПДн, коммерческий оператор), и только они входят
-- в процент. Пусто — все пункты базы, как до этой миграции. Настройки
-- применимости у организации нет, поэтому значение задаёт расписание.

ALTER TABLE report_schedules
    ADD COLUMN applies text NOT NULL DEFAULT ''
        CHECK (applies IN ('', 'gis', 'kii', 'ispdn', 'commercial')),
    ADD CONSTRAINT report_schedules_applies_compliance CHECK (applies = '' OR report = 'compliance');

GRANT UPDATE (applies) ON report_schedules TO aisec_app;
