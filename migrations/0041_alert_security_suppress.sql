-- Окна подавления после закрытия у системных правил и правил безопасности
-- нет (3В15 ревью 3.r2 этапа 3, ADR-0020, п. 5): закрытие оповещения
-- безопасности не глушит повторы — каждое повторное срабатывание после
-- закрытия даёт новое оповещение и новые уведомления. Шум DM-40 снимает
-- окно группировки (10 минут).
UPDATE alert_rules SET suppress_minutes = 0 WHERE kind IN ('system', 'security');
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_locked_no_suppress
    CHECK (suppress_minutes = 0 OR kind NOT IN ('system', 'security'));
