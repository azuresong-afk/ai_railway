-- Настройки установки, которые администратор выбирает при первичной
-- настройке (ТЗ 6.4, решение H-Р4, задача 2.24b): часовой пояс показа
-- времени (ВРМ.2) и режим хранения содержимого по умолчанию для новых
-- приложений (ТЗ 5.5). Строка создаётся одной транзакцией с первым
-- администратором. Чтение значений сервером и их изменение в
-- «Администрировании» — отдельные задачи.
CREATE TABLE install_settings (
    org_id         uuid        PRIMARY KEY REFERENCES organizations (id),
    timezone       text        NOT NULL CHECK (char_length(timezone) BETWEEN 1 AND 64),
    retention_mode text        NOT NULL CHECK (retention_mode IN ('none', 'masked', 'full')),
    updated_at     timestamptz NOT NULL
);

-- Права приложения: запись при первичной настройке; изменение в «Администрировании»
-- получит право UPDATE отдельной миграцией.
GRANT SELECT, INSERT ON install_settings TO aisec_app;
