-- Выдержки ответов тестирования устойчивости — только запечатанными
-- (5В3 ревью 5.r3 этапа 5; ADR-0031, раздел 7).
--
-- Выдержка ответа цели endpoint в режиме masked (до 1 КиБ) хранилась
-- открытым текстом: замена категорией закрывает только найденные ПДн и
-- секреты, а утёкший системный промпт или внутренние данные приложения
-- заказчика оставались в БД и её дампах. Теперь — шифротекст ключа данных
-- (internal/keyring, AAD redteam_results|example|<запуск>/<сценарий>) с ID
-- версии ключа и алгоритмом; ротация ключа данных его перешифровывает, а
-- версия не удаляется, пока на неё ссылается выдержка.
--
-- Открытые выдержки, записанные до обновления, удаляются: зашифровать их
-- миграция не может (ключ данных — вне БД), а выдержка — не результат
-- запуска, а пример к отчёту. Вердикты, находки и счётчики сохраняются.

UPDATE redteam_results SET example = '' WHERE example <> '';
ALTER TABLE redteam_results DROP COLUMN example;
ALTER TABLE redteam_results
    ADD COLUMN example        bytea CHECK (octet_length(example) BETWEEN 16 AND 1200),
    ADD COLUMN example_key_id uuid  REFERENCES data_keys (id),
    ADD COLUMN example_alg    text  CHECK (char_length(example_alg) BETWEEN 1 AND 32),
    ADD CONSTRAINT redteam_results_example_sealed
        CHECK ((example IS NULL) = (example_key_id IS NULL) AND (example IS NULL) = (example_alg IS NULL));
CREATE INDEX redteam_results_example_key ON redteam_results (example_key_id) WHERE example_key_id IS NOT NULL;
