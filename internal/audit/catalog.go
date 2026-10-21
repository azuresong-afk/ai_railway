package audit

import "sort"

// Event — тип события журнала аудита.
type Event struct {
	Action string // код: «группа.действие», латиница
	Title  string // описание для консоли и отчётов
	// Mandatory — событие из РСБ.2: регистрируется всегда, в настройках не
	// отключается (РСБ.3).
	Mandatory bool
}

// Перечень событий (РСБ.2–3). Новый тип события добавляется строкой сюда;
// запись с кодом вне перечня отклоняется.
var catalog = []Event{
	// Вход и выход (РСБ.2).
	{"auth.login", "Вход в консоль", true},
	{"auth.logout", "Выход из консоли", true},
	{"auth.login_failed", "Неудачная попытка входа в консоль", true},
	{"auth.locked", "Учётная запись заблокирована после неудачных попыток", true},
	{"auth.unlocked", "Снятие блокировки учётной записи командой aisec-cli", true},
	{"auth.mfa_reset", "Сброс второго фактора пользователя", true},
	{"auth.mfa_setup_started", "Выдача секрета для подключения второго фактора", true},
	{"auth.mfa_enabled", "Подключение второго фактора (TOTP)", true},
	{"auth.mfa_verified", "Вход: второй фактор подтверждён", true},
	{"auth.mfa_failed", "Неверный код второго фактора", true},
	{"auth.recovery_code_used", "Вход по коду восстановления", true},
	{"auth.recovery_codes_regenerated", "Выпуск новых кодов восстановления", true},
	{"auth.password_changed", "Смена своего пароля", true},
	{"auth.sessions_revoked", "Завершение всех сессий пользователя", true},
	{"auth.session_expired", "Завершение сессии по бездействию или сроку", true},
	{"auth.policy_changed", "Изменение парольной политики и настроек входа", true},
	{"gateway.auth_failed", "Неудачная аутентификация на шлюзе", true},
	// Учётные записи (РСБ.2, УПД.5, ЗИ.4).
	{"setup.completed", "Первичная настройка: создан первый администратор", true},
	{"user.create", "Создание учётной записи", true},
	{"user.deactivate", "Деактивация учётной записи", true},
	{"user.activate", "Повторная активация учётной записи", true},
	{"user.password_reset", "Сброс пароля пользователя администратором", true},
	// Регистрация шлюзов и mTLS (ИАФ.10, задача 2.14).
	{"gateway.token_issue", "Выпуск токена регистрации шлюза", true},
	{"gateway.register", "Регистрация шлюза: выпуск сертификата по токену", true},
	{"gateway.revoke", "Отзыв шлюза", true},
	{"gateway.mtls_denied", "Отказ шлюзу во внутреннем API: сертификат отозван или неизвестен", true},
	// Роли и доступ (РСБ.1, УПД.1–2, 6).
	{"role.create", "Создание своей роли", true},
	{"role.update", "Изменение своей роли", true},
	{"role.delete", "Удаление своей роли", true},
	{"user.role_changed", "Назначение роли пользователю", true},
	{"access.denied", "Отказ в доступе к функции управления", true},
	// Токены API (ИАФ.9, РСБ.1; задача 2.10).
	{"api_token.create", "Выпуск токена API", true},
	{"api_token.revoke", "Отзыв токена API", true},
	{"api_token.used", "Запрос по токену API", true},
	{"api_token.auth_failed", "Неудачная аутентификация по токену API", true},
	// Приложения, ключи и провайдеры (ИАФ.8, ЗИ.1, DM-40; задача 2.11).
	{"provider.create", "Создание провайдера", true},
	{"provider.update", "Изменение провайдера", true},
	{"provider.delete", "Удаление провайдера", true},
	{"provider.credentials_set", "Замена учётных данных провайдера", true},
	{"provider.external_changed", "Изменение признака «внешний» у провайдера", true},
	{"application.create", "Создание приложения", true},
	{"application.update", "Изменение приложения", true},
	{"application.protection_changed", "Изменение политики, режима или режима хранения приложения", true},
	{"application.archive", "Архивация приложения", true},
	{"app_key.issue", "Выпуск ключа приложения", true},
	{"app_key.rotate", "Ротация ключа приложения", true},
	{"app_key.revoke", "Отзыв ключа приложения", true},
	// Компоненты (РСБ.2).
	{"component.start", "Запуск компонента", true},
	{"component.stop", "Остановка компонента", true},
	{"system.error", "Ошибка или сбой", true},
	{"system.init", "Создание ключей установки (aisec-cli init)", true},
	{"system.audit_key", "Создание ключа подписи журнала аудита (aisec-cli init -add-audit-key)", true},
	// Целостность и самотестирование (РСБ.2, ОЦЛ).
	{"integrity.check", "Результат контроля целостности", true},
	{"selftest.result", "Результат самотестирования", true},
	// Уведомления раздела 7 на этапе 2: смена состояния условия (ВРМ.1, РСБ.5, ОЦЛ.5).
	{"system.alert", "Условие уведомления возникло или снято", true},
	// Обновления, резервное копирование, выгрузки (РСБ.2).
	{"update.install", "Обновление компонента", true},
	{"backup.create", "Резервное копирование", true},
	{"backup.restore", "Восстановление из резервной копии", true},
	{"data.export", "Выгрузка данных", true},
	{"events.content_read", "Доступ к содержимому события", true},
	{"events.retention", "Удаление событий по сроку хранения", true},
	{"events.settings_changed", "Изменение сроков хранения событий", true},
	// Сам журнал аудита (РСБ.3–4).
	{"audit.settings_changed", "Изменение настроек журнала аудита", true},
	{"audit.chain_verified", "Проверка цепочки журнала аудита: цела", true},
	{"audit.chain_broken", "Проверка цепочки журнала аудита: нарушена", true},
	{"audit.archive", "Архивация журнала аудита", true},
	{"audit.export", "Выгрузка журнала аудита в файл", true},
	// Просмотр без изменений (РСБ.1): отключаемые. Изменения конфигурации
	// добавляют задачи, которые их вводят.
	{"events.list", "Просмотр списка событий", false},
	{"events.view", "Просмотр карточки события без содержимого", false},
	{"audit.list", "Просмотр журнала аудита", false},
}

var catalogIndex = func() map[string]Event {
	m := make(map[string]Event, len(catalog))
	for _, e := range catalog {
		if _, dup := m[e.Action]; dup {
			panic("audit: код события повторяется: " + e.Action)
		}
		m[e.Action] = e
	}
	return m
}()

// Lookup возвращает тип события по коду.
func Lookup(action string) (Event, bool) {
	e, ok := catalogIndex[action]
	return e, ok
}

// Catalog возвращает перечень событий, отсортированный по коду.
func Catalog() []Event {
	out := append([]Event(nil), catalog...)
	sort.Slice(out, func(i, j int) bool { return out[i].Action < out[j].Action })
	return out
}
