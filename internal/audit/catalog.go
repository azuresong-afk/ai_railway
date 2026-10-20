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
	{"auth.mfa_reset", "Сброс второго фактора пользователя", true},
	{"gateway.auth_failed", "Неудачная аутентификация на шлюзе", true},
	// Компоненты (РСБ.2).
	{"component.start", "Запуск компонента", true},
	{"component.stop", "Остановка компонента", true},
	{"system.error", "Ошибка или сбой", true},
	{"system.init", "Создание ключей установки (aisec-cli init)", true},
	// Целостность и самотестирование (РСБ.2, ОЦЛ).
	{"integrity.check", "Результат контроля целостности", true},
	{"selftest.result", "Результат самотестирования", true},
	// Обновления, резервное копирование, выгрузки (РСБ.2).
	{"update.install", "Обновление компонента", true},
	{"backup.create", "Резервное копирование", true},
	{"backup.restore", "Восстановление из резервной копии", true},
	{"data.export", "Выгрузка данных", true},
	{"events.content_read", "Доступ к содержимому события", true},
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
