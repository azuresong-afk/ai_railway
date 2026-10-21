package sysstatus

// Состояние синхронизации времени (ТЗ 7.8 ВРМ.1, решение Р11): ядро ОС
// сообщает, синхронизировано ли системное время с внешним источником.
// Продукт сам не обращается к NTP-серверам и не запускает внешних команд.

// Значения TimeStatus.Sync.
const (
	SyncSynchronized   = "synchronized"
	SyncUnsynchronized = "unsynchronized"
	SyncUnknown        = "unknown"
)

// Константы ядра Linux (linux/timex.h): в пакете syscall их нет.
const (
	// staUnsync — флаг STA_UNSYNC в поле status: часы не синхронизированы.
	staUnsync = 0x0040
	// timeError — состояние TIME_ERROR, которое возвращает adjtimex: часы
	// не синхронизированы или ошибка синхронизации.
	timeError = 5
)

// ClockState — сведения ядра о синхронизации часов.
type ClockState struct {
	Sync string
	// ErrorMicros — оценка ошибки времени в микросекундах; nil, если её нет.
	ErrorMicros *int64
}

// ClockReader читает состояние часов; подменяется в тестах.
type ClockReader func() ClockState

// classifyClock переводит ответ adjtimex в ClockState: state — возвращённое
// состояние, status — поле status структуры timex, esterror — оценка ошибки.
func classifyClock(state int, status int64, esterror int64) ClockState {
	st := ClockState{Sync: SyncSynchronized}
	if state == timeError || status&staUnsync != 0 {
		st.Sync = SyncUnsynchronized
	}
	if esterror >= 0 {
		e := esterror
		st.ErrorMicros = &e
	}
	return st
}
