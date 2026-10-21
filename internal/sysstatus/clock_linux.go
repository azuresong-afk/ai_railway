//go:build linux

package sysstatus

import "syscall" //nolint:depguard // ADR-0014: только чтение состояния часов через adjtimex (Р11)

// SystemClock читает состояние часов через adjtimex(2) без изменения часов
// (modes = 0): без os/exec и без обращений к сети (Р11, ADR-0014). Ошибка
// вызова — «unknown», не сбой.
func SystemClock() ClockState {
	var tx syscall.Timex                //nolint:forbidigo // ADR-0014: структура для чтения состояния часов
	state, err := syscall.Adjtimex(&tx) //nolint:forbidigo // ADR-0014: modes = 0, часы не меняются
	if err != nil {
		return ClockState{Sync: SyncUnknown}
	}
	return classifyClock(state, int64(tx.Status), tx.Esterror) //nolint:forbidigo // ADR-0014: поля Status и Esterror только читаются
}
