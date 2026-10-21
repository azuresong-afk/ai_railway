//go:build !linux

package sysstatus

// SystemClock — на системах без adjtimex состояние синхронизации неизвестно
// (это не ошибка).
func SystemClock() ClockState { return ClockState{Sync: SyncUnknown} }
