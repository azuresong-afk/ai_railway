package license

import (
	"time"
)

// Состояния лицензии (ADR-0026, п. 4).
const (
	// PhaseNone — «пилот по договору»: лицензия не загружалась ни разу,
	// ограничений нет.
	PhaseNone = "none"
	// PhaseActive — лицензия действует, до конца срока больше ExpiryWarn.
	PhaseActive = "active"
	// PhaseExpiring — до конца срока ExpiryWarn и меньше.
	PhaseExpiring = "expiring"
	// PhaseGrace — срок истёк, идёт льготный период GracePeriod.
	PhaseGrace = "grace"
	// PhaseRestricted — льготный период закончился: изменения конфигурации
	// запрещены, трафик и чтение работают.
	PhaseRestricted = "restricted"
	// PhaseInvalid — загруженная лицензия не прошла повторную проверку
	// (отозван ключ, изменена запись в БД): как PhaseRestricted.
	PhaseInvalid = "invalid"
)

// Пороги (ADR-0026, п. 4, 7, 8).
const (
	// ExpiryWarn — за сколько до конца срока поднимается license_expiry и
	// оповещение system.license_expiry.
	ExpiryWarn = 30 * 24 * time.Hour
	// ExpiryCritical — второе оповещение (license_expiry:critical).
	ExpiryCritical = 7 * 24 * time.Hour
	// GracePeriod — льготный период после конца срока.
	GracePeriod = 30 * 24 * time.Hour
	// ClockTolerance — насколько часы сервера могут отставать от отметки
	// часов лицензии без условия license_clock (переход NTP, разные узлы).
	ClockTolerance = 10 * time.Minute
)

// State — состояние лицензии на момент оценки.
type State struct {
	Phase string
	// Signed — действующая проверенная лицензия; nil в PhaseNone и PhaseInvalid.
	Signed *Signed
	// Number — номер загруженной лицензии (и в PhaseInvalid); 0 — нет.
	Number uint64
	// At — время лицензии: наибольшее из часов сервера и отметки часов.
	At time.Time
	// Now — часы сервера.
	Now time.Time
	// ClockBehind — часы сервера раньше даты выдачи лицензии или больше чем
	// на ClockTolerance раньше отметки часов (условие license_clock).
	ClockBehind bool
}

// Evaluate вычисляет состояние по проверенной лицензии s (nil — нет
// действующей), номеру загруженной (0 — не загружалась), часам сервера now
// и отметке часов highWater.
func Evaluate(s *Signed, number uint64, now, highWater time.Time) State {
	now = now.UTC()
	at := now
	if highWater.After(at) {
		at = highWater.UTC()
	}
	st := State{Signed: s, Number: number, At: at, Now: now, ClockBehind: highWater.Sub(now) > ClockTolerance}
	switch {
	case number == 0:
		st.Phase, st.Signed = PhaseNone, nil
		return st
	case s == nil:
		st.Phase = PhaseInvalid
		return st
	}
	l := s.License
	if now.Before(l.IssuedAt) {
		st.ClockBehind = true
	}
	switch until := l.ValidUntil; {
	case at.After(until.Add(GracePeriod)):
		st.Phase = PhaseRestricted
	case at.After(until):
		st.Phase = PhaseGrace
	case until.Sub(at) <= ExpiryWarn:
		st.Phase = PhaseExpiring
	default:
		st.Phase = PhaseActive
	}
	return st
}

// Restricted — изменения конфигурации запрещены.
func (st State) Restricted() bool { return st.Phase == PhaseRestricted || st.Phase == PhaseInvalid }

// Licensed — действует проверенная лицензия (её пределы и модули
// применяются): active, expiring или grace.
func (st State) Licensed() bool {
	return st.Signed != nil && (st.Phase == PhaseActive || st.Phase == PhaseExpiring || st.Phase == PhaseGrace)
}

// ModuleEnabled — модуль доступен: без лицензии — все модули.
func (st State) ModuleEnabled(m string) bool {
	if !st.Licensed() {
		return st.Phase == PhaseNone
	}
	return st.Signed.License.HasModule(m)
}

// LeftUntil — сколько осталось до конца срока (отрицательное — истёк).
func (st State) LeftUntil() time.Duration {
	if st.Signed == nil {
		return 0
	}
	return st.Signed.License.ValidUntil.Sub(st.At)
}

// GraceUntil — конец льготного периода; нулевое — лицензии нет.
func (st State) GraceUntil() time.Time {
	if st.Signed == nil {
		return time.Time{}
	}
	return st.Signed.License.ValidUntil.Add(GracePeriod)
}

// days — целых суток в d, не меньше нуля.
func days(d time.Duration) int { return max(int(d/(24*time.Hour)), 0) }

// DaysLeft — целых суток до конца срока.
func (st State) DaysLeft() int { return days(st.LeftUntil()) }

// GraceDaysLeft — целых суток до конца льготного периода.
func (st State) GraceDaysLeft() int {
	if st.Signed == nil {
		return 0
	}
	return days(st.GraceUntil().Sub(st.At))
}
