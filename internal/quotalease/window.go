package quotalease

import "time"

// Окна квот на сервере (ADR-0021, п. 3 и дополнение 1):
//   - минутные квоты — скользящая минута: выдача учитывается, пока не прошла
//     MinuteWindow после её срока;
//   - суточная квота — календарные сутки, бюджет — календарный месяц в
//     часовом поясе установки; аренда не переходит их границу.

// minuteKey — ключ окна минутных квот.
const minuteKey = "minute"

// window — окно квоты в момент now: ключ, срок аренды (не дальше границы
// окна) и длина окна для расчёта начальной доли.
type window struct {
	key    string
	ttl    time.Duration
	length time.Duration
	// end — граница календарного окна; нулевое — скользящее окно.
	end time.Time
}

func windowOf(quota string, now time.Time, loc *time.Location) window {
	switch quota {
	case QuotaRPM, QuotaTPM:
		return window{key: minuteKey, ttl: MinuteTTL, length: MinuteWindow}
	case QuotaTPD:
		t := now.In(loc)
		start := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
		end := start.AddDate(0, 0, 1)
		return window{key: t.Format("2006-01-02"), ttl: min(LongTTL, end.Sub(now)), length: end.Sub(start), end: end}
	}
	t := now.In(loc)
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, loc)
	end := start.AddDate(0, 1, 0)
	return window{key: t.Format("2006-01"), ttl: min(LongTTL, end.Sub(now)), length: end.Sub(start), end: end}
}

// share — размер следующей выдачи шлюзу (ADR-0021, п. 3): начальная доля —
// лимит окна на срок аренды, делённый на число шлюзов на связи, но не
// меньше 1 % лимита и не меньше одной единицы; нагруженный шлюз получает
// до удвоенной прошлой выдачи. Для минутных квот «лимит на срок аренды» —
// весь лимит (как в ADR); для суток и месяца — его часть на срок аренды:
// иначе один шлюз сразу забирал бы полсуток или полмесяца, а остановленный
// шлюз «замораживал» бы их до отчёта. Не меньше want — одного запроса;
// для суток и месяца want берётся не больше равной доли лимита на шлюз
// (4В19 ревью 4.r2): иначе один запрос скомпрометированного шлюза выбирал
// бы весь суточный лимит или месячный бюджет до конца окна.
func share(limit, want int64, gateways int, w window, prev *prevGrant) int64 {
	eff := limit
	n := int64(max(gateways, 1))
	if !w.end.IsZero() {
		eff = msPart(limit, LongTTL, w.length)
		want = min(want, ceilDiv(limit, n))
	}
	size := max(ceilDiv(eff, n), ceilDiv(limit, 100), 1)
	if prev != nil && prev.busy() {
		size = max(size, min(satAdd(prev.granted, prev.granted), limit))
	}
	return min(max(size, want), MaxUnits)
}

// prevGrant — последняя аренда шлюза по приложению и квоте.
type prevGrant struct {
	granted int64
	// used — сообщённый расход; nil — ещё не сообщён (аренда действует
	// или шлюз не успел отчитаться).
	used *int64
	// recent — выдана не раньше двух сроков аренды назад.
	recent bool
	// unreported — недавних неотчитанных аренд шлюза по приложению и
	// квоте, включая эту.
	unreported int
}

// maxUnreported — сколько недавних неотчитанных аренд шлюза ещё считаются
// загрузкой: текущая и прошлая, отчёт о которой не готов (резервы
// держатся до минуты после срока).
const maxUnreported = 2

// busy — прошлая аренда недавняя и использована хотя бы наполовину или
// ещё не закрыта (шлюз просит новую, израсходовав 80 % текущей). Без
// отчётов удвоение не больше двух раз подряд (4В19 ревью 4.r2): иначе
// шлюз удваивал бы долю запросами без отчёта до всего лимита.
func (p *prevGrant) busy() bool {
	if !p.recent {
		return false
	}
	if p.used == nil {
		return p.unreported <= maxUnreported
	}
	return *p.used*2 >= p.granted
}

func ceilDiv(a, b int64) int64 {
	if a <= 0 {
		return 0
	}
	return (a-1)/b + 1
}

// msPart — a·part/whole с точностью до миллисекунды без переполнения:
// a до 2^62, whole — от суток до месяца, part меньше whole.
func msPart(a int64, part, whole time.Duration) int64 {
	p, w := part.Milliseconds(), whole.Milliseconds()
	if w <= 0 || p >= w {
		return a
	}
	return a/w*p + a%w*p/w
}

func satAdd(a, b int64) int64 {
	if a > MaxUnits-b {
		return MaxUnits
	}
	return a + b
}
