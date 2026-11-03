package gwregistry

import (
	"fmt"
	"time"
)

// MediaStats — состояние клиента aisec-media шлюза из heartbeat (задача 5.44
// этапа 5, DM-50): очередь шлюза, отсрочка после сбоя, итоги с запуска
// процесса шлюза и последний самотест на эталонных изображениях. Поле
// heartbeat необязательное: шлюз без -media-socket или прежней версии его
// не присылает.
type MediaStats struct {
	Inflight, MaxInflight int64
	// Down — последний вызов закончился сбоем анализатора, успешного после
	// него не было.
	Down bool
	// Analyzed — ответов анализатора с запуска шлюза.
	Analyzed int64
	// Unavailable, Overloaded, Timeout, Error — изображения «не проверено»
	// из-за сбоя анализатора по причинам.
	Unavailable, Overloaded, Timeout, Error int64
	// Selftest — последний самотест; nil — ещё не выполнялся.
	Selftest *MediaSelftest
}

// MediaSelftest — итог самотеста aisec-media шлюза.
type MediaSelftest struct {
	// Result — MediaSelftestOK, MediaSelftestFailed или MediaSelftestUnchecked.
	Result string
	At     time.Time
	Failed int
}

// Итоги самотеста aisec-media: unchecked — анализатор недоступен или без
// нужной проверки (не провал).
const (
	MediaSelftestOK        = "ok"
	MediaSelftestFailed    = "failed"
	MediaSelftestUnchecked = "unchecked"
)

// MediaMark — последнее состояние клиента aisec-media шлюза: время
// heartbeat и запуск процесса шлюза (по нему видно, что счётчики начаты
// заново).
type MediaMark struct {
	MediaStats
	At        time.Time
	StartedAt time.Time
}

// maxMediaInflight — предел очереди шлюза в сообщении.
const maxMediaInflight = 1 << 16

// validate — счётчики 0–2^62, очередь не больше предела, предел очереди
// 1–65536; итог самотеста — из списка, время задано, провалы 0–1000 и
// ненулевые только у failed.
func (m *MediaStats) validate() error {
	if m == nil {
		return nil
	}
	if m.MaxInflight < 1 || m.MaxInflight > maxMediaInflight || m.Inflight < 0 || m.Inflight > m.MaxInflight {
		return fmt.Errorf("%w: media — inflight от 0 до max_inflight, max_inflight от 1 до %d", ErrInvalidRequest, maxMediaInflight)
	}
	for _, c := range []struct {
		n string
		v int64
	}{{"analyzed", m.Analyzed}, {"unchecked.unavailable", m.Unavailable}, {"unchecked.overloaded", m.Overloaded},
		{"unchecked.timeout", m.Timeout}, {"unchecked.error", m.Error}} {
		if c.v < 0 || c.v > maxLimitCount {
			return fmt.Errorf("%w: media.%s — от 0 до 2^62", ErrInvalidRequest, c.n)
		}
	}
	if t := m.Selftest; t != nil {
		ok := t.Result == MediaSelftestOK || t.Result == MediaSelftestFailed || t.Result == MediaSelftestUnchecked
		if !ok || t.At.IsZero() || t.Failed < 0 || t.Failed > maxReportFailed || (t.Failed > 0) != (t.Result == MediaSelftestFailed) {
			return fmt.Errorf("%w: media.selftest — ok, failed или unchecked, время проверки, провалы 0–%d только у failed", ErrInvalidRequest, maxReportFailed)
		}
	}
	return nil
}

// observeMedia запоминает состояние клиента aisec-media из принятого
// heartbeat — в памяти сервера, как счётчики limits (задача 5.9): шлюз
// присылает их с каждым heartbeat. Шлюз без поля или остановленный —
// данных нет.
func (s *Service) observeMedia(gatewayID string, in HeartbeatInput, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Media == nil || in.Stopping {
		delete(s.media, gatewayID)
		return
	}
	m := MediaMark{MediaStats: *in.Media, At: now, StartedAt: in.StartedAt}
	if t := in.Media.Selftest; t != nil {
		st := *t
		m.Selftest = &st
	}
	s.media[gatewayID] = m
}

// GatewayMedia — последнее состояние клиента aisec-media каждого шлюза по ID
// (копия).
func (s *Service) GatewayMedia() map[string]MediaMark {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]MediaMark, len(s.media))
	for id, m := range s.media {
		if m.Selftest != nil {
			st := *m.Selftest
			m.Selftest = &st
		}
		out[id] = m
	}
	return out
}
