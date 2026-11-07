package gwregistry

import (
	"fmt"
	"time"
)

// EventBufferStats — буфер событий шлюза на диске из heartbeat (задача
// 6.31, ADR-0037, раздел 8): заполнение, самая старая непосланная запись и
// счётчики с запуска процесса шлюза. Поле heartbeat необязательное: шлюз с
// выключенным буфером или прежней версии его не присылает.
type EventBufferStats struct {
	Bytes, MaxBytes int64
	// Records — непосланные события; OldestAt — время первой записи самого
	// старого сегмента с непосланными (нулевое — буфер пуст).
	Records  int64
	OldestAt time.Time
	// Spilled — записано на диск, Replayed — дослано с диска.
	Spilled, Replayed int64
	// DroppedLimit, DroppedExpired — отброшено сверх предела и срока;
	// Corrupt — пропущено повреждённых; WriteErrors — неудачных записей на
	// диск (события остались в памяти).
	DroppedLimit, DroppedExpired, Corrupt, WriteErrors int64
}

// EventBufferMark — последнее состояние буфера шлюза: время heartbeat и
// запуск процесса шлюза (по нему видно, что счётчики начаты заново).
type EventBufferMark struct {
	EventBufferStats
	At        time.Time
	StartedAt time.Time
}

// Пределы размера буфера в сообщении: как -event-buffer-max-mib шлюза
// (64 МиБ — 1 ТиБ) с запасом до 1 ПиБ.
const (
	minEventBufferBytes = 64 << 20
	maxEventBufferBytes = 1 << 50
)

// validate — счётчики 0–2^62, предел 64 МиБ — 1 ПиБ, занятое не больше
// предела с запасом на сегмент, oldest_at только при непосланных.
func (b *EventBufferStats) validate() error {
	if b == nil {
		return nil
	}
	if b.MaxBytes < minEventBufferBytes || b.MaxBytes > maxEventBufferBytes || b.Bytes < 0 || b.Bytes > 2*b.MaxBytes {
		return fmt.Errorf("%w: event_buffer — max_bytes от 64 МиБ до 1 ПиБ, bytes не больше удвоенного max_bytes", ErrInvalidRequest)
	}
	for _, c := range []struct {
		n string
		v int64
	}{{"records", b.Records}, {"spilled", b.Spilled}, {"replayed", b.Replayed}, {"dropped_limit", b.DroppedLimit},
		{"dropped_expired", b.DroppedExpired}, {"corrupt", b.Corrupt}, {"write_errors", b.WriteErrors}} {
		if c.v < 0 || c.v > maxLimitCount {
			return fmt.Errorf("%w: event_buffer.%s — от 0 до 2^62", ErrInvalidRequest, c.n)
		}
	}
	if !b.OldestAt.IsZero() && b.Records == 0 {
		return fmt.Errorf("%w: event_buffer.oldest_at — только при непосланных событиях", ErrInvalidRequest)
	}
	return nil
}

// observeEventBuffer запоминает состояние буфера из принятого heartbeat —
// в памяти сервера, как limits и media: шлюз присылает его с каждым
// heartbeat. Шлюз без поля или остановленный — данных нет.
func (s *Service) observeEventBuffer(gatewayID string, in HeartbeatInput, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.EventBuffer == nil || in.Stopping {
		delete(s.eventBuffer, gatewayID)
		return
	}
	s.eventBuffer[gatewayID] = EventBufferMark{EventBufferStats: *in.EventBuffer, At: now, StartedAt: in.StartedAt}
}

// GatewayEventBuffer — последнее состояние буфера событий каждого шлюза по
// ID (копия).
func (s *Service) GatewayEventBuffer() map[string]EventBufferMark {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]EventBufferMark, len(s.eventBuffer))
	for id, m := range s.eventBuffer {
		out[id] = m
	}
	return out
}
