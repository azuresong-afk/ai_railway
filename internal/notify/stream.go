package notify

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Передача журнала аудита в SIEM (РСБ.6; задача 3.14, ADR-0020 п. 15).
// Канал syslog или webhook (общий формат) с подпиской audit_stream получает
// записи журнала по порядку seq. Курсор канала хранится в БД; источник
// истины — сам журнал: при недоступности приёмника записи не теряются, а
// передача догоняет журнал после восстановления. Доставка «хотя бы один
// раз»: пакет, не подтверждённый приёмником, передаётся снова целиком, у
// записи есть seq и id для отбрасывания повторов.
const (
	// StreamInterval — период прохода передачи.
	StreamInterval = 10 * time.Second
	// streamBatch — записей за одну попытку (syslog — одно соединение,
	// webhook — один запрос).
	streamBatch = 200
	// streamRounds — попыток канала за проход: догон до 5000 записей за 10 с.
	streamRounds = 25
	// streamLease — срок, на который курсор берётся одним экземпляром
	// сервера: больше предела одной попытки.
	streamLease = 2 * time.Minute
	// maxStreamBody — тело webhook с пакетом записей.
	maxStreamBody = 1 << 20
	// maxStreamAttempts — предел счётчика неудачных попыток (повторы не
	// заканчиваются, задержка — не больше 10 минут).
	maxStreamAttempts = 1_000_000
	// Отставание передачи — условие DM-44: самая старая не переданная
	// запись старше StreamLagAge или не передано больше StreamLagRecords.
	StreamLagAge     = 15 * time.Minute
	StreamLagRecords = 10_000
)

// StreamCursor — курсор передачи журнала в канал.
type StreamCursor struct {
	ChannelID string
	// LastSeq — последняя переданная запись (seq).
	LastSeq int64
	// Attempts — неудачных попыток подряд; Error — код последней ошибки.
	Attempts int
	NextAt   time.Time
	Error    string
	// LagRaised — условие отставания возникло и записано в аудит.
	LagRaised bool
	SentAt    time.Time
	UpdatedAt time.Time
}

// Backlog — не переданная часть журнала.
type Backlog struct {
	// Head — последняя запись журнала (seq).
	Head int64
	// Pending — записей после курсора; Oldest — время самой старой из них
	// (нулевое, если их нет).
	Pending int64
	Oldest  time.Time
}

// lagging — отставание выше порога DM-44.
func (b Backlog) lagging(now time.Time) bool {
	return b.Pending > StreamLagRecords || (!b.Oldest.IsZero() && now.Sub(b.Oldest) > StreamLagAge)
}

// StreamStatus — состояние передачи журнала в канал для API.
type StreamStatus struct {
	// Subscribed — канал подписан на журнал; Active — подписан и включён.
	Subscribed bool
	Active     bool
	Cursor     StreamCursor
	Backlog    Backlog
	// Lagging — отставание выше порога сейчас.
	Lagging bool
}

// streamCode — код условия отставания канала в system.alert.
func streamCode(channelID string) string { return "audit_stream_lag:" + channelID }

// StreamAuditOnce — один проход передачи по всем подписанным каналам;
// возвращает число переданных записей. Ошибка одного канала не мешает
// остальным: ошибка отправки остаётся в его курсоре, ошибка БД
// возвращается вместе с ошибками других каналов. Отставание проверяется
// при любом итоге передачи.
func (s *Service) StreamAuditOnce(ctx context.Context) (int, error) {
	chans, err := s.store.StreamChannels(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	var errs []error
	for _, c := range chans {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		n, err := s.streamChannel(ctx, c)
		total += n
		if err != nil {
			errs = append(errs, err)
		}
		if err := s.checkLag(ctx, c); err != nil {
			errs = append(errs, err)
		}
	}
	return total, errors.Join(errs...)
}

// streamChannel передаёт записи после курсора канала c пакетами.
func (s *Service) streamChannel(ctx context.Context, c Channel) (int, error) {
	sent := 0
	for range streamRounds {
		cur, ok, err := s.store.ClaimStream(ctx, c.ID, streamLease)
		if err != nil || !ok {
			return sent, err
		}
		prev := cur.LastSeq
		recs, err := s.store.AuditAfter(ctx, prev, streamBatch)
		if err != nil {
			return sent, err
		}
		now := s.now().UTC()
		if len(recs) == 0 {
			cur.NextAt, cur.UpdatedAt = now, now
			return sent, s.store.FinishStream(ctx, prev, cur, nil)
		}
		var sendErr error
		n := 0
		sec, err := s.secrets(ctx, c)
		if err != nil {
			sendErr = failed(ErrCodeConfig)
		} else {
			n, sendErr = s.transport.SendAudit(ctx, c, sec, recs)
		}
		if ctx.Err() != nil {
			// Остановка сервера: попытка не засчитывается, повтор после lease.
			return sent, ctx.Err()
		}
		now = s.now().UTC()
		cur.UpdatedAt = now
		if sendErr != nil || n == 0 {
			if sendErr == nil {
				sendErr = failed(ErrCodeInternal)
			}
			cur.Attempts = min(cur.Attempts+1, maxStreamAttempts)
			cur.Error, cur.NextAt = ErrorCode(sendErr), now.Add(Backoff(cur.Attempts))
			return sent, s.store.FinishStream(ctx, prev, cur, nil)
		}
		var gap []audit.Entry
		if first := recs[0].Seq; first != prev+1 {
			// Записи между курсором и первой прочитанной удалены архивацией
			// журнала (aisec-cli audit archive) раньше, чем переданы.
			gap = append(gap, audit.Entry{OrgID: s.orgID, Actor: systemActor, Action: "notify.audit_stream_gap",
				Object: audit.Object{Type: "notify_channel", ID: c.ID}, Result: audit.ResultFailure,
				Details: map[string]any{"channel_name": c.Name, "reason": "archived", "from_seq": prev + 1, "to_seq": first - 1}})
		}
		cur.LastSeq, cur.Attempts, cur.Error, cur.NextAt, cur.SentAt = recs[n-1].Seq, 0, "", now, now
		if err := s.store.FinishStream(ctx, prev, cur, gap); err != nil {
			return sent, err
		}
		sent += n
		if n == len(recs) && len(recs) < streamBatch {
			return sent, nil
		}
	}
	return sent, nil
}

// checkLag переводит отставание передачи в условие DM-44: запись
// system.alert при возникновении и снятии (оповещение поднимает правило
// system.audit_stream_lag в транзакции записи аудита).
func (s *Service) checkLag(ctx context.Context, c Channel) error {
	return s.store.StreamLag(ctx, c.ID, func(cur StreamCursor, b Backlog) (bool, *audit.Entry) {
		now := s.now().UTC()
		lag := b.lagging(now)
		if lag == cur.LagRaised {
			return lag, nil
		}
		state, res := "cleared", audit.ResultSuccess
		if lag {
			state, res = "raised", audit.ResultFailure
		}
		d := map[string]any{"condition": streamCode(c.ID), "state": state, "requirement": "РСБ.6", "channel_name": c.Name,
			"type": c.Type, "pending": b.Pending, "last_seq": cur.LastSeq, "head_seq": b.Head, "error": cur.Error}
		if !b.Oldest.IsZero() {
			d["oldest_pending_seconds"] = int64(now.Sub(b.Oldest) / time.Second)
		}
		return lag, &audit.Entry{OrgID: s.orgID, Actor: systemActor, Action: "system.alert",
			Object: audit.Object{Type: "system", ID: streamCode(c.ID)}, Result: res, Details: d}
	})
}

// lagCleared — снятие условия отставания канала c, когда передача в него
// остановлена (подписка снята, канал отключён) или начата заново: условие
// в журнале аудита не остаётся незакрытым.
func lagCleared(orgID string, c Channel, reason string) audit.Entry {
	return audit.Entry{OrgID: orgID, Actor: systemActor, Action: "system.alert",
		Object: audit.Object{Type: "system", ID: streamCode(c.ID)}, Result: audit.ResultSuccess,
		Details: map[string]any{"condition": streamCode(c.ID), "state": "cleared", "requirement": "РСБ.6",
			"channel_name": c.Name, "type": c.Type, "reason": reason}}
}

// lagReason — причина снятия отставания при изменении канала old → c;
// пусто — снимать не нужно.
func lagReason(old, c Channel) string {
	switch {
	case !c.AuditStream:
		return "stream_disabled"
	case !c.Enabled:
		return "channel_disabled"
	case !old.AuditStream:
		return "stream_restarted"
	}
	return ""
}

// cursorLost — запись о курсоре, созданном заново для давно подписанного
// канала: записи с момента потери курсора не переданы (их можно перенести
// выгрузкой журнала).
func cursorLost(orgID string, c Channel, head int64) audit.Entry {
	return audit.Entry{OrgID: orgID, Actor: systemActor, Action: "notify.audit_stream_gap",
		Object: audit.Object{Type: "notify_channel", ID: c.ID}, Result: audit.ResultFailure,
		Details: map[string]any{"channel_name": c.Name, "reason": "cursor_lost", "to_seq": head}}
}

// StreamStatus — состояние передачи журнала в канал (право
// notify_channels.read).
func (s *Service) StreamStatus(ctx context.Context, id string) (StreamStatus, error) {
	c, err := s.store.Channel(ctx, id)
	if err != nil {
		return StreamStatus{}, err
	}
	st := StreamStatus{Subscribed: c.AuditStream, Active: c.AuditStream && c.Enabled}
	if !c.AuditStream {
		return st, nil
	}
	cur, b, ok, err := s.store.StreamState(ctx, id)
	if err != nil || !ok {
		return st, err
	}
	st.Cursor, st.Backlog, st.Lagging = cur, b, b.lagging(s.now().UTC())
	return st, nil
}

// RunAuditStream передаёт журнал в SIEM каждые interval до отмены ctx.
// Ошибки — в технический журнал без адресов и содержимого записей.
func (s *Service) RunAuditStream(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = StreamInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := s.StreamAuditOnce(ctx); err != nil && ctx.Err() == nil {
			logger.Error("уведомления: передача журнала аудита не выполнена", "class", "notify", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// siemRecord — запись журнала для SIEM: каноническая форма записи
// (audit.Record.Canonical — ровно то, от чего считается хеш, как в архиве
// журнала, ADR-0008) и её хеш. SIEM проверяет запись и цепочку сам:
// hash = H(байты record), record.prev — хеш предыдущей записи, H — хеш
// криптопрофиля (record.alg). Подробностей с секретами и содержимым
// запросов в журнале нет (ТЗ 5.5, РСБ.3), они передаются как записаны.
type siemRecord struct {
	Record json.RawMessage `json:"record"`
	Hash   string          `json:"hash"`
}

func toSIEM(r *audit.Record) (siemRecord, error) {
	if !json.Valid(r.Details) {
		// Запись в БД повреждена: передаётся с пустыми подробностями, хеш
		// не сойдётся — SIEM увидит нарушение, а передача не встанет.
		cp := *r
		cp.Details = json.RawMessage("{}")
		r = &cp
	}
	c, err := r.Canonical()
	if err != nil {
		return siemRecord{}, err
	}
	return siemRecord{Record: c, Hash: hex.EncodeToString(r.Hash)}, nil
}

// siemMessage — тело сообщения syslog (JSON): одна запись.
type siemMessage struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Type    string `json:"type"`
	siemRecord
}

// Серьёзность записи журнала: успех — info, отказ и запрет — warning
// (syslog), CEF — 3 и 6.
func auditSeverity(r *audit.Record) (syslog, cef int) {
	if r.Result == audit.ResultSuccess {
		return 6, 3
	}
	return 4, 6
}

// auditCEF — запись журнала в CEF 0.
func auditCEF(r *audit.Record, version string) []byte {
	h := func(s string) string { return cefHeader.Replace(clean(s)) }
	v := func(s string) string { return cefValue.Replace(clean(s)) }
	_, sev := auditSeverity(r)
	details := string(r.Details)
	if !json.Valid(r.Details) {
		details = "{}"
	}
	var ext []string
	if !r.TS.IsZero() {
		ext = append(ext, "rt="+strconv.FormatInt(r.TS.UnixMilli(), 10))
	}
	ext = append(ext,
		"externalId="+v(r.ID),
		"cat=audit",
		"outcome="+v(string(r.Result)),
		"suid="+v(r.Actor.ID),
		"suser="+v(r.Actor.Name),
		"cs1Label=seq",
		"cs1="+strconv.FormatInt(r.Seq, 10),
		"cs2Label=actorType",
		"cs2="+v(string(r.Actor.Type)),
		"cs3Label=object",
		"cs3="+v(r.Object.Type+":"+r.Object.ID),
		"cs4Label=details",
		"cs4="+v(details),
		"cs5Label=hash",
		"cs5="+v(r.HashAlg)+":"+hex.EncodeToString(r.Hash),
	)
	if r.SourceIP.IsValid() {
		ext = append(ext, "src="+r.SourceIP.String())
	}
	return fmt.Appendf(nil, "CEF:0|AISec|AISec|%s|%s|%s|%d|%s", h(version), h(r.Action), h(r.Action), sev,
		strings.Join(ext, " "))
}

// auditSyslogRecord — запись журнала в RFC 5424 с MSGID audit и временем
// записи журнала.
func auditSyslogRecord(r *audit.Record, s Settings, version string) ([]byte, error) {
	var msg []byte
	if s.Format == FormatCEF {
		msg = auditCEF(r, version)
	} else {
		rec, err := toSIEM(r)
		if err != nil {
			return nil, err
		}
		if msg, err = json.Marshal(siemMessage{Product: "AISec", Version: version, Type: "audit", siemRecord: rec}); err != nil {
			return nil, err
		}
	}
	sev, _ := auditSeverity(r)
	ts := r.TS
	if ts.IsZero() {
		ts = time.Unix(0, 0)
	}
	return syslogFrame(s, sev, ts, "audit", msg), nil
}

// auditBatch — тело webhook с пакетом записей не больше maxStreamBody:
// возвращает тело и число вошедших записей (не меньше одной).
func auditBatch(recs []audit.Record, version string) ([]byte, int, error) {
	v, err := json.Marshal(version)
	if err != nil {
		return nil, 0, err
	}
	body := fmt.Appendf(nil, `{"product":"AISec","version":%s,"type":"audit","records":[`, v)
	n := 0
	for i := range recs {
		rec, err := toSIEM(&recs[i])
		if err != nil {
			return nil, 0, err
		}
		b, err := json.Marshal(rec)
		if err != nil {
			return nil, 0, err
		}
		if n > 0 && len(body)+len(b)+3 > maxStreamBody {
			break
		}
		if n > 0 {
			body = append(body, ',')
		}
		body = append(body, b...)
		n++
	}
	return append(body, "]}"...), n, nil
}
