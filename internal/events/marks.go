package events

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Отметки аналитиков (ТЗ 5.5; задача 3.22 этапа 3): «ложное срабатывание»
// или «подтверждено» с комментарием. Событие неизменяемо, поэтому отметка
// хранится отдельно (таблица event_marks, одна на событие: новая заменяет
// прежнюю) и каждая её смена — запись в журнал аудита той же транзакцией.
// Содержимое запроса в отметку не копируется.

// Значения отметки.
const (
	MarkFalsePositive = "false_positive"
	MarkConfirmed     = "confirmed"
	// MarkNone — значение фильтра «без отметки».
	MarkNone = "none"
)

// MaxMarkComment — символов в комментарии к отметке.
const MaxMarkComment = 1000

// Действия журнала аудита для отметок.
const (
	ActionMarkSet     = "events.mark_set"
	ActionMarkRemoved = "events.mark_removed"
)

// Ошибки отметок.
var (
	// ErrBadMark — неизвестная отметка или неверный комментарий.
	ErrBadMark = errors.New("отметка события: значение false_positive или confirmed, комментарий до 1000 символов")
	// ErrNoMark — у события нет отметки.
	ErrNoMark = errors.New("у события нет отметки")
)

// Mark — отметка события.
type Mark struct {
	Mark    string    `json:"mark"`
	Comment string    `json:"comment,omitempty"`
	At      time.Time `json:"marked_at"`
	// By — субъект (тип:ID), ByName — его имя на момент отметки.
	By     string `json:"marked_by"`
	ByName string `json:"marked_by_name,omitempty"`
}

// CleanMark проверяет отметку и комментарий: пробелы по краям убираются,
// переводы строки допустимы, прочие управляющие символы и символы
// форматирования — нет.
func CleanMark(mark, comment string) (string, string, error) {
	if mark != MarkFalsePositive && mark != MarkConfirmed {
		return "", "", ErrBadMark
	}
	comment = strings.TrimSpace(comment)
	if !utf8.ValidString(comment) || utf8.RuneCountInString(comment) > MaxMarkComment ||
		strings.ContainsFunc(comment, func(r rune) bool { return r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) }) {
		return "", "", ErrBadMark
	}
	return mark, comment, nil
}

// MarkStore — отметки событий.
type MarkStore interface {
	// SetMark ставит отметку m событию id и той же транзакцией пишет
	// events.mark_set; возвращает прежнюю отметку (nil — не было).
	// ErrNotFound — события нет.
	SetMark(ctx context.Context, id string, m Mark, by audit.Actor, ip netip.Addr) (*Mark, error)
	// DeleteMark снимает отметку (events.mark_removed); ErrNotFound —
	// события нет, ErrNoMark — отметки нет.
	DeleteMark(ctx context.Context, id string, by audit.Actor, ip netip.Addr) error
}

// markRef — ссылка на субъекта в marked_by (как created_by политик).
func markRef(a audit.Actor) string {
	s := string(a.Type) + ":" + a.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func markName(a audit.Actor) string {
	n := a.Name
	for utf8.RuneCountInString(n) > 128 {
		_, size := utf8.DecodeLastRuneInString(n)
		n = n[:len(n)-size]
	}
	return n
}

// markAudit — запись об отметке: значение и прежнее значение, без
// комментария (аналитик мог вставить в него фрагмент запроса).
func markAudit(orgID, id, action, mark string, prev *Mark, comment string, by audit.Actor, ip netip.Addr) audit.Entry {
	d := map[string]any{"mark": mark, "comment_chars": utf8.RuneCountInString(comment)}
	if prev != nil {
		d["previous"] = prev.Mark
	}
	return audit.Entry{OrgID: orgID, Actor: by, SourceIP: ip, Action: action, Object: audit.Object{Type: "event", ID: id},
		Result: audit.ResultSuccess, Details: d}
}

// SetMark — см. MarkStore.
func (s *PGStore) SetMark(ctx context.Context, id string, m Mark, by audit.Actor, ip netip.Addr) (*Mark, error) {
	mark, comment, err := CleanMark(m.Mark, m.Comment)
	if err != nil {
		return nil, err
	}
	ts, err := PartitionTime(id)
	if err != nil {
		return nil, ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var prev *Mark
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var one int
		err := tx.QueryRow(ctx, "SELECT 1 FROM events WHERE id = $1 AND ts = $2 AND org_id = $3", id, ts, s.orgID).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return dbError("отметка события", err)
		}
		// FOR UPDATE не блокирует ещё не созданную строку: две первые отметки
		// одного события упорядочиваются блокировкой транзакции по его ID,
		// чтобы вторая увидела первую в previous.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('event_mark:' || $1, 0))", id); err != nil {
			return dbError("отметка события", err)
		}
		var p Mark
		err = tx.QueryRow(ctx, `SELECT mark, comment, marked_at, marked_by, marked_by_name FROM event_marks
			WHERE event_id = $1 AND event_ts = $2 AND org_id = $3 FOR UPDATE`, id, ts, s.orgID).
			Scan(&p.Mark, &p.Comment, &p.At, &p.By, &p.ByName)
		switch {
		case err == nil:
			p.At = p.At.UTC()
			prev = &p
		case !errors.Is(err, pgx.ErrNoRows):
			return dbError("отметка события", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO event_marks (event_id, event_ts, org_id, mark, comment, marked_at, marked_by, marked_by_name)
			VALUES ($1, $2, $3, $4, $5, now(), $6, $7)
			ON CONFLICT (event_id, event_ts) DO UPDATE SET mark = EXCLUDED.mark, comment = EXCLUDED.comment,
				marked_at = EXCLUDED.marked_at, marked_by = EXCLUDED.marked_by, marked_by_name = EXCLUDED.marked_by_name`,
			id, ts, s.orgID, mark, comment, markRef(by), markName(by)); err != nil {
			return dbError("отметка события", err)
		}
		return s.audit.RecordTx(ctx, tx, markAudit(s.orgID, id, ActionMarkSet, mark, prev, comment, by, ip))
	})
	if err != nil {
		return nil, err
	}
	return prev, nil
}

// DeleteMark — см. MarkStore.
func (s *PGStore) DeleteMark(ctx context.Context, id string, by audit.Actor, ip netip.Addr) error {
	ts, err := PartitionTime(id)
	if err != nil {
		return ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var one int
		err := tx.QueryRow(ctx, "SELECT 1 FROM events WHERE id = $1 AND ts = $2 AND org_id = $3", id, ts, s.orgID).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return dbError("отметка события", err)
		}
		var p Mark
		err = tx.QueryRow(ctx, `DELETE FROM event_marks WHERE event_id = $1 AND event_ts = $2 AND org_id = $3
			RETURNING mark, comment`, id, ts, s.orgID).Scan(&p.Mark, &p.Comment)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoMark
		}
		if err != nil {
			return dbError("отметка события", err)
		}
		return s.audit.RecordTx(ctx, tx, markAudit(s.orgID, id, ActionMarkRemoved, p.Mark, &p, "", by, ip))
	})
}

// dropOrphanMarks удаляет отметки событий, секции которых удалены по сроку
// хранения (вызывается в транзакции DropExpired). Срок метаданных — не
// меньше MinMetadataDays, поэтому более свежие отметки не просматриваются.
func dropOrphanMarks(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `DELETE FROM event_marks m
		WHERE m.event_ts < now() - make_interval(days => $1)
		  AND NOT EXISTS (SELECT 1 FROM events e WHERE e.id = m.event_id AND e.ts = m.event_ts)`, MinMetadataDays-1); err != nil {
		return fmt.Errorf("отметки удалённых событий: %w", err)
	}
	return nil
}

// SetMark — см. MarkStore (Memory: запись аудита — через SetRetentionAudit,
// без приёмника отметка не ставится).
func (m *Memory) SetMark(_ context.Context, id string, mk Mark, by audit.Actor, ip netip.Addr) (*Mark, error) {
	mark, comment, err := CleanMark(mk.Mark, mk.Comment)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return nil, m.ReadErr
	}
	if _, ok := m.events[id]; !ok {
		return nil, ErrNotFound
	}
	if m.auditFn == nil {
		return nil, errors.New("хранилище событий в памяти: нет приёмника аудита")
	}
	var prev *Mark
	if p, ok := m.marks[id]; ok {
		prev = &p
	}
	if err := m.auditFn(markAudit("", id, ActionMarkSet, mark, prev, comment, by, ip)); err != nil {
		return nil, err
	}
	if m.marks == nil {
		m.marks = map[string]Mark{}
	}
	m.marks[id] = Mark{Mark: mark, Comment: comment, At: time.Now().UTC().Truncate(time.Microsecond), By: markRef(by), ByName: markName(by)}
	return prev, nil
}

// DeleteMark — см. MarkStore.
func (m *Memory) DeleteMark(_ context.Context, id string, by audit.Actor, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return m.ReadErr
	}
	if _, ok := m.events[id]; !ok {
		return ErrNotFound
	}
	p, ok := m.marks[id]
	if !ok {
		return ErrNoMark
	}
	if m.auditFn == nil {
		return errors.New("хранилище событий в памяти: нет приёмника аудита")
	}
	if err := m.auditFn(markAudit("", id, ActionMarkRemoved, p.Mark, &p, "", by, ip)); err != nil {
		return err
	}
	delete(m.marks, id)
	return nil
}

// markOf — отметка события в Memory (вызывать под m.mu).
func (m *Memory) markOf(id string) *Mark {
	if p, ok := m.marks[id]; ok {
		return &p
	}
	return nil
}
