package events

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/detect/session"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// history.integrity (ТЗ 5.16 DM-03; задача 4.14 этапа 4, миграция
// 0052_session_replies). Шлюз в событии хода с правилом history.integrity
// передаёт хеши реплик ассистента из истории запроса (Session.History) и
// хеши ответов, выданных приложению (Session.Issued). Сервер при приёме —
// до записи события — сверяет историю с ответами, которые шлюз выдал в
// этой сессии раньше: реплика, которой среди них нет, — подмена истории
// (находка history.forged, угроза DM-03, шаг трассировки, действие и
// серьёзность правила). Ответ приложению к этому времени уже отдан:
// проверка его не задерживает и не блокирует, итог — находка в событии и
// оповещение по встроенному правилу.
//
// В первом ходе, который сервер видит в сессии, реплики истории
// принимаются как известные: сессия могла начаться до включения правила,
// до перезапуска шлюза (новый случайный ключ сессий) или раньше срока
// хранения. Хеши хранятся 7 суток с последнего упоминания: реплики,
// которые повторяются в истории, срок продлевают.

// Срок хранения хешей сессий и частота очистки.
const (
	HistoryRetention = 7 * 24 * time.Hour
	historyPruneEach = time.Hour
	historyPruneRows = 10_000
	// historyPruneBatches — пачек на таблицу за одну очистку: до 1 млн строк
	// в час; остаток удаляет следующая очистка.
	historyPruneBatches = 100
)

// Источники хеша в session_replies.
const (
	replyIssued  = "issued"
	replyHistory = "history"
)

// historyStore — хранение хешей сессий: PostgreSQL (pgHistory) или память.
type historyStore interface {
	// seen отмечает ход сессии; first — сессия впервые.
	seen(ctx context.Context, app, sess string, at time.Time) (first bool, err error)
	// known — какие из hashes есть в сессии; найденным продлевает срок.
	known(ctx context.Context, app, sess string, hashes []string, at time.Time) (map[string]bool, error)
	// remember добавляет хеши сессии.
	remember(ctx context.Context, app, sess string, hashes []string, source string, at time.Time) error
}

// checkHistory проверяет историю событий пакета по порядку: ответ,
// выданный в событии пакета, известен следующим событиям той же сессии.
func checkHistory(ctx context.Context, st historyStore, evs []Event, now time.Time) error {
	for i := range evs {
		e := &evs[i]
		s := e.Session
		if e.Type != TypeGatewayRequest || s == nil || s.HistoryRule == "" {
			continue
		}
		first, err := st.seen(ctx, e.App, s.ID, now)
		if err != nil {
			return err
		}
		hashes := make([]string, 0, len(s.History))
		for _, r := range s.History {
			if !slices.Contains(hashes, r.Hash) {
				hashes = append(hashes, r.Hash)
			}
		}
		switch {
		case first:
			if err := st.remember(ctx, e.App, s.ID, hashes, replyHistory, now); err != nil {
				return err
			}
		case len(hashes) > 0:
			known, err := st.known(ctx, e.App, s.ID, hashes, now)
			if err != nil {
				return err
			}
			var forged []Reply
			for _, r := range s.History {
				if !known[r.Hash] {
					forged = append(forged, r)
				}
			}
			if len(forged) > 0 {
				markForged(e, forged)
			}
		}
		if err := st.remember(ctx, e.App, s.ID, s.Issued, replyIssued, now); err != nil {
			return err
		}
	}
	return nil
}

// markForged добавляет в событие находки подмены истории, угрозу DM-03,
// шаг трассировки и при необходимости усиливает итог решения правилом
// history.integrity (allow → log), не превышая пределов события.
func markForged(e *Event, forged []Reply) {
	s := e.Session
	for _, r := range forged {
		if len(e.Findings) >= maxFindings {
			break
		}
		e.Findings = append(e.Findings, Finding{Detector: session.HistoryID, Version: session.HistoryVersion,
			Category: session.CatHistoryForged, Score: 1, Location: "messages[" + strconv.Itoa(r.Message) + "].content",
			Threat: session.ThreatHistory, Source: "user"})
	}
	if !slices.Contains(e.Threats, session.ThreatHistory) && len(e.Threats) < maxThreats {
		e.Threats = append(e.Threats, session.ThreatHistory)
	}
	d := e.Decision
	if d == nil {
		return
	}
	d.Trace = append(d.Trace, TraceStep{Rule: s.HistoryRule, Detector: session.HistoryID, Matched: true, Action: s.HistoryAction,
		Note: fmt.Sprintf("реплик ассистента, которых шлюз не выдавал в этой сессии: %d", len(forged))})
	if policy.Stronger(policy.Action(s.HistoryAction), policy.Action(d.Action)) {
		d.Action, d.Rule = s.HistoryAction, s.HistoryRule
	}
	if policy.SeverityAbove(policy.Severity(s.HistorySeverity), policy.Severity(d.Severity)) {
		d.Severity = s.HistorySeverity
	}
}

// pgHistory — хеши сессий в транзакции приёма.
type pgHistory struct {
	tx    pgx.Tx
	orgID string
}

func (h pgHistory) seen(ctx context.Context, app, sess string, at time.Time) (bool, error) {
	tag, err := h.tx.Exec(ctx, `INSERT INTO session_history (org_id, app, session, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $4) ON CONFLICT (org_id, app, session) DO NOTHING`, h.orgID, app, sess, at)
	if err != nil {
		return false, dbError("история сессии", err)
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	if _, err := h.tx.Exec(ctx, `UPDATE session_history SET last_seen = $4 WHERE org_id = $1 AND app = $2 AND session = $3`,
		h.orgID, app, sess, at); err != nil {
		return false, dbError("история сессии", err)
	}
	return false, nil
}

func (h pgHistory) known(ctx context.Context, app, sess string, hashes []string, at time.Time) (map[string]bool, error) {
	rows, err := h.tx.Query(ctx, `UPDATE session_replies SET seen_at = $5
		WHERE org_id = $1 AND app = $2 AND session = $3 AND hash = ANY($4) RETURNING hash`, h.orgID, app, sess, hashes, at)
	if err != nil {
		return nil, dbError("история сессии", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, dbError("история сессии", err)
		}
		out[hash] = true
	}
	return out, rows.Err()
}

func (h pgHistory) remember(ctx context.Context, app, sess string, hashes []string, source string, at time.Time) error {
	if len(hashes) == 0 {
		return nil
	}
	if _, err := h.tx.Exec(ctx, `INSERT INTO session_replies (org_id, app, session, hash, source, seen_at)
		SELECT $1, $2, $3, h, $5, $6 FROM unnest($4::text[]) AS h
		ON CONFLICT (org_id, app, session, hash) DO UPDATE SET seen_at = EXCLUDED.seen_at`,
		h.orgID, app, sess, hashes, source, at); err != nil {
		return dbError("история сессии", err)
	}
	return nil
}

// hasHistory — в пакете есть ход с правилом history.integrity.
func hasHistory(evs []Event) bool {
	return slices.ContainsFunc(evs, func(e Event) bool { return e.Session != nil && e.Session.HistoryRule != "" })
}

// checkHistory — проверка истории пакета до записи событий (отдельная
// транзакция: при повторе пакета хеши уже записаны, и результат тот же) и
// очистка хешей старше срока не чаще раза в час.
func (s *PGStore) checkHistory(ctx context.Context, in Ingest) error {
	if !hasHistory(in.Events) {
		return nil
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
			return dbError("история сессии", err)
		}
		if err := checkHistory(ctx, pgHistory{tx: tx, orgID: s.orgID}, in.Events, now); err != nil {
			return err
		}
		return s.pruneHistory(ctx, tx, now)
	})
}

// pruneHistory удаляет сессии и хеши без упоминаний дольше
// HistoryRetention не чаще раза в historyPruneEach: пачками по
// historyPruneRows, пока пачка полная, но не больше historyPruneBatches
// пачек на таблицу.
func (s *PGStore) pruneHistory(ctx context.Context, tx pgx.Tx, now time.Time) error {
	last := s.historyPrunedAt.Load()
	if now.Unix()-last < int64(historyPruneEach/time.Second) || !s.historyPrunedAt.CompareAndSwap(last, now.Unix()) {
		return nil
	}
	cutoff := now.Add(-HistoryRetention)
	for _, q := range []string{
		`DELETE FROM session_replies WHERE ctid = ANY (ARRAY(
			SELECT ctid FROM session_replies WHERE org_id = $1 AND seen_at < $2 LIMIT $3))`,
		`DELETE FROM session_history WHERE ctid = ANY (ARRAY(
			SELECT ctid FROM session_history WHERE org_id = $1 AND last_seen < $2 LIMIT $3))`,
	} {
		for range historyPruneBatches {
			tag, err := tx.Exec(ctx, q, s.orgID, cutoff, historyPruneRows)
			if err != nil {
				return dbError("срок хранения истории сессий", err)
			}
			if tag.RowsAffected() < historyPruneRows {
				break
			}
		}
	}
	return nil
}

// memHistory — хеши сессий в памяти (Memory).
type memHistory struct {
	sessions map[string]time.Time
	replies  map[string]time.Time
}

func newMemHistory() *memHistory {
	return &memHistory{sessions: map[string]time.Time{}, replies: map[string]time.Time{}}
}

func (h *memHistory) seen(_ context.Context, app, sess string, at time.Time) (bool, error) {
	k := app + "\x00" + sess
	_, ok := h.sessions[k]
	h.sessions[k] = at
	return !ok, nil
}

func (h *memHistory) known(_ context.Context, app, sess string, hashes []string, at time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	for _, x := range hashes {
		k := app + "\x00" + sess + "\x00" + x
		if _, ok := h.replies[k]; ok {
			h.replies[k], out[x] = at, true
		}
	}
	return out, nil
}

func (h *memHistory) remember(_ context.Context, app, sess string, hashes []string, _ string, at time.Time) error {
	for _, x := range hashes {
		h.replies[app+"\x00"+sess+"\x00"+x] = at
	}
	return nil
}
