package notify

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Передача журнала в SIEM на PostgreSQL (миграция 0036_audit_stream).

// headSeqSQL — последняя запись журнала: после архивации журнал может быть
// пуст, тогда — контрольная точка архивации.
const headSeqSQL = `SELECT GREATEST((SELECT COALESCE(max(seq), 0) FROM audit_log),
	(SELECT COALESCE(max(seq), 0) FROM audit_checkpoints))`

// resetCursorTx ставит курсор канала на конец журнала: передача идёт с
// момента подписки (ранние записи — выгрузкой журнала, РСБ.5).
func (s *PGStore) resetCursorTx(ctx context.Context, tx pgx.Tx, channelID string) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_stream_cursors (channel_id, org_id, last_seq, attempts, next_at, error,
			lag_raised, updated_at)
		VALUES ($1, $2, (`+headSeqSQL+`), 0, now(), '', false, now())
		ON CONFLICT (channel_id) DO UPDATE SET last_seq = EXCLUDED.last_seq, attempts = 0, next_at = now(), error = '',
			lag_raised = false, updated_at = now()`, channelID, s.orgID)
	return dbErr(err)
}

// clearLagTx снимает условие отставания канала c, если оно поднято
// (передача остановлена или начата заново), с записью system.alert.
func (s *PGStore) clearLagTx(ctx context.Context, tx pgx.Tx, c Channel, reason string) error {
	tag, err := tx.Exec(ctx, `UPDATE audit_stream_cursors SET lag_raised = false WHERE org_id = $1 AND channel_id = $2 AND lag_raised`,
		s.orgID, c.ID)
	if err != nil {
		return dbErr(err)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	return s.audit.RecordTx(ctx, tx, lagCleared(s.orgID, c, reason))
}

// StreamChannels — см. Store. Подписанному каналу без курсора (каналы
// восстановлены без таблицы курсоров) курсор ставится на конец журнала.
func (s *PGStore) StreamChannels(ctx context.Context) ([]Channel, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	if err := s.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `INSERT INTO audit_stream_cursors (channel_id, org_id, last_seq, attempts, next_at, error,
				lag_raised, updated_at)
			SELECT c.id, c.org_id, (`+headSeqSQL+`), 0, now(), '', false, now() FROM notify_channels c
			WHERE c.org_id = $1 AND c.audit_stream AND NOT EXISTS (SELECT 1 FROM audit_stream_cursors k WHERE k.channel_id = c.id)
			ON CONFLICT (channel_id) DO NOTHING
			RETURNING channel_id::text, last_seq`, s.orgID)
		if err != nil {
			return dbErr(err)
		}
		type lost struct {
			id   string
			head int64
		}
		found, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (lost, error) {
			var l lost
			return l, r.Scan(&l.id, &l.head)
		})
		if err != nil {
			return dbErr(err)
		}
		for _, l := range found {
			c, err := scanChannel(tx.QueryRow(ctx, `SELECT `+channelCols+` FROM notify_channels WHERE org_id = $1 AND id = $2`,
				s.orgID, l.id))
			if err != nil {
				return err
			}
			if err := s.audit.RecordTx(ctx, tx, cursorLost(s.orgID, c, l.head)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT `+channelCols+` FROM notify_channels WHERE org_id = $1 AND enabled AND audit_stream
		ORDER BY created_at, id LIMIT $2`, s.orgID, MaxChannels)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const cursorCols = `channel_id::text, last_seq, attempts, next_at, error, lag_raised, sent_at, updated_at`

func scanCursor(row pgx.Row) (StreamCursor, error) {
	var c StreamCursor
	var sent *time.Time
	err := row.Scan(&c.ChannelID, &c.LastSeq, &c.Attempts, &c.NextAt, &c.Error, &c.LagRaised, &sent, &c.UpdatedAt)
	if sent != nil {
		c.SentAt = *sent
	}
	return c, err
}

// ClaimStream — см. Store. Курсор берёт один экземпляр сервера: срок
// next_at сдвигается на lease той же командой.
func (s *PGStore) ClaimStream(ctx context.Context, channelID string, lease time.Duration) (StreamCursor, bool, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	c, err := scanCursor(s.db.QueryRow(ctx, `UPDATE audit_stream_cursors k SET next_at = now() + make_interval(secs => $3)
		WHERE k.org_id = $1 AND k.channel_id = $2 AND k.next_at <= now()
			AND EXISTS (SELECT 1 FROM notify_channels c WHERE c.id = k.channel_id AND c.enabled AND c.audit_stream)
		RETURNING `+cursorCols, s.orgID, channelID, lease.Seconds()))
	if errors.Is(err, pgx.ErrNoRows) {
		return StreamCursor{}, false, nil
	}
	if err != nil {
		return StreamCursor{}, false, dbErr(err)
	}
	return c, true, nil
}

// AuditAfter — см. Store. Порядок seq совпадает с порядком фиксации: записи
// встраиваются в цепочку под общей блокировкой (internal/audit).
func (s *PGStore) AuditAfter(ctx context.Context, after int64, limit int) ([]audit.Record, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT seq, id::text, org_id::text, CASE WHEN isfinite(ts) THEN ts END, actor_type, actor_id,
		actor_name, host(source_ip), action, object_type, object_id, result, details::text, hash_alg, prev_hash, hash
		FROM audit_log WHERE seq > $1 ORDER BY seq LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (audit.Record, error) {
		var r audit.Record
		var ts *time.Time
		var ip *string
		var actorType, result, details string
		if err := row.Scan(&r.Seq, &r.ID, &r.OrgID, &ts, &actorType, &r.Actor.ID, &r.Actor.Name, &ip, &r.Action,
			&r.Object.Type, &r.Object.ID, &result, &details, &r.HashAlg, &r.PrevHash, &r.Hash); err != nil {
			return r, err
		}
		if ts != nil {
			r.TS = ts.UTC()
		}
		if ip != nil {
			if a, err := netip.ParseAddr(*ip); err == nil {
				r.SourceIP = a
			}
		}
		r.Actor.Type, r.Result, r.Details = audit.ActorType(actorType), audit.Result(result), []byte(details)
		return r, nil
	})
}

// FinishStream — см. Store.
func (s *PGStore) FinishStream(ctx context.Context, prevSeq int64, c StreamCursor, recs []audit.Entry) error {
	var sent *time.Time
	if !c.SentAt.IsZero() {
		sent = &c.SentAt
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		// Срок следующей попытки — по часам БД, как и выборка в ClaimStream:
		// расхождение часов экземпляров сервера не сдвигает повторы.
		tag, err := tx.Exec(ctx, `UPDATE audit_stream_cursors SET last_seq = $4, attempts = $5,
			next_at = now() + make_interval(secs => $6), error = $7, sent_at = COALESCE($8, sent_at), updated_at = $9
			WHERE org_id = $1 AND channel_id = $2 AND last_seq = $3`,
			s.orgID, c.ChannelID, prevSeq, c.LastSeq, c.Attempts, max(c.NextAt.Sub(c.UpdatedAt), 0).Seconds(), c.Error, sent, c.UpdatedAt)
		if err != nil {
			return dbErr(err)
		}
		if tag.RowsAffected() != 1 {
			// Курсор сдвинул другой экземпляр после истечения lease или
			// подписку сбросили: итог этой попытки не сохраняется.
			return nil
		}
		for _, r := range recs {
			if err := s.audit.RecordTx(ctx, tx, r); err != nil {
				return err
			}
		}
		return nil
	})
}

// backlogTx — не переданная часть журнала после seq.
func backlogTx(ctx context.Context, q pgx.Tx, after int64) (Backlog, error) {
	var b Backlog
	var oldest *time.Time
	err := q.QueryRow(ctx, `SELECT (`+headSeqSQL+`), (SELECT CASE WHEN isfinite(ts) THEN ts END FROM audit_log
		WHERE seq > $1 ORDER BY seq LIMIT 1)`, after).Scan(&b.Head, &oldest)
	if err != nil {
		return b, err
	}
	if oldest != nil {
		b.Oldest = oldest.UTC()
	}
	if b.Head > after {
		b.Pending = b.Head - after
	}
	return b, nil
}

// StreamLag — см. Store. Курсор, занятый другим экземпляром, пропускается.
func (s *PGStore) StreamLag(ctx context.Context, channelID string, fn func(StreamCursor, Backlog) (bool, *audit.Entry)) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		c, err := scanCursor(tx.QueryRow(ctx, `SELECT `+cursorCols+` FROM audit_stream_cursors
			WHERE org_id = $1 AND channel_id = $2 FOR UPDATE SKIP LOCKED`, s.orgID, channelID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		b, err := backlogTx(ctx, tx, c.LastSeq)
		if err != nil {
			return err
		}
		lag, rec := fn(c, b)
		if lag == c.LagRaised {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE audit_stream_cursors SET lag_raised = $3 WHERE org_id = $1 AND channel_id = $2`,
			s.orgID, channelID, lag); err != nil {
			return dbErr(err)
		}
		if rec == nil {
			return nil
		}
		return s.audit.RecordTx(ctx, tx, *rec)
	})
}

// StreamState — см. Store.
func (s *PGStore) StreamState(ctx context.Context, channelID string) (StreamCursor, Backlog, bool, error) {
	var c StreamCursor
	var b Backlog
	found := false
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		c, err = scanCursor(tx.QueryRow(ctx, `SELECT `+cursorCols+` FROM audit_stream_cursors WHERE org_id = $1 AND channel_id = $2`,
			s.orgID, channelID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		b, err = backlogTx(ctx, tx, c.LastSeq)
		return err
	})
	return c, b, found, err
}
