package audit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

const (
	// archiveTimeout — предел всей процедуры архивации (одна транзакция).
	archiveTimeout = 10 * time.Minute
	// archiveLockID — две архивации одновременно не идут.
	archiveLockID = 0x41524348 // "ARCH"
	// archiverRole — роль СУБД процедуры архивации (0002_audit, 0005_audit_archive).
	archiverRole = "aisec_audit_archiver"
)

// ErrNothingToArchive — нет записей старше границы после последней точки.
var ErrNothingToArchive = errors.New("нет записей журнала аудита старше границы архивации")

// ArchiveSink — файл архива: запись и сброс на диск до фиксации удаления.
type ArchiveSink interface {
	io.Writer
	Sync() error
}

// ArchiveOptions — параметры архивации.
type ArchiveOptions struct {
	// Before сдвигает границу в прошлое; граница не бывает ближе срока
	// хранения (РСБ.3). Нулевое значение — граница по сроку хранения.
	Before time.Time
	Out    ArchiveSink
	// ArchiveName — имя файла архива для точки и журнала.
	ArchiveName string
	// Signer — ключ подписи контрольных точек: действующий по расписанию
	// (audit-signing.key или ключ последней смены, ADR-0018, п. 5).
	Signer crypto.Signer
	// Verifier — открытый ключ-якорь audit-signing.pub: от него строится
	// расписание, по которому проверяются прежние точки.
	Verifier crypto.Verifier
	By       Actor
}

// ArchiveResult — итог архивации. Checkpoint заполнен, как только точка
// подписана: при ошибке фиксации по нему проверяют, записана ли она.
type ArchiveResult struct {
	Checkpoint *Checkpoint
	Cutoff     time.Time
}

// Archive выгружает записи старше срока хранения в файл с подписанной
// контрольной точкой и удаляет их (РСБ.4, ADR-0008). Всё — одной
// транзакцией под ролью aisec_audit_archiver: точка, удаление и запись
// audit.archive фиксируются вместе. Файл записывается и сбрасывается на диск
// до удаления; при ошибке вызывающий удаляет его, если точка не записана.
// Перед вызовом цепочку нужно проверить (Verifier): при записи архива она
// проверяется ещё раз, и нарушение отменяет архивацию.
func (l *Log) Archive(ctx context.Context, opt ArchiveOptions) (*ArchiveResult, error) {
	if opt.Out == nil || opt.Signer == nil || opt.Verifier == nil || opt.ArchiveName == "" {
		return nil, errors.New("архивация: нет файла, имени или ключей подписи")
	}
	ctx, cancel := withTimeout(ctx, archiveTimeout)
	defer cancel()
	res := &ArchiveResult{}
	err := l.inTx(ctx, func(tx pgx.Tx) error {
		// Роль задаётся константой: идентификатор не параметризуется в SQL.
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+archiverRole); err != nil {
			return fmt.Errorf("архивация: роль %s (логину нужно членство в ней): %w", archiverRole, err)
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", archiveLockID); err != nil {
			return fmt.Errorf("архивация: блокировка: %w", err)
		}
		return l.archiveTx(ctx, tx, &opt, res)
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

func (l *Log) archiveTx(ctx context.Context, tx pgx.Tx, opt *ArchiveOptions, res *ArchiveResult) error {
	cps, err := loadCheckpoints(ctx, tx)
	if err != nil {
		return err
	}
	keys, err := LoadKeySchedule(ctx, tx, l.provider, opt.Verifier)
	if err != nil {
		return err
	}
	if !crypto.Equal(opt.Signer.PublicKey(), keys.Latest().PublicKey()) {
		return errors.New("архивация: ключ подписи — не действующий ключ аудита по расписанию смен")
	}
	anchor, err := VerifyCheckpoints(l.hasher, keys, cps)
	if err != nil {
		return err
	}
	now := l.now().UTC().Truncate(time.Microsecond)
	days := DefaultRetentionDays
	err = tx.QueryRow(ctx, "SELECT retention_days FROM audit_settings WHERE org_id = $1", DefaultOrgID).Scan(&days)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("архивация: срок хранения: %w", err)
	}
	cutoff := now.AddDate(0, 0, -days)
	if !opt.Before.IsZero() && opt.Before.Before(cutoff) {
		cutoff = opt.Before.UTC()
	}
	res.Cutoff = cutoff
	// Архивируется только непрерывное начало цепочки: до первой записи не
	// старше границы. Последняя запись журнала не архивируется никогда —
	// хранимая часть не бывает пустой (её начало видно по самой цепочке).
	var first, last *int64
	if err := tx.QueryRow(ctx, "SELECT min(seq) FILTER (WHERE ts >= $1), max(seq) FROM audit_log", cutoff).
		Scan(&first, &last); err != nil {
		return fmt.Errorf("архивация: граница: %w", err)
	}
	if last == nil {
		return ErrNothingToArchive
	}
	upTo := *last - 1
	if first != nil && *first-1 < upTo {
		upTo = *first - 1
	}
	if upTo <= anchor.Seq {
		return ErrNothingToArchive
	}

	fw := newFileWriter(opt.Out, l.hasher)
	if err := fw.line(fileHeader{
		Format: archiveFormat, V: formatVersion, OrgID: DefaultOrgID, HashAlg: l.hasher.Name(),
		PrevSeq: anchor.Seq, PrevHash: hex.EncodeToString(anchor.Hash), FromSeq: anchor.Seq + 1, ToSeq: upTo,
		CreatedAt: now.Format(tsLayout),
	}, true); err != nil {
		return fmt.Errorf("архивация: запись файла: %w", err)
	}
	c := newChain(l.hasher, anchor, nil)
	if err := readRange(ctx, tx, anchor.Seq, upTo, time.Time{}, time.Time{}, func(r *Record) error {
		if b := c.add(r); b != nil {
			return fmt.Errorf("архивация отменена: %w", b)
		}
		return fw.line(toFileRecord(r), true)
	}); err != nil {
		return err
	}
	if want := upTo - anchor.Seq; c.checked != want {
		return fmt.Errorf("архивация отменена: прочитано %d записей из %d", c.checked, want)
	}
	id, err := store.NewUUIDv7(now, l.random)
	if err != nil {
		return err
	}
	head := c.head()
	cp := &Checkpoint{
		ID: string(id), OrgID: DefaultOrgID, Seq: head.Seq, Hash: head.Hash, HashAlg: l.hasher.Name(),
		PrevSeq: anchor.Seq, PrevHash: anchor.Hash, Records: c.checked,
		ArchiveName: opt.ArchiveName, ArchiveHash: fw.bodyHash(), CreatedAt: now,
	}
	if err := cp.Sign(opt.Signer); err != nil {
		return err
	}
	res.Checkpoint = cp
	if err := fw.line(fileTrailer{Checkpoint: cp.payload(), SigAlg: cp.SigAlg, Signature: cp.Signature, PublicKey: cp.PublicKey}, false); err != nil {
		return fmt.Errorf("архивация: запись файла: %w", err)
	}
	if err := fw.flush(); err != nil {
		return fmt.Errorf("архивация: запись файла: %w", err)
	}
	if err := opt.Out.Sync(); err != nil {
		return fmt.Errorf("архивация: сброс файла на диск: %w", err)
	}

	if _, err := tx.Exec(ctx, `INSERT INTO audit_checkpoints
		(id, org_id, seq, hash, hash_alg, prev_seq, prev_hash, records, archive_name, archive_hash,
		 created_at, sig_alg, signature, public_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		cp.ID, cp.OrgID, cp.Seq, cp.Hash, cp.HashAlg, cp.PrevSeq, cp.PrevHash, cp.Records, cp.ArchiveName,
		cp.ArchiveHash, cp.CreatedAt, cp.SigAlg, cp.Signature, cp.PublicKey); err != nil {
		return fmt.Errorf("архивация: запись контрольной точки: %w", err)
	}
	tag, err := tx.Exec(ctx, "DELETE FROM audit_log WHERE seq > $1 AND seq <= $2", anchor.Seq, cp.Seq)
	if err != nil {
		return fmt.Errorf("архивация: удаление записей: %w", err)
	}
	if tag.RowsAffected() != cp.Records {
		return fmt.Errorf("архивация отменена: удалено %d записей из %d", tag.RowsAffected(), cp.Records)
	}
	_, err = l.recordTx(ctx, tx, Entry{
		Actor: opt.By, Action: "audit.archive", Object: Object{Type: "audit_checkpoint", ID: cp.ID}, Result: ResultSuccess,
		Details: map[string]any{
			"from_seq": cp.PrevSeq + 1, "to_seq": cp.Seq, "records": cp.Records,
			"archive_name": cp.ArchiveName, "archive_hash": hex.EncodeToString(cp.ArchiveHash),
			"cutoff": cutoff.Format(time.RFC3339),
		},
	})
	return err
}

// readRange читает записи с номерами (after, upTo] (upTo = 0 — без верхней
// границы) и, если заданы, временем [from, to) пачками по verifyBatch.
func readRange(ctx context.Context, q querier, after, upTo int64, from, to time.Time, fn func(*Record) error) error {
	var fromArg, toArg *time.Time
	if !from.IsZero() {
		fromArg = &from
	}
	if !to.IsZero() {
		toArg = &to
	}
	var upArg *int64
	if upTo > 0 {
		upArg = &upTo
	}
	cursor := after
	for {
		n, last, err := readRangeBatch(ctx, q, cursor, upArg, fromArg, toArg, fn)
		if err != nil {
			return err
		}
		if n < verifyBatch {
			return nil
		}
		cursor = last
	}
}

func readRangeBatch(ctx context.Context, q querier, after int64, upTo *int64, from, to *time.Time, fn func(*Record) error) (int, int64, error) {
	bctx, cancel := withTimeout(ctx, batchTimeout)
	defer cancel()
	rows, err := q.Query(bctx, `SELECT seq, id::text, org_id::text,
		CASE WHEN isfinite(ts) THEN ts END, actor_type, actor_id, actor_name,
		host(source_ip), action, object_type, object_id, result, details::text, hash_alg, prev_hash, hash
		FROM audit_log
		WHERE seq > $1 AND ($2::bigint IS NULL OR seq <= $2)
		  AND ($3::timestamptz IS NULL OR ts >= $3) AND ($4::timestamptz IS NULL OR ts < $4)
		ORDER BY seq LIMIT $5`, after, upTo, from, to, verifyBatch)
	if err != nil {
		return 0, 0, fmt.Errorf("журнал аудита: чтение записей: %w", err)
	}
	defer rows.Close()
	n, last := 0, after
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return 0, 0, err
		}
		if err := fn(&r); err != nil {
			return 0, 0, err
		}
		n, last = n+1, r.Seq
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("журнал аудита: чтение записей: %w", err)
	}
	return n, last, nil
}

// ExportOptions — параметры выгрузки журнала в файл (РСБ.5).
type ExportOptions struct {
	From, To time.Time // [From, To); нулевое значение — без границы
	Out      io.Writer
	By       Actor
}

// Export выгружает записи журнала в файл для переноса на внешний носитель
// (РСБ.5): заголовок и записи с хешами — по ним цепочка проверяется вне
// продукта. Журнал не меняется; выгрузка пишется в журнал (audit.export).
// Возвращает число выгруженных записей.
func (l *Log) Export(ctx context.Context, opt ExportOptions) (int64, error) {
	if opt.Out == nil {
		return 0, errors.New("выгрузка: нет файла")
	}
	if !opt.From.IsZero() && !opt.To.IsZero() && !opt.From.Before(opt.To) {
		return 0, errors.New("выгрузка: начало периода не раньше конца")
	}
	ctx, cancel := withTimeout(ctx, archiveTimeout)
	defer cancel()
	now := l.now().UTC().Truncate(time.Microsecond)
	var n, first, last int64
	err := l.inTx(ctx, func(tx pgx.Tx) error {
		// Снимок на всё время чтения: выгрузка согласована с одним моментом.
		if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"); err != nil {
			return fmt.Errorf("выгрузка: %w", err)
		}
		fw := newFileWriter(opt.Out, l.hasher)
		hdr := fileHeader{Format: exportFormat, V: formatVersion, OrgID: DefaultOrgID, HashAlg: l.hasher.Name(), CreatedAt: now.Format(tsLayout)}
		hdr.From, hdr.To = dateOrEmpty(opt.From), dateOrEmpty(opt.To)
		// Диапазон номеров известен только после чтения; в заголовке — границы
		// хранимой части на момент снимка.
		var minSeq, maxSeq *int64
		if err := tx.QueryRow(ctx, "SELECT min(seq), max(seq) FROM audit_log").Scan(&minSeq, &maxSeq); err != nil {
			return fmt.Errorf("выгрузка: %w", err)
		}
		if minSeq != nil {
			hdr.FromSeq, hdr.ToSeq = *minSeq, *maxSeq
		}
		// Начало хранимой части из того же снимка: от него проверяется
		// цепочка полной выгрузки вне продукта.
		cps, err := loadCheckpoints(ctx, tx)
		if err != nil {
			return err
		}
		anchor, err := VerifyCheckpoints(l.hasher, nil, cps)
		if err != nil {
			return err
		}
		hdr.PrevSeq, hdr.PrevHash = anchor.Seq, hex.EncodeToString(anchor.Hash)
		if err := fw.line(hdr, true); err != nil {
			return fmt.Errorf("выгрузка: запись файла: %w", err)
		}
		if err := readRange(ctx, tx, 0, 0, opt.From, opt.To, func(r *Record) error {
			if n == 0 {
				first = r.Seq
			}
			n, last = n+1, r.Seq
			return fw.line(toFileRecord(r), true)
		}); err != nil {
			return err
		}
		return fw.flush()
	})
	if err != nil {
		return n, err
	}
	err = l.Record(ctx, Entry{
		Actor: opt.By, Action: "audit.export", Object: Object{Type: "audit_log"}, Result: ResultSuccess,
		Details: map[string]any{"records": n, "first_seq": first, "last_seq": last, "from": dateOrEmpty(opt.From), "to": dateOrEmpty(opt.To)},
	})
	return n, err
}

// dateOrEmpty — дата ГГГГ-ММ-ДД или пусто для нулевого времени.
func dateOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.DateOnly)
}
