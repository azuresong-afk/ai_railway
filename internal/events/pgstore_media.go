package events

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Изображения содержимого full в PostgreSQL (миграция 0081, ADR-0039,
// раздел 3): строка на изображение, шифротекст производным ключом суток
// события с назначением ContentKeyPurpose, AAD — event_media | sealed |
// <ID события>/<номер>. Секции и срок — как у event_content.

// Место хранения шифротекста изображения — для AAD.
const (
	mediaTable  = "event_media"
	mediaColumn = "sealed"
)

const insertMedia = `INSERT INTO event_media (event_id, ts, idx, org_id, location, format, sanitized, key_id, key_day, alg, sealed)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

// MediaAAD — ID строки event_media в AAD: ID события и номер изображения.
func MediaAAD(eventID string, idx int) string { return eventID + "/" + strconv.Itoa(idx) }

// queueMedia шифрует изображения события и ставит их запись в b.
func (s *PGStore) queueMedia(ctx context.Context, b *pgx.Batch, r eventRow) error {
	e := r.ev
	if e.Storage != StorageFull || e.Content == nil {
		return nil
	}
	for i, img := range e.Content.Images {
		keyID, alg, sealed, err := s.box.SealDerived(ctx, ContentKeyPurpose, r.ts, img.Data, mediaTable, mediaColumn, MediaAAD(e.ID, i))
		if err != nil {
			return fmt.Errorf("хранилище событий: шифрование изображения: %w", err)
		}
		day := r.ts.UTC().Format(time.DateOnly)
		b.Queue(insertMedia, e.ID, r.ts, i, s.orgID, img.Location, img.Format, img.Sanitized, keyID, day, alg, sealed)
	}
	return nil
}

// Images читает и расшифровывает изображения события по порядку (проверку
// права в полной области и аудит делает вызывающий). Нет изображений —
// пустой список без ошибки.
func (s *PGStore) Images(ctx context.Context, id string) ([]ContentImage, error) {
	ts, err := PartitionTime(id)
	if err != nil {
		return nil, nil
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	type row struct {
		idx    int
		img    ContentImage
		keyID  string
		day    time.Time
		sealed []byte
	}
	rows, err := s.rdb.Query(ctx, `SELECT idx, location, format, sanitized, key_id::text, key_day, sealed
		FROM event_media WHERE event_id = $1 AND ts = $2 AND org_id = $3 ORDER BY idx`, id, ts, s.orgID)
	if err != nil {
		return nil, fmt.Errorf("хранилище событий: чтение изображений: %w", err)
	}
	var list []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.idx, &x.img.Location, &x.img.Format, &x.img.Sanitized, &x.keyID, &x.day, &x.sealed); err != nil {
			rows.Close()
			return nil, fmt.Errorf("хранилище событий: чтение изображений: %w", err)
		}
		list = append(list, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("хранилище событий: чтение изображений: %w", err)
	}
	out := make([]ContentImage, 0, len(list))
	for _, x := range list {
		plain, err := s.box.OpenDerivedContext(ctx, x.keyID, ContentKeyPurpose, x.day, x.sealed, mediaTable, mediaColumn, MediaAAD(id, x.idx))
		if err != nil {
			for _, o := range out {
				clear(o.Data)
			}
			return nil, fmt.Errorf("хранилище событий: расшифрование изображения: %w", err)
		}
		x.img.Data = plain
		out = append(out, x.img)
	}
	return out, nil
}
