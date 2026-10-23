package keyring

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Ротация ключа данных (ADR-0018, п. 3; задача 3.2 этапа 3). Выполняет
// aisec-cli keys rotate-data под логином владельца схемы: новая версия,
// перешифрование секретов и содержимого событий пачками, удаление прежней
// версии, когда на неё не ссылается ни одна строка. Сервер переходит на
// новую версию сам (Box.Watch, перечитывание при отказе в резерве).

// Owner — БД с правами владельца схемы; *pgxpool.Pool ему соответствует.
type Owner interface {
	DB
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Recorder пишет запись аудита в транзакции (audit.Log).
type Recorder interface {
	RecordTx(ctx context.Context, tx pgx.Tx, e audit.Entry) error
}

// LockName — рекомендательная блокировка команд aisec-cli keys: две
// ротации не идут одновременно.
const LockName = "aisec-keys"

// rotateTimeout — предел транзакции ротации и одной пачки перешифрования.
const rotateTimeout = 2 * time.Minute

// LockTx берёт рекомендательную блокировку ротации до конца транзакции.
func LockTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, LockName); err != nil {
		return fmt.Errorf("блокировка ротации ключей: %w", err)
	}
	return nil
}

// InTx выполняет fn в транзакции с блокировкой ротации; ошибка — откат.
func InTx(ctx context.Context, db Owner, fn func(tx pgx.Tx) error) (err error) {
	ctx, cancel := context.WithTimeout(ctx, rotateTimeout)
	defer cancel()
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer rcancel()
			_ = tx.Rollback(rctx) //nolint:gosec // G104: ошибку отката скрывает исходная
		}
	}()
	if err = LockTx(ctx, tx); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Rotation — итог создания новой версии ключа данных.
type Rotation struct {
	OldID, NewID string
	Version      int
}

// RotateData создаёт новую версию ключа данных организации orgID под
// мастер-ключом из dir и выводит прежнюю (retired_at): шифровать ею больше
// нельзя, расшифровывать можно. Одна транзакция вместе с записью
// keys.data_rotated.
func RotateData(ctx context.Context, db Owner, rec Recorder, p aisecCrypto.Provider, dir, orgID string,
	actor audit.Actor, now time.Time) (Rotation, error) {
	master, err := ReadMaster(dir, p)
	if err != nil {
		return Rotation{}, err
	}
	defer clear(master)
	wrap, err := p.NewAEAD(master)
	if err != nil {
		return Rotation{}, err
	}
	rnd, err := p.Random()
	if err != nil {
		return Rotation{}, err
	}
	var out Rotation
	err = InTx(ctx, db, func(tx pgx.Tx) error {
		var old keyRow
		var masterVersion int
		err := tx.QueryRow(ctx, `SELECT id::text, version, profile, wrapped, master_version FROM data_keys
			WHERE org_id = $1 AND retired_at IS NULL FOR UPDATE`, orgID).
			Scan(&old.id, &old.num, &old.profile, &old.wrapped, &masterVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoDataKey
		}
		if err != nil {
			return fmt.Errorf("ключ данных: чтение: %w", err)
		}
		// Мастер-ключ из dir должен открывать действующую версию: чужой
		// каталог ключей не создаст версию, которую сервер не расшифрует.
		if _, err := old.open(p, wrap); err != nil {
			return err
		}
		key, err := aisecCrypto.RandomBytes(rnd, aisecCrypto.AEADKeySize)
		if err != nil {
			return err
		}
		defer clear(key)
		id, err := store.NewUUIDv7(now, rnd)
		if err != nil {
			return err
		}
		aad, err := aisecCrypto.StorageAAD("data_keys", "wrapped", string(id))
		if err != nil {
			return err
		}
		wrapped, err := wrap.Seal(key, aad)
		if err != nil {
			return err
		}
		ts := now.UTC().Truncate(time.Microsecond)
		if _, err := tx.Exec(ctx, `UPDATE data_keys SET retired_at = $2 WHERE id = $1`, old.id, ts); err != nil {
			return fmt.Errorf("ключ данных: вывод прежней версии: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO data_keys (id, org_id, version, profile, alg, wrapped, created_at, master_version)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, string(id), orgID, old.num+1, p.Name(), wrap.Name(), wrapped, ts, masterVersion); err != nil {
			return fmt.Errorf("ключ данных: запись новой версии: %w", err)
		}
		out = Rotation{OldID: old.id, NewID: string(id), Version: old.num + 1}
		return rec.RecordTx(ctx, tx, audit.Entry{
			OrgID: orgID, Actor: actor, Action: "keys.data_rotated",
			Object: audit.Object{Type: "data_key", ID: out.NewID}, Result: audit.ResultSuccess,
			Details: map[string]any{"version": out.Version, "previous_key_id": old.id, "previous_version": old.num},
		})
	})
	return out, err
}

// RewrapCounts — сколько строк перешифровано новой версией.
type RewrapCounts struct {
	MFA       int64 `json:"mfa"`
	Providers int64 `json:"providers"`
	Content   int64 `json:"content"`
	// Channels — секреты каналов уведомлений (задача 3.13 этапа 3).
	Channels int64 `json:"channels"`
	// GatewayTLS — ключ сертификата заказчика для адреса шлюза (задача 3.27).
	GatewayTLS int64 `json:"gateway_tls"`
}

// Total — всего строк.
func (c RewrapCounts) Total() int64 {
	return c.MFA + c.Providers + c.Content + c.Channels + c.GatewayTLS
}

// RewrapOptions — параметры перешифрования.
type RewrapOptions struct {
	// Batch — строк в одной транзакции (по умолчанию 500).
	Batch int
	// ContentPurpose — назначение производного ключа содержимого событий
	// (events.ContentKeyPurpose): пакет events импортирует keyring.
	ContentPurpose string
	// Progress получает счётчики после каждой пачки (может быть nil).
	Progress func(RewrapCounts)
	// AfterBatch — точка остановки для тестов прерывания (может быть nil):
	// ошибка прерывает перешифрование после зафиксированной пачки.
	AfterBatch func(RewrapCounts) error
}

// DefaultRewrapBatch — строк в пачке перешифрования.
const DefaultRewrapBatch = 500

// Места хранения шифротекстов ключа данных: те же AAD, что у internal/auth
// (TOTP), internal/apps (учётные данные провайдеров и ключ сертификата
// заказчика), internal/events (содержимое full) и internal/notify
// (секреты каналов).
const (
	mfaTable, mfaColumn             = "user_mfa", "secret"
	providersTable, providersColumn = "providers", "credential"
	contentTable, contentColumn     = "event_content", "sealed"
	channelsTable, channelsColumn   = "notify_channels", "secret"
	gwTLSTable, gwTLSColumn         = "gateway_tls", "key"
)

// Rewrap перешифровывает действующей версией box все строки прежних версий:
// секреты TOTP, учётные данные провайдеров, содержимое событий full,
// секреты каналов уведомлений и ключ сертификата заказчика.
// Каждая пачка — своя транзакция; строка обновляется, только если её ключ
// не сменился (сервер мог заменить её параллельно). Прерванное
// перешифрование продолжается повторным вызовом. box — из Load под
// логином владельца: знает все невыведенные версии.
func Rewrap(ctx context.Context, db Owner, box *Box, o RewrapOptions) (RewrapCounts, error) {
	if o.Batch <= 0 {
		o.Batch = DefaultRewrapBatch
	}
	if o.ContentPurpose == "" {
		return RewrapCounts{}, errors.New("перешифрование: не задано назначение ключа содержимого событий")
	}
	var total RewrapCounts
	steps := []struct {
		count *int64
		fn    func(ctx context.Context, tx pgx.Tx, active string) (int, error)
	}{
		{&total.MFA, func(ctx context.Context, tx pgx.Tx, active string) (int, error) {
			return rewrapMFA(ctx, tx, box, active, o.Batch)
		}},
		{&total.Providers, func(ctx context.Context, tx pgx.Tx, active string) (int, error) {
			return rewrapProviders(ctx, tx, box, active, o.Batch)
		}},
		{&total.Content, func(ctx context.Context, tx pgx.Tx, active string) (int, error) {
			return rewrapContent(ctx, tx, box, active, o.ContentPurpose, o.Batch)
		}},
		{&total.Channels, func(ctx context.Context, tx pgx.Tx, active string) (int, error) {
			return rewrapChannels(ctx, tx, box, active, o.Batch)
		}},
		{&total.GatewayTLS, func(ctx context.Context, tx pgx.Tx, active string) (int, error) {
			return rewrapGatewayTLS(ctx, tx, box, active, o.Batch)
		}},
	}
	for _, st := range steps {
		for {
			if err := ctx.Err(); err != nil {
				return total, err
			}
			var n int
			err := InTx(ctx, db, func(tx pgx.Tx) error {
				// Действующая версия — из БД: Box без опроса мог отстать.
				var active string
				if err := tx.QueryRow(ctx, `SELECT id::text FROM data_keys WHERE org_id = (SELECT org_id FROM data_keys WHERE id = $1)
					AND retired_at IS NULL`, box.KeyID()).Scan(&active); err != nil {
					return fmt.Errorf("перешифрование: действующая версия: %w", err)
				}
				if active != box.KeyID() {
					return errors.New("перешифрование: действующая версия ключа данных сменилась — запустите заново")
				}
				var err error
				n, err = st.fn(ctx, tx, active)
				return err
			})
			if err != nil {
				return total, err
			}
			if n == 0 {
				break
			}
			*st.count += int64(n)
			if o.Progress != nil {
				o.Progress(total)
			}
			if o.AfterBatch != nil {
				if err := o.AfterBatch(total); err != nil {
					return total, err
				}
			}
		}
	}
	return total, nil
}

// rewrapMFA — пачка секретов TOTP.
func rewrapMFA(ctx context.Context, tx pgx.Tx, box *Box, active string, batch int) (int, error) {
	type row struct {
		id, keyID string
		sealed    []byte
	}
	rows, err := collect(ctx, tx, `SELECT user_id::text, data_key_id::text, secret FROM user_mfa
		WHERE data_key_id <> $1 ORDER BY user_id LIMIT $2 FOR UPDATE`, []any{active, batch},
		func(r pgx.Rows) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.keyID, &x.sealed)
		})
	if err != nil {
		return 0, fmt.Errorf("перешифрование TOTP: %w", err)
	}
	for _, x := range rows {
		keyID, sealed, err := reseal(ctx, box, active, x.keyID, x.sealed, mfaTable, mfaColumn, x.id)
		if err != nil {
			return 0, fmt.Errorf("перешифрование TOTP пользователя %s: %w", x.id, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE user_mfa SET secret = $1, data_key_id = $2 WHERE user_id = $3 AND data_key_id = $4`,
			sealed, keyID, x.id, x.keyID); err != nil {
			return 0, fmt.Errorf("перешифрование TOTP пользователя %s: %w", x.id, err)
		}
	}
	return len(rows), nil
}

// rewrapProviders — пачка учётных данных провайдеров.
func rewrapProviders(ctx context.Context, tx pgx.Tx, box *Box, active string, batch int) (int, error) {
	type row struct {
		id, keyID string
		sealed    []byte
	}
	rows, err := collect(ctx, tx, `SELECT id::text, credential_key_id::text, credential FROM providers
		WHERE credential_key_id <> $1 ORDER BY id LIMIT $2 FOR UPDATE`, []any{active, batch},
		func(r pgx.Rows) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.keyID, &x.sealed)
		})
	if err != nil {
		return 0, fmt.Errorf("перешифрование учётных данных провайдеров: %w", err)
	}
	for _, x := range rows {
		keyID, sealed, err := reseal(ctx, box, active, x.keyID, x.sealed, providersTable, providersColumn, x.id)
		if err != nil {
			return 0, fmt.Errorf("перешифрование учётных данных провайдера %s: %w", x.id, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE providers SET credential = $1, credential_key_id = $2 WHERE id = $3 AND credential_key_id = $4`,
			sealed, keyID, x.id, x.keyID); err != nil {
			return 0, fmt.Errorf("перешифрование учётных данных провайдера %s: %w", x.id, err)
		}
	}
	return len(rows), nil
}

// rewrapChannels — пачка секретов каналов уведомлений (internal/notify).
func rewrapChannels(ctx context.Context, tx pgx.Tx, box *Box, active string, batch int) (int, error) {
	type row struct {
		id, keyID string
		sealed    []byte
	}
	rows, err := collect(ctx, tx, `SELECT id::text, secret_key_id::text, secret FROM notify_channels
		WHERE secret_key_id <> $1 ORDER BY id LIMIT $2 FOR UPDATE`, []any{active, batch},
		func(r pgx.Rows) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.keyID, &x.sealed)
		})
	if err != nil {
		return 0, fmt.Errorf("перешифрование секретов каналов уведомлений: %w", err)
	}
	for _, x := range rows {
		keyID, sealed, err := reseal(ctx, box, active, x.keyID, x.sealed, channelsTable, channelsColumn, x.id)
		if err != nil {
			return 0, fmt.Errorf("перешифрование секретов канала %s: %w", x.id, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE notify_channels SET secret = $1, secret_key_id = $2 WHERE id = $3 AND secret_key_id = $4`,
			sealed, keyID, x.id, x.keyID); err != nil {
			return 0, fmt.Errorf("перешифрование секретов канала %s: %w", x.id, err)
		}
	}
	return len(rows), nil
}

// rewrapGatewayTLS — ключ сертификата заказчика (internal/apps, задача
// 3.27): AAD gateway_tls|key|<org_id>.
func rewrapGatewayTLS(ctx context.Context, tx pgx.Tx, box *Box, active string, batch int) (int, error) {
	type row struct {
		id, keyID string
		sealed    []byte
	}
	rows, err := collect(ctx, tx, `SELECT org_id::text, key_key_id::text, key_sealed FROM gateway_tls
		WHERE key_key_id <> $1 ORDER BY org_id LIMIT $2 FOR UPDATE`, []any{active, batch},
		func(r pgx.Rows) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.keyID, &x.sealed)
		})
	if err != nil {
		return 0, fmt.Errorf("перешифрование ключа сертификата заказчика: %w", err)
	}
	for _, x := range rows {
		keyID, sealed, err := reseal(ctx, box, active, x.keyID, x.sealed, gwTLSTable, gwTLSColumn, x.id)
		if err != nil {
			return 0, fmt.Errorf("перешифрование ключа сертификата заказчика: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE gateway_tls SET key_sealed = $1, key_key_id = $2 WHERE org_id = $3 AND key_key_id = $4`,
			sealed, keyID, x.id, x.keyID); err != nil {
			return 0, fmt.Errorf("перешифрование ключа сертификата заказчика: %w", err)
		}
	}
	return len(rows), nil
}

// rewrapContent — пачка содержимого событий full: производный ключ тех же
// суток от новой версии (ADR-0007, п. 8).
func rewrapContent(ctx context.Context, tx pgx.Tx, box *Box, active, purpose string, batch int) (int, error) {
	type row struct {
		id, keyID, alg string
		ts, day        time.Time
		sealed         []byte
	}
	rows, err := collect(ctx, tx, `SELECT event_id::text, ts, key_id::text, key_day, alg, sealed FROM event_content
		WHERE storage = 'full' AND key_id <> $1 ORDER BY ts, event_id LIMIT $2 FOR UPDATE`, []any{active, batch},
		func(r pgx.Rows) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.ts, &x.keyID, &x.day, &x.alg, &x.sealed)
		})
	if err != nil {
		return 0, fmt.Errorf("перешифрование содержимого событий: %w", err)
	}
	for _, x := range rows {
		plain, err := box.OpenDerivedContext(ctx, x.keyID, purpose, x.day, x.sealed, contentTable, contentColumn, x.id)
		if err != nil {
			return 0, fmt.Errorf("перешифрование содержимого события %s: %w", x.id, err)
		}
		keyID, alg, sealed, err := box.SealDerived(ctx, purpose, x.day, plain, contentTable, contentColumn, x.id)
		clear(plain)
		if err != nil {
			return 0, fmt.Errorf("перешифрование содержимого события %s: %w", x.id, err)
		}
		if keyID != active || alg != x.alg {
			return 0, errors.New("перешифрование: версия или алгоритм ключа сменились — запустите заново")
		}
		if _, err := tx.Exec(ctx, `UPDATE event_content SET key_id = $1, sealed = $2 WHERE event_id = $3 AND ts = $4 AND key_id = $5`,
			keyID, sealed, x.id, x.ts, x.keyID); err != nil {
			return 0, fmt.Errorf("перешифрование содержимого события %s: %w", x.id, err)
		}
	}
	return len(rows), nil
}

// reseal расшифровывает прежней версией и шифрует действующей; открытый
// текст затирается.
func reseal(ctx context.Context, box *Box, active, keyID string, sealed []byte, table, column, id string) (string, []byte, error) {
	plain, err := box.OpenContext(ctx, keyID, sealed, table, column, id)
	if err != nil {
		return "", nil, err
	}
	defer clear(plain)
	newID, out, err := box.SealKey(ctx, plain, table, column, id)
	if err != nil {
		return "", nil, err
	}
	if newID != active {
		return "", nil, errors.New("версия ключа данных сменилась — запустите заново")
	}
	return newID, out, nil
}

// collect читает все строки запроса.
func collect[T any](ctx context.Context, tx pgx.Tx, sql string, args []any, scan func(pgx.Rows) (T, error)) ([]T, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		x, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// VersionStatus — версия ключа данных и число строк под ней.
type VersionStatus struct {
	ID            string
	Version       int
	MasterVersion int
	Sealed        int64
	CreatedAt     time.Time
	RetiredAt     *time.Time
	Rows          RewrapCounts
}

// Status — версии ключа данных организации и строки под каждой (без ключей).
func Status(ctx context.Context, db Owner, orgID string) ([]VersionStatus, error) {
	ctx, cancel := dbCtx(ctx)
	defer cancel()
	rows, err := db.Query(ctx, `SELECT k.id::text, k.version, k.master_version, k.sealed, k.created_at, k.retired_at,
		(SELECT count(*) FROM user_mfa WHERE data_key_id = k.id),
		(SELECT count(*) FROM providers WHERE credential_key_id = k.id),
		(SELECT count(*) FROM event_content WHERE key_id = k.id),
		(SELECT count(*) FROM notify_channels WHERE secret_key_id = k.id),
		(SELECT count(*) FROM gateway_tls WHERE key_key_id = k.id)
		FROM data_keys k WHERE k.org_id = $1 ORDER BY k.version`, orgID)
	if err != nil {
		return nil, fmt.Errorf("ключ данных: состояние: %w", err)
	}
	defer rows.Close()
	var out []VersionStatus
	for rows.Next() {
		var v VersionStatus
		if err := rows.Scan(&v.ID, &v.Version, &v.MasterVersion, &v.Sealed, &v.CreatedAt, &v.RetiredAt,
			&v.Rows.MFA, &v.Rows.Providers, &v.Rows.Content, &v.Rows.Channels, &v.Rows.GatewayTLS); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DestroyResult — итог вывода прежних версий.
type DestroyResult struct {
	Destroyed []string
	// Remaining — выведенные версии, на которые ещё ссылаются строки.
	Remaining map[string]RewrapCounts
}

// DestroyRetired удаляет выведенные версии ключа данных, на которые не
// ссылается ни одна строка, вместе с их счётчиками производных ключей
// (запись keys.data_key_destroyed на каждую). Внешние ключи проверяют
// отсутствие ссылок в той же транзакции.
func DestroyRetired(ctx context.Context, db Owner, rec Recorder, orgID string, actor audit.Actor) (DestroyResult, error) {
	res := DestroyResult{Remaining: map[string]RewrapCounts{}}
	versions, err := Status(ctx, db, orgID)
	if err != nil {
		return res, err
	}
	for _, v := range versions {
		if v.RetiredAt == nil {
			continue
		}
		var left RewrapCounts
		err := InTx(ctx, db, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM user_mfa WHERE data_key_id = $1),
				(SELECT count(*) FROM providers WHERE credential_key_id = $1),
				(SELECT count(*) FROM event_content WHERE key_id = $1),
				(SELECT count(*) FROM notify_channels WHERE secret_key_id = $1),
				(SELECT count(*) FROM gateway_tls WHERE key_key_id = $1)`, v.ID).
				Scan(&left.MFA, &left.Providers, &left.Content, &left.Channels, &left.GatewayTLS); err != nil {
				return err
			}
			if left.Total() > 0 {
				return nil
			}
			if _, err := tx.Exec(ctx, `DELETE FROM derived_key_usage WHERE data_key_id = $1`, v.ID); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `DELETE FROM data_keys WHERE id = $1 AND org_id = $2 AND retired_at IS NOT NULL`, v.ID, orgID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errors.New("выведенная версия не найдена")
			}
			return rec.RecordTx(ctx, tx, audit.Entry{
				OrgID: orgID, Actor: actor, Action: "keys.data_key_destroyed",
				Object: audit.Object{Type: "data_key", ID: v.ID}, Result: audit.ResultSuccess,
				Details: map[string]any{"version": v.Version, "sealed": v.Sealed},
			})
		})
		if err != nil {
			return res, fmt.Errorf("ключ данных: удаление версии %d: %w", v.Version, err)
		}
		if left.Total() > 0 {
			res.Remaining[v.ID] = left
			continue
		}
		res.Destroyed = append(res.Destroyed, v.ID)
	}
	return res, nil
}
