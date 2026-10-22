package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// errSetupDone — первичная настройка уже выполнена: токен больше не нужен,
// учётные записи создаёт администратор безопасности в консоли.
var errSetupDone = errors.New("первичная настройка уже выполнена: повторный выпуск токена недоступен " +
	"(учётные записи создаёт администратор безопасности; аварийный доступ — aisec-cli user reset-password)")

// reissueRecord — новый токен первичной настройки: в БД — только хеш.
type reissueRecord struct {
	OrgID     string
	TokenID   string
	HashAlg   string
	TokenHash []byte
	Created   time.Time
	Expires   time.Time
}

// reissueStore — то, что повторный выпуск делает с БД.
type reissueStore interface {
	// Reissue одной транзакцией под блокировкой первичной настройки гасит
	// все непогашенные токены организации, сохраняет новый и пишет запись
	// аудита (в её подробности добавляется revoked_tokens). Если
	// пользователи уже есть — errSetupDone, ничего не меняется.
	Reissue(ctx context.Context, r *reissueRecord, rec audit.Entry) (revoked int, err error)
}

// runReissueSetupToken — aisec-cli init -reissue-setup-token (H-Р13 ревью
// 2.r5, ЗИ.4): новый одноразовый токен вместо утерянного или истёкшего,
// только пока первичная настройка не выполнена. Прежние токены гасятся,
// новый показывается один раз. p — криптопрофиль установки: хеш токена
// сервер сверяет своим алгоритмом.
func runReissueSetupToken(ctx context.Context, p aisecCrypto.Provider, st reissueStore, actor audit.Actor, now time.Time, stdout io.Writer) error {
	token, r, err := newSetupToken(p, now)
	if err != nil {
		return err
	}
	rec := audit.Entry{
		OrgID: r.OrgID, Actor: actor, Action: "system.setup_token_reissued",
		Object: audit.Object{Type: "setup_token", ID: r.TokenID}, Result: audit.ResultSuccess,
		Details: map[string]any{"setup_expires_at": r.Expires.UTC().Format(time.RFC3339), "setup_record_id": r.TokenID},
	}
	revoked, err := st.Reissue(ctx, r, rec)
	if err != nil {
		return err
	}
	say(stdout, "Прежних непогашенных токенов погашено: %d.\n", revoked)
	// Как и в init: если токен не дошёл до вывода, код возврата это покажет.
	if _, err := fmt.Fprintf(stdout, "\nНовый токен первичной настройки (показывается один раз, действует до %s UTC):\n\n  %s\n\n",
		r.Expires.UTC().Format("2006-01-02 15:04"), token); err != nil {
		return fmt.Errorf("токен выпущен, но не выведен (%w): выпустите его снова", err)
	}
	return nil
}

// newSetupToken создаёт токен первичной настройки и строку для БД.
func newSetupToken(p aisecCrypto.Provider, now time.Time) (string, *reissueRecord, error) {
	rnd, err := p.Random()
	if err != nil {
		return "", nil, err
	}
	h, err := p.Hasher()
	if err != nil {
		return "", nil, err
	}
	raw, err := aisecCrypto.RandomBytes(rnd, setupTokenSize)
	if err != nil {
		return "", nil, err
	}
	token := setupTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	id, err := store.NewUUIDv7(now, rnd)
	if err != nil {
		return "", nil, err
	}
	return token, &reissueRecord{OrgID: audit.DefaultOrgID, TokenID: string(id), HashAlg: h.Name(),
		TokenHash: h.Sum([]byte(token)), Created: now, Expires: now.Add(setupTokenTTL)}, nil
}

// pgReissueStore — reissueStore на PostgreSQL.
type pgReissueStore struct {
	pool *pgxpool.Pool
	log  *audit.Log
}

// SetupProfile — криптопрофиль установки по действующему ключу данных;
// ok = false — установка не инициализирована.
func (s pgReissueStore) SetupProfile(ctx context.Context, orgID string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, initDBTimeout)
	defer cancel()
	var profile string
	err := s.pool.QueryRow(ctx, `SELECT profile FROM data_keys WHERE org_id = $1 AND retired_at IS NULL
		ORDER BY version DESC LIMIT 1`, orgID).Scan(&profile)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("ключ данных (миграции применены? aisec-cli migrate): %w", err)
	}
	return profile, true, nil
}

func (s pgReissueStore) Reissue(ctx context.Context, r *reissueRecord, rec audit.Entry) (revoked int, err error) {
	ctx, cancel := context.WithTimeout(ctx, initDBTimeout)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer rcancel()
			_ = tx.Rollback(rctx) //nolint:gosec // G104: ошибку отката скрывает исходная
		}
	}()
	// Та же блокировка, что у первичной настройки: токен не выпускается
	// между проверкой пустоты и созданием первого администратора.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", setupLockKey); err != nil {
		return 0, fmt.Errorf("блокировка первичной настройки: %w", err)
	}
	var users bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE org_id = $1)", r.OrgID).Scan(&users); err != nil {
		return 0, err
	}
	if users {
		return 0, errSetupDone
	}
	tag, err := tx.Exec(ctx, "UPDATE setup_tokens SET used_at = $2 WHERE org_id = $1 AND used_at IS NULL", r.OrgID, r.Created)
	if err != nil {
		return 0, fmt.Errorf("погашение прежних токенов: %w", err)
	}
	revoked = int(tag.RowsAffected())
	if _, err = tx.Exec(ctx, `INSERT INTO setup_tokens (id, org_id, hash_alg, token_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, r.TokenID, r.OrgID, r.HashAlg, r.TokenHash, r.Created, r.Expires); err != nil {
		return 0, fmt.Errorf("запись токена первичной настройки: %w", err)
	}
	if d, ok := rec.Details.(map[string]any); ok {
		d["revoked_tokens"] = revoked
	}
	if err = s.log.RecordTx(ctx, tx, rec); err != nil {
		return 0, err
	}
	return revoked, tx.Commit(ctx)
}
