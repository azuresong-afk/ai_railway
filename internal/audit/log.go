package audit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

const (
	// writeTimeout — предел на одну запись, если у контекста нет своего срока.
	writeTimeout = 10 * time.Second
	// rollbackTimeout — предел на откат транзакции после отмены контекста.
	rollbackTimeout = 5 * time.Second
	// chainLockID — ключ рекомендательной блокировки: записи журнала
	// встают в цепочку строго по одной.
	chainLockID = 0x41554449 // "AUDI"
)

// DB — доступ к PostgreSQL, нужный журналу; *pgxpool.Pool ему соответствует.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Checkpoints — источник контрольной точки, от которой начинается хранимая
// часть цепочки после архивации (задача 2.5). Нет архивации — nil.
type Checkpoints interface {
	// Latest возвращает последнюю контрольную точку; ok = false — её нет.
	Latest(ctx context.Context) (a Anchor, ok bool, err error)
}

// Log — журнал аудита (РСБ.1–4) и журнал технического состояния (РСБ.7).
type Log struct {
	db          DB
	provider    crypto.Provider
	hasher      crypto.Hasher
	random      crypto.Random
	checkpoints Checkpoints
	now         func() time.Time
	// rdb — пул чтения для просмотра журнала консолью; nil — основной.
	rdb Querier
}

// Querier — чтение из БД (пул чтения, *pgxpool.Pool).
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// WithReadDB задаёт отдельный пул для выборок консоли (List): медленные
// выборки не занимают соединения записи аудита, входа и приёма событий
// (В17 ревью 2.r3b).
func WithReadDB(db Querier) Option {
	return func(l *Log) {
		if db != nil {
			l.rdb = db
		}
	}
}

// reader — пул для выборок консоли.
func (l *Log) reader() Querier {
	if l.rdb != nil {
		return l.rdb
	}
	return l.db
}

// Option настраивает Log.
type Option func(*Log)

// WithCheckpoints подключает контрольные точки архивации.
func WithCheckpoints(c Checkpoints) Option { return func(l *Log) { l.checkpoints = c } }

// WithClock подменяет часы (для тестов).
func WithClock(now func() time.Time) Option { return func(l *Log) { l.now = now } }

// New создаёт журнал на криптопрофиле p.
func New(db DB, p crypto.Provider, opts ...Option) (*Log, error) {
	if db == nil || p == nil {
		return nil, errors.New("журнал аудита: нет БД или криптопрофиля")
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, fmt.Errorf("журнал аудита: хеш-функция профиля: %w", err)
	}
	r, err := p.Random()
	if err != nil {
		return nil, fmt.Errorf("журнал аудита: источник случайности профиля: %w", err)
	}
	l := &Log{db: db, provider: p, hasher: h, random: r, now: time.Now}
	for _, o := range opts {
		o(l)
	}
	return l, nil
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// inTx выполняет fn в транзакции; ошибка fn откатывает её.
func (l *Log) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := l.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("журнал аудита: начало транзакции: %w", err)
	}
	// Откат после коммита безвреден; ошибку отката скрывает исходная. Откат
	// идёт и после отмены ctx, но со своим сроком.
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после коммита безвреден, ошибку скрывает исходная
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("журнал аудита: фиксация: %w", err)
	}
	return nil
}

// Record пишет запись в журнал аудита. Необязательное событие, отключённое
// в настройках (РСБ.3), не пишется; обязательное пишется всегда.
func (l *Log) Record(ctx context.Context, e Entry) error {
	ctx, cancel := withTimeout(ctx, writeTimeout)
	defer cancel()
	return l.inTx(ctx, func(tx pgx.Tx) error {
		_, err := l.recordTx(ctx, tx, e)
		return err
	})
}

// recordTx встраивает запись в цепочку внутри транзакции tx: так изменение
// и запись о нём фиксируются вместе. false — событие отключено.
func (l *Log) recordTx(ctx context.Context, tx pgx.Tx, e Entry) (bool, error) {
	ev, err := e.normalize()
	if err != nil {
		return false, fmt.Errorf("журнал аудита: %w", err)
	}
	details, err := CanonicalDetails(e.Details)
	if err != nil {
		return false, fmt.Errorf("журнал аудита: %w", err)
	}
	if e.Actor.Type == ActorCLI {
		// «Кто» для aisec-cli — пользователь ОС и логин СУБД, под которым
		// выполнено действие (Н5 ревью 2.r1). Логин берётся из самой
		// транзакции: вызывающий его не задаёт.
		var dbUser string
		if err := tx.QueryRow(ctx, "SELECT session_user::text").Scan(&dbUser); err != nil {
			return false, fmt.Errorf("журнал аудита: логин СУБД: %w", err)
		}
		if details, err = withDetail(details, "db_user", dbUser); err != nil {
			return false, fmt.Errorf("журнал аудита: %w", err)
		}
	}
	org := e.OrgID
	if org == "" {
		org = DefaultOrgID
	}
	if !ev.Mandatory {
		var disabled bool
		err := tx.QueryRow(ctx,
			"SELECT $2 = ANY(disabled_actions) FROM audit_settings WHERE org_id = $1", org, e.Action).Scan(&disabled)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("журнал аудита: настройки: %w", err)
		}
		if disabled {
			return false, nil
		}
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", chainLockID); err != nil {
		return false, fmt.Errorf("журнал аудита: блокировка цепочки: %w", err)
	}
	head, err := l.head(ctx, tx)
	if err != nil {
		return false, err
	}
	now := l.now().UTC().Truncate(time.Microsecond)
	id, err := store.NewUUIDv7(now, l.random)
	if err != nil {
		return false, fmt.Errorf("журнал аудита: %w", err)
	}
	r := Record{
		Seq:      head.Seq + 1,
		ID:       string(id),
		OrgID:    org,
		TS:       now,
		Actor:    e.Actor,
		SourceIP: e.SourceIP,
		Action:   e.Action,
		Object:   e.Object,
		Result:   e.Result,
		Details:  details,
		HashAlg:  l.hasher.Name(),
		PrevHash: head.Hash,
	}
	if r.Hash, err = r.ComputeHash(l.hasher); err != nil {
		return false, fmt.Errorf("журнал аудита: %w", err)
	}
	var ip *string
	if r.SourceIP.IsValid() {
		s := r.SourceIP.String()
		ip = &s
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log
		(seq, id, org_id, ts, actor_type, actor_id, actor_name, source_ip, action,
		 object_type, object_id, result, details, hash_alg, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9, $10, $11, $12, $13::json, $14, $15, $16)`,
		r.Seq, r.ID, r.OrgID, r.TS, string(r.Actor.Type), r.Actor.ID, r.Actor.Name, ip, r.Action,
		r.Object.Type, r.Object.ID, string(r.Result), string(r.Details), r.HashAlg, r.PrevHash, r.Hash)
	if err != nil {
		return false, fmt.Errorf("журнал аудита: вставка записи: %w", err)
	}
	return true, nil
}

// head — последняя запись цепочки; пустой журнал продолжает контрольную
// точку архивации, а без неё начинается с нулевого хеша. Точка читается в
// той же транзакции tx: второе соединение при удержании блокировки цепочки
// не нужно (Н8 ревью 2.r1).
func (l *Log) head(ctx context.Context, q pgx.Tx) (Anchor, error) {
	var a Anchor
	err := q.QueryRow(ctx, "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&a.Seq, &a.Hash)
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Anchor{}, fmt.Errorf("журнал аудита: последняя запись: %w", err)
	}
	return l.anchorIn(ctx, q)
}

// anchor — начало хранимой части цепочки.
func (l *Log) anchor(ctx context.Context) (Anchor, error) { return l.anchorIn(ctx, nil) }

// txCheckpoints — источник контрольных точек, который читает их в
// переданной транзакции.
type txCheckpoints interface {
	LatestIn(ctx context.Context, q querier) (Anchor, bool, error)
}

// anchorIn — anchor в транзакции q (nil — отдельным запросом).
func (l *Log) anchorIn(ctx context.Context, q querier) (Anchor, error) {
	if l.checkpoints != nil {
		var (
			a   Anchor
			ok  bool
			err error
		)
		if tc, in := l.checkpoints.(txCheckpoints); in && q != nil {
			a, ok, err = tc.LatestIn(ctx, q)
		} else {
			a, ok, err = l.checkpoints.Latest(ctx)
		}
		if err != nil {
			return Anchor{}, fmt.Errorf("журнал аудита: контрольная точка: %w", err)
		}
		if ok {
			return a, nil
		}
	}
	return Anchor{Seq: 0, Hash: genesis(l.hasher)}, nil
}

// Settings — настройки журнала аудита (РСБ.3).
type Settings struct {
	DisabledActions []string // отключённые необязательные события
	RetentionDays   int      // срок хранения записей, дней
}

// Пределы срока хранения; те же — в CHECK таблицы audit_settings.
const (
	DefaultRetentionDays = 365
	MinRetentionDays     = 30
	MaxRetentionDays     = 3650
)

// Validate проверяет настройки: отключать можно только необязательные
// события из перечня.
func (s Settings) Validate() error {
	if s.RetentionDays < MinRetentionDays || s.RetentionDays > MaxRetentionDays {
		return fmt.Errorf("срок хранения журнала: от %d до %d дней", MinRetentionDays, MaxRetentionDays)
	}
	if len(s.DisabledActions) > len(catalog) {
		return errors.New("отключённых событий больше, чем событий в перечне")
	}
	seen := make(map[string]bool, len(s.DisabledActions))
	for _, a := range s.DisabledActions {
		ev, ok := Lookup(a)
		if !ok {
			return fmt.Errorf("событие %q не из перечня", a)
		}
		if ev.Mandatory {
			return fmt.Errorf("событие %q обязательное (РСБ.2), отключить его нельзя", a)
		}
		if seen[a] {
			return fmt.Errorf("событие %q указано дважды", a)
		}
		seen[a] = true
	}
	return nil
}

// Settings возвращает настройки организации; нет строки — значения по умолчанию.
func (l *Log) Settings(ctx context.Context, orgID string) (Settings, error) {
	ctx, cancel := withTimeout(ctx, writeTimeout)
	defer cancel()
	if orgID == "" {
		orgID = DefaultOrgID
	}
	s := Settings{DisabledActions: []string{}, RetentionDays: DefaultRetentionDays}
	err := l.db.QueryRow(ctx,
		"SELECT disabled_actions, retention_days FROM audit_settings WHERE org_id = $1", orgID).
		Scan(&s.DisabledActions, &s.RetentionDays)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, fmt.Errorf("журнал аудита: чтение настроек: %w", err)
	}
	return s, nil
}

// SetSettings меняет настройки и в той же транзакции пишет
// audit.settings_changed со значениями до и после. Субъект и адрес берутся
// из by (Action, Object, Result и Details в нём игнорируются).
func (l *Log) SetSettings(ctx context.Context, by Entry, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	ctx, cancel := withTimeout(ctx, writeTimeout)
	defer cancel()
	org := by.OrgID
	if org == "" {
		org = DefaultOrgID
	}
	disabled := slices.Clone(s.DisabledActions)
	slices.Sort(disabled)
	return l.inTx(ctx, func(tx pgx.Tx) error {
		// FOR UPDATE не блокирует ещё не созданную строку: два первых
		// изменения подряд сериализует блокировка цепочки.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", chainLockID); err != nil {
			return fmt.Errorf("журнал аудита: блокировка: %w", err)
		}
		before := Settings{DisabledActions: []string{}, RetentionDays: DefaultRetentionDays}
		err := tx.QueryRow(ctx,
			"SELECT disabled_actions, retention_days FROM audit_settings WHERE org_id = $1 FOR UPDATE", org).
			Scan(&before.DisabledActions, &before.RetentionDays)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("журнал аудита: чтение настроек: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_settings (org_id, disabled_actions, retention_days, updated_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (org_id) DO UPDATE
			SET disabled_actions = EXCLUDED.disabled_actions, retention_days = EXCLUDED.retention_days, updated_at = now()`,
			org, disabled, s.RetentionDays); err != nil {
			return fmt.Errorf("журнал аудита: запись настроек: %w", err)
		}
		e := by
		e.OrgID = org
		e.Action = "audit.settings_changed"
		e.Object = Object{Type: "audit_settings", ID: org}
		e.Result = ResultSuccess
		e.Details = map[string]any{
			"before": settingsDetails(before),
			"after":  settingsDetails(Settings{DisabledActions: disabled, RetentionDays: s.RetentionDays}),
		}
		_, err = l.recordTx(ctx, tx, e)
		return err
	})
}

func settingsDetails(s Settings) map[string]any {
	return map[string]any{"disabled_actions": s.DisabledActions, "retention_days": s.RetentionDays}
}
