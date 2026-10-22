package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Чтение событий для консоли (ТЗ 5.5, задача 2.16): списки и выгрузка по
// фильтру, карточка, сроки хранения, сохранённые фильтры. Содержимое
// запросов и ответов эти запросы не читают — к event_content обращается
// только PGStore.Content.

// Лимиты запросов.
const (
	// MaxQueryRange — наибольший период запроса: не больше 32 суточных
	// секций, чтобы один запрос не сканировал всё хранилище (Р9).
	MaxQueryRange = 31 * 24 * time.Hour
	// MaxListLimit — наибольшая страница списка.
	MaxListLimit = 200
	// MaxExportRows — наибольшая выгрузка за один запрос.
	MaxExportRows = 100_000
	// ExportTimeout — предел выгрузки целиком.
	ExportTimeout = 2 * time.Minute
)

// Ошибки запросов чтения.
var (
	// ErrBadRange — период пуст, перевёрнут или длиннее MaxQueryRange.
	ErrBadRange = errors.New("период запроса событий задан неверно")
)

// Record — событие в ответах API: метаданные без содержимого.
type Record struct {
	ID string
	// TS — время из UUIDv7 события (ключ секции и курсора); Time — время
	// события по часам шлюза.
	TS               time.Time
	Time             time.Time
	ReceivedAt       time.Time
	GatewayID        string
	Type             string
	App              string
	Env              string
	User             string
	Provider         string
	Model            string
	Source           string
	PolicyMode       string
	Action           string
	Rule             string
	Severity         string
	Storage          string
	Threats          []string
	Stream           bool
	NonTextUnchecked bool
	HasContent       bool
	// Details — решение с трассировкой, находки, задержки; заполняется для
	// карточки и выгрузки JSON (Query.WithDetails).
	Details *Details
}

// Position — место в выборке «от новых к старым»: (TS, ID) последней
// выданной записи.
type Position struct {
	TS time.Time
	ID string
}

// Query — выборка событий за период [From, To) по фильтру.
type Query struct {
	From, To time.Time
	Filter   Filter
	After    *Position
	Limit    int
	// ReceivedBefore — только события, принятые не позже этого времени:
	// снимок, чтобы подсчёт строк выгрузки и сама выгрузка совпадали.
	ReceivedBefore time.Time
	WithDetails    bool
}

// Validate проверяет период и страницу.
func (q *Query) Validate() error {
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) || q.To.Sub(q.From) > MaxQueryRange {
		return ErrBadRange
	}
	if q.Limit < 0 {
		return errors.New("отрицательный предел выборки")
	}
	if len(q.Filter.Conds) > MaxFilterConds {
		return errors.New("слишком много условий фильтра")
	}
	return nil
}

// Reader — чтение событий для API. Рабочая реализация — PGStore, для
// тестов без PostgreSQL — Memory.
type Reader interface {
	// List — страница событий от новых к старым (не больше q.Limit).
	List(ctx context.Context, q Query) ([]Record, error)
	// Card — карточка события с Details; ErrNotFound — нет такого.
	Card(ctx context.Context, id string) (Record, error)
	// Content — содержимое события (проверку права и аудит делает
	// вызывающий); ErrNotFound — содержимого нет.
	Content(ctx context.Context, id string) (StoredContent, error)
	// Count — число событий выборки, но не больше limit+1.
	Count(ctx context.Context, q Query, limit int) (int, error)
	// Each передаёт fn события выборки по одному.
	Each(ctx context.Context, q Query, fn func(*Record) error) error
	// Export — выгрузка по одному снимку: подсчёт (больше q.Limit —
	// ErrTooManyRows), start(n) до первой записи (запись data.export в
	// аудит; ошибка отменяет выгрузку), затем записи по одной в fn.
	Export(ctx context.Context, q Query, start func(n int) error, fn func(*Record) error) error
}

// selectColumns — столбцы записи; details — только с WithDetails.
const selectColumns = `e.id::text, e.ts, e.event_time, e.received_at, e.gateway_id::text, e.type, e.app, e.env,
	e.user_alias, e.provider, e.model, e.source, e.policy_mode, e.action, e.rule, e.severity, e.storage,
	e.threats, e.stream, e.non_text_unchecked, e.has_content`

// buildQuery — SELECT выборки. Текст запроса собирается только из
// констант и фрагментов фильтра (filter.appendSQL); значения пользователя —
// параметрами.
func (s *PGStore) buildQuery(q *Query, count int) (string, []any) {
	a := &sqlArgs{}
	var b strings.Builder
	if count > 0 {
		b.WriteString("SELECT count(*) FROM (SELECT 1")
	} else {
		b.WriteString("SELECT " + selectColumns)
		if q.WithDetails {
			b.WriteString(", e.details")
		}
	}
	b.WriteString(" FROM events e WHERE e.org_id = " + a.add(s.orgID))
	b.WriteString(" AND e.ts >= " + a.add(q.From.UTC()) + " AND e.ts < " + a.add(q.To.UTC()))
	if !q.ReceivedBefore.IsZero() {
		b.WriteString(" AND e.received_at <= " + a.add(q.ReceivedBefore.UTC()))
	}
	if q.After != nil {
		b.WriteString(" AND (e.ts, e.id) < (" + a.add(q.After.TS.UTC()) + ", " + a.add(q.After.ID) + "::uuid)")
	}
	q.Filter.appendSQL(&b, a)
	if count > 0 {
		b.WriteString(" LIMIT " + a.add(count+1) + ") AS s")
		return b.String(), a.args
	}
	b.WriteString(" ORDER BY e.ts DESC, e.id DESC")
	if q.Limit > 0 {
		b.WriteString(" LIMIT " + a.add(q.Limit))
	}
	return b.String(), a.args
}

func scanRecord(row pgx.Row, withDetails bool) (Record, error) {
	var (
		r                                             Record
		app, env, user, provider, model, source, mode *string
		action, rule, severity                        *string
		details                                       []byte
	)
	dest := []any{&r.ID, &r.TS, &r.Time, &r.ReceivedAt, &r.GatewayID, &r.Type, &app, &env, &user, &provider,
		&model, &source, &mode, &action, &rule, &severity, &r.Storage, &r.Threats, &r.Stream,
		&r.NonTextUnchecked, &r.HasContent}
	if withDetails {
		dest = append(dest, &details)
	}
	if err := row.Scan(dest...); err != nil {
		return Record{}, err
	}
	r.App, r.Env, r.User, r.Provider, r.Model = deref(app), deref(env), deref(user), deref(provider), deref(model)
	r.Source, r.PolicyMode, r.Action, r.Rule, r.Severity = deref(source), deref(mode), deref(action), deref(rule), deref(severity)
	r.TS, r.Time, r.ReceivedAt = r.TS.UTC(), r.Time.UTC(), r.ReceivedAt.UTC()
	if withDetails {
		var d Details
		if err := json.Unmarshal(details, &d); err != nil {
			return Record{}, errors.New("хранилище событий: details — не JSON")
		}
		r.Details = &d
	}
	return r, nil
}

// List — см. Reader.
func (s *PGStore) List(ctx context.Context, q Query) ([]Record, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	if q.Limit == 0 || q.Limit > MaxListLimit+1 {
		q.Limit = MaxListLimit + 1
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	out := []Record{}
	err := s.each(ctx, &q, func(r *Record) error {
		out = append(out, *r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Each — см. Reader. Срок задаёт контекст вызывающего (выгрузка — ExportTimeout).
func (s *PGStore) Each(ctx context.Context, q Query, fn func(*Record) error) error {
	if err := q.Validate(); err != nil {
		return err
	}
	if q.Limit == 0 || q.Limit > MaxExportRows {
		q.Limit = MaxExportRows
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.each(ctx, &q, fn)
}

// querier — пул или транзакция, из которых читается выборка.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *PGStore) each(ctx context.Context, q *Query, fn func(*Record) error) error {
	return s.eachIn(ctx, s.rdb, q, fn)
}

func (s *PGStore) eachIn(ctx context.Context, db querier, q *Query, fn func(*Record) error) error {
	sql, args := s.buildQuery(q, 0)
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return dbError("чтение событий", err)
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanRecord(rows, q.WithDetails)
		if err != nil {
			return dbError("чтение событий", err)
		}
		if err := fn(&r); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return dbError("чтение событий", err)
	}
	return nil
}

// Count — см. Reader.
func (s *PGStore) Count(ctx context.Context, q Query, limit int) (int, error) {
	if err := q.Validate(); err != nil {
		return 0, err
	}
	if limit < 1 {
		return 0, errors.New("предел подсчёта меньше 1")
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.countIn(ctx, s.rdb, &q, limit)
}

func (s *PGStore) countIn(ctx context.Context, db querier, q *Query, limit int) (int, error) {
	sql, args := s.buildQuery(q, limit)
	var n int
	if err := db.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return 0, dbError("подсчёт событий", err)
	}
	return n, nil
}

// Export — см. Reader. Подсчёт и выборка — в одной транзакции REPEATABLE
// READ READ ONLY на пуле чтения: оба видят один снимок, и число строк в
// записи data.export совпадает с переданным (Н21 ревью 2.r3a). Срок задаёт
// контекст вызывающего (ExportTimeout).
func (s *PGStore) Export(ctx context.Context, q Query, start func(n int) error, fn func(*Record) error) error {
	if err := q.Validate(); err != nil {
		return err
	}
	if q.Limit <= 0 || q.Limit > MaxExportRows {
		q.Limit = MaxExportRows
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := s.rdb.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("хранилище событий: начало транзакции выгрузки: %w", err)
	}
	defer func() {
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer rcancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: транзакция только читает, откат — её завершение
	}()
	n, err := s.countIn(ctx, tx, &q, q.Limit)
	if err != nil {
		return err
	}
	if n > q.Limit {
		return ErrTooManyRows
	}
	if err := start(n); err != nil {
		return err
	}
	return s.eachIn(ctx, tx, &q, fn)
}

// Card — см. Reader.
func (s *PGStore) Card(ctx context.Context, id string) (Record, error) {
	ts, err := PartitionTime(id)
	if err != nil {
		return Record{}, ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	r, err := scanRecord(s.rdb.QueryRow(ctx, "SELECT "+selectColumns+", e.details FROM events e"+
		" WHERE e.id = $1 AND e.ts = $2 AND e.org_id = $3", id, ts, s.orgID), true)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, dbError("чтение события", err)
	}
	return r, nil
}

// Сроки хранения (ТЗ 5.5): границы — как в ограничениях event_settings.
const (
	MinMetadataDays  = 30
	MinContentDays   = 7
	MaxRetentionDays = 3650
)

// Retention — сроки хранения событий в сутках.
type Retention struct {
	MetadataDays int       `json:"metadata_days"`
	ContentDays  int       `json:"content_days"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ErrBadRetention — сроки вне допустимых границ.
var ErrBadRetention = errors.New("сроки хранения событий вне допустимых границ")

// Validate: метаданные 30–3650 суток, содержимое 7–3650 и не дольше
// метаданных (содержимое без метаданных не найти и не удалить).
func (r Retention) Validate() error {
	if r.MetadataDays < MinMetadataDays || r.MetadataDays > MaxRetentionDays ||
		r.ContentDays < MinContentDays || r.ContentDays > MaxRetentionDays || r.ContentDays > r.MetadataDays {
		return ErrBadRetention
	}
	return nil
}

// RetentionStore — настройка сроков хранения.
type RetentionStore interface {
	Retention(ctx context.Context) (Retention, error)
	// SetRetention меняет сроки и той же транзакцией пишет
	// events.settings_changed в аудит; возвращает прежние сроки.
	SetRetention(ctx context.Context, r Retention, by audit.Actor, ip netip.Addr) (Retention, error)
}

// Retention — см. RetentionStore.
func (s *PGStore) Retention(ctx context.Context) (Retention, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var r Retention
	if err := s.db.QueryRow(ctx, "SELECT metadata_days, content_days, updated_at FROM event_settings").
		Scan(&r.MetadataDays, &r.ContentDays, &r.UpdatedAt); err != nil {
		return Retention{}, dbError("сроки хранения", err)
	}
	r.UpdatedAt = r.UpdatedAt.UTC()
	return r, nil
}

// SetRetention — см. RetentionStore. Сокращение срока отмечается в аудите
// признаком reduced (основа правила DM-40 этапа 3).
func (s *PGStore) SetRetention(ctx context.Context, r Retention, by audit.Actor, ip netip.Addr) (Retention, error) {
	if err := r.Validate(); err != nil {
		return Retention{}, err
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var old Retention
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT metadata_days, content_days, updated_at FROM event_settings FOR UPDATE").
			Scan(&old.MetadataDays, &old.ContentDays, &old.UpdatedAt); err != nil {
			return dbError("сроки хранения", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE event_settings SET metadata_days = $1, content_days = $2, updated_at = now()",
			r.MetadataDays, r.ContentDays); err != nil {
			return dbError("сроки хранения", err)
		}
		return s.audit.RecordTx(ctx, tx, RetentionAudit(s.orgID, old, r, by, ip))
	})
	if err != nil {
		return Retention{}, err
	}
	old.UpdatedAt = old.UpdatedAt.UTC()
	return old, nil
}

// RetentionAudit — запись events.settings_changed об изменении сроков.
func RetentionAudit(orgID string, old, r Retention, by audit.Actor, ip netip.Addr) audit.Entry {
	reduced := r.MetadataDays < old.MetadataDays || r.ContentDays < old.ContentDays
	return audit.Entry{
		OrgID: orgID, Actor: by, SourceIP: ip, Action: "events.settings_changed",
		Object: audit.Object{Type: "event_settings"}, Result: audit.ResultSuccess,
		Details: map[string]any{
			"before":  map[string]int{"metadata_days": old.MetadataDays, "content_days": old.ContentDays},
			"after":   map[string]int{"metadata_days": r.MetadataDays, "content_days": r.ContentDays},
			"reduced": reduced,
		},
	}
}

// Сохранённые фильтры (ТЗ 5.5): личные, у каждого пользователя свои.
const (
	MaxSavedFilters    = 50
	MaxFilterNameRunes = 100
)

// Ошибки сохранённых фильтров.
var (
	ErrFilterName     = errors.New("имя фильтра: 1–100 символов без управляющих")
	ErrFilterExists   = errors.New("фильтр с таким именем уже есть")
	ErrTooManyFilters = errors.New("сохранено слишком много фильтров")
)

// SavedFilter — сохранённый фильтр пользователя.
type SavedFilter struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Filter    string    `json:"filter"`
	CreatedAt time.Time `json:"created_at"`
}

// ValidFilterName — имя фильтра: 1–100 символов, без управляющих и пробелов
// по краям.
func ValidFilterName(s string) bool {
	if !utf8.ValidString(s) || s == "" || strings.TrimSpace(s) != s || utf8.RuneCountInString(s) > MaxFilterNameRunes {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return true
}

// FilterStore — сохранённые фильтры пользователя.
type FilterStore interface {
	Filters(ctx context.Context, userID string) ([]SavedFilter, error)
	// SaveFilter сохраняет фильтр в канонической записи f.String().
	SaveFilter(ctx context.Context, userID, name string, f Filter) (SavedFilter, error)
	// DeleteFilter удаляет свой фильтр; ErrNotFound — нет своего с таким ID.
	DeleteFilter(ctx context.Context, userID, id string) error
}

// Filters — см. FilterStore.
func (s *PGStore) Filters(ctx context.Context, userID string) ([]SavedFilter, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT id::text, name, filter, created_at FROM event_filters
		WHERE org_id = $1 AND user_id = $2 ORDER BY name LIMIT $3`, s.orgID, userID, MaxSavedFilters)
	if err != nil {
		return nil, dbError("сохранённые фильтры", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SavedFilter, error) {
		var f SavedFilter
		err := row.Scan(&f.ID, &f.Name, &f.Filter, &f.CreatedAt)
		f.CreatedAt = f.CreatedAt.UTC()
		return f, err
	})
	if err != nil {
		return nil, dbError("сохранённые фильтры", err)
	}
	return out, nil
}

// filterLockSeed — затравка ключа блокировки фильтров пользователя.
const filterLockSeed int64 = 0x6576_6669_6c74 // «evfilt»

// SaveFilter — см. FilterStore. Лимит числа фильтров проверяется под
// блокировкой по пользователю, чтобы параллельные запросы его не обошли.
func (s *PGStore) SaveFilter(ctx context.Context, userID, name string, f Filter) (SavedFilter, error) {
	if !ValidFilterName(name) {
		return SavedFilter{}, ErrFilterName
	}
	id, err := s.newID()
	if err != nil {
		return SavedFilter{}, err
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	out := SavedFilter{ID: id, Name: name, Filter: f.String()}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))", userID, filterLockSeed); err != nil {
			return dbError("сохранённые фильтры", err)
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM event_filters WHERE org_id = $1 AND user_id = $2",
			s.orgID, userID).Scan(&n); err != nil {
			return dbError("сохранённые фильтры", err)
		}
		if n >= MaxSavedFilters {
			return ErrTooManyFilters
		}
		tag, err := tx.Exec(ctx, `INSERT INTO event_filters (id, org_id, user_id, name, filter, created_at)
			VALUES ($1, $2, $3, $4, $5, now()) ON CONFLICT (org_id, user_id, name) DO NOTHING`,
			out.ID, s.orgID, userID, out.Name, out.Filter)
		if err != nil {
			return dbError("сохранённые фильтры", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrFilterExists
		}
		return tx.QueryRow(ctx, "SELECT created_at FROM event_filters WHERE id = $1", out.ID).Scan(&out.CreatedAt)
	})
	if err != nil {
		return SavedFilter{}, err
	}
	out.CreatedAt = out.CreatedAt.UTC()
	return out, nil
}

// DeleteFilter — см. FilterStore.
func (s *PGStore) DeleteFilter(ctx context.Context, userID, id string) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var gone string
	err := s.db.QueryRow(ctx, "DELETE FROM event_filters WHERE id = $1 AND org_id = $2 AND user_id = $3 RETURNING id::text",
		id, s.orgID, userID).Scan(&gone)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return dbError("сохранённые фильтры", err)
	}
	return nil
}

// newID — UUIDv7 для новой строки.
func (s *PGStore) newID() (string, error) {
	if s.ids == nil {
		return "", errors.New("хранилище событий: нет генератора ID")
	}
	u, err := s.ids.New()
	if err != nil {
		return "", fmt.Errorf("хранилище событий: ID: %w", err)
	}
	return u.String(), nil
}
