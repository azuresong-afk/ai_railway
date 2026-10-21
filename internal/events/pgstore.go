package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Хранение событий в PostgreSQL (миграция 0008_events, решение Р9): секции
// по суткам UTC, приём идемпотентен по ID, содержимое full шифруется
// производным ключом суток (ЗИ.1, ADR-0007 п. 8) с AAD места хранения (Р4).

const (
	// pgTimeout — предел на операцию, если у контекста нет своего срока.
	pgTimeout = 10 * time.Second
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
	// ContentKeyPurpose — назначение производного ключа содержимого событий.
	ContentKeyPurpose = "event-content"
	// PartitionsBack и PartitionsAhead — окно секций, которое держит сервер:
	// приём событий за MaxEventAge назад и на неделю вперёд (Р9).
	PartitionsBack  = 7
	PartitionsAhead = 7
)

// Место хранения шифротекста содержимого — для AAD (Р4).
const (
	contentTable  = "event_content"
	contentColumn = "sealed"
)

// Ошибки хранилища. Текст ошибок СУБД наружу и в журнал не передаётся: в
// сообщении PostgreSQL могли бы оказаться значения полей.
var (
	ErrNotFound = errors.New("событие не найдено")
	// ErrNoPartition — нет секции для времени события: фоновое задание
	// секций не успело или не сработало. Пакет стоит повторить позже.
	ErrNoPartition = errors.New("хранилище событий: нет секции для времени события")
	// ErrRejectedByDB — СУБД отвергла данные (ограничение или формат): повтор
	// того же пакета не поможет.
	ErrRejectedByDB = errors.New("хранилище событий: СУБД отвергла данные пакета")
)

// dbError заменяет ошибку СУБД кодом SQLSTATE и именем ограничения.
func dbError(what string, err error) error {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return fmt.Errorf("хранилище событий: %s: %w", what, err)
	}
	switch {
	case pe.Code == "23514" && strings.HasPrefix(pe.Message, "no partition of relation"):
		return ErrNoPartition
	case strings.HasPrefix(pe.Code, "22") || strings.HasPrefix(pe.Code, "23"):
		return fmt.Errorf("%w: %s: SQLSTATE %s %s", ErrRejectedByDB, what, pe.Code, pe.ConstraintName)
	}
	return fmt.Errorf("хранилище событий: %s: SQLSTATE %s", what, pe.Code)
}

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Ingest — пакет к записи: события уже проверены Check.
type Ingest struct {
	GatewayID string
	// ReceivedAt — время приёма по часам приложения: отметка счётчиков
	// шлюза и время приёма в Memory. PGStore пишет received_at событий по
	// часам СУБД (Н22 ревью 2.r3a).
	ReceivedAt time.Time
	Events     []Event
	Stats      *SenderStats
}

// InsertResult — итог записи пакета.
type InsertResult struct {
	Accepted   int
	Duplicates int
	// Truncated — принятые события, содержимое которых обрезано под предел
	// хранения (FitContent).
	Truncated int
	// Rejected — индексы событий Ingest.Events, которые СУБД отвергла при
	// поштучной записи (RejectStorage); остальные события записаны.
	Rejected []int
}

// Store — хранилище событий для приёма. Рабочая реализация — PGStore, для
// тестов без PostgreSQL — Memory.
type Store interface {
	// Insert записывает события одной транзакцией. Событие с уже
	// записанным ID пропускается (duplicates); содержимое пишется только для
	// новых событий. Если СУБД отвергла данные, пакет записывается заново по
	// одному событию, и отказ получают только отвергнутые (В10 ревью 2.r3a).
	Insert(ctx context.Context, in Ingest) (InsertResult, error)
}

// PGStore — Store на PostgreSQL.
type PGStore struct {
	db PGDB
	// rdb — пул чтения событий консолью (список, карточка, содержимое,
	// выгрузка, агрегаты): отдельно от приёма событий, входа и аудита, чтобы
	// медленные выборки не занимали их соединения (В11 ревью 2.r3a). По
	// умолчанию — тот же db.
	rdb   PGDB
	box   *keyring.Box
	audit *audit.Log
	orgID string
	// ids — UUIDv7 сохранённых фильтров (задача 2.16); nil — сохранение
	// фильтров недоступно.
	ids *ids.Generator
}

// PGOption — необязательная настройка PGStore.
type PGOption func(*PGStore)

// WithRandom задаёт источник случайности криптопрофиля для ID новых строк
// (сохранённые фильтры).
func WithRandom(r aisecCrypto.Random) PGOption {
	return func(s *PGStore) { s.ids = ids.NewGenerator(r) }
}

// WithReadDB задаёт отдельный пул для чтения событий консолью.
func WithReadDB(db PGDB) PGOption {
	return func(s *PGStore) {
		if db != nil {
			s.rdb = db
		}
	}
}

// NewPGStore создаёт хранилище. box нужен для содержимого full, журнал —
// для записи об удалении секций и изменении сроков хранения.
func NewPGStore(db PGDB, box *keyring.Box, a *audit.Log, orgID string, opts ...PGOption) (*PGStore, error) {
	if db == nil || box == nil || a == nil {
		return nil, errors.New("хранилище событий: нет БД, ключа данных или журнала аудита")
	}
	if orgID == "" {
		orgID = audit.DefaultOrgID
	}
	s := &PGStore{db: db, rdb: db, box: box, audit: a, orgID: orgID}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

func (s *PGStore) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("хранилище событий: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после фиксации безвреден, ошибку скрывает исходная
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("хранилище событий: фиксация: %w", err)
	}
	return nil
}

// PartitionTime — ключ секции события: время из его UUIDv7. Повтор
// события с тем же ID всегда попадает в ту же строку.
func PartitionTime(id string) (time.Time, error) {
	u, err := ids.Parse(id)
	if err != nil {
		return time.Time{}, err
	}
	return u.Time(), nil
}

// insertEvent: received_at ставят часы СУБД (clock_timestamp), те же, по
// которым сдвигается отметка агрегатов: при расхождении часов хостов
// приложения и СУБД события не выпадают из агрегатов (Н22 ревью 2.r3a).
const insertEvent = `INSERT INTO events (id, ts, event_time, org_id, gateway_id, received_at, type, app, env,
	user_alias, provider, model, source, policy_mode, action, rule, severity, storage, threats, stream,
	non_text_unchecked, has_content, details)
	VALUES ($1, $2, $3, $4, $5, clock_timestamp(), $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
	ON CONFLICT (id, ts) DO NOTHING`

const insertContent = `INSERT INTO event_content (event_id, ts, org_id, storage, request, response, key_id, key_day, alg, sealed)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

// Insert — см. Store.
func (s *PGStore) Insert(ctx context.Context, in Ingest) (InsertResult, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows := make([]eventRow, 0, len(in.Events))
	defer func() {
		for _, r := range rows {
			clear(r.plain)
		}
	}()
	for i := range in.Events {
		r, err := newEventRow(&in.Events[i])
		if err != nil {
			return InsertResult{}, err
		}
		rows = append(rows, r)
	}
	res, err := s.insertRows(ctx, in, rows, false)
	if errors.Is(err, ErrRejectedByDB) {
		// Одно событие не должно губить пакет: повтор по одному событию в
		// своей точке сохранения, отказ — только отвергнутым.
		res, err = s.insertRows(ctx, in, rows, true)
	}
	if err != nil {
		return InsertResult{}, err
	}
	return res, nil
}

// insertRows записывает подготовленные события одной транзакцией: пакетом
// запросов или, при oneByOne, по одному событию в точке сохранения
// (SAVEPOINT), пропуская те, что СУБД отвергла.
func (s *PGStore) insertRows(ctx context.Context, in Ingest, rows []eventRow, oneByOne bool) (InsertResult, error) {
	var res InsertResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		res = InsertResult{}
		var inserted []bool
		var err error
		if oneByOne {
			inserted, res.Rejected, err = s.insertEach(ctx, tx, in, rows)
		} else {
			inserted, err = s.insertBatch(ctx, tx, in, rows)
		}
		if err != nil {
			return err
		}
		for i, r := range rows {
			if inserted[i] {
				res.Accepted++
				if r.truncated {
					res.Truncated++
				}
			}
		}
		res.Duplicates = len(rows) - res.Accepted - len(res.Rejected)
		return s.insertStats(ctx, tx, in)
	})
	return res, err
}

func (s *PGStore) eventArgs(in Ingest, r eventRow) []any {
	e := r.ev
	return []any{e.ID, r.ts, e.Time.UTC(), s.orgID, in.GatewayID, e.Type,
		null(e.App), null(e.Env), null(e.User), null(e.Provider), null(e.Model), null(e.Source),
		null(e.PolicyMode), null(r.action), null(r.rule), null(r.severity), storageOf(e), threatsOf(e),
		e.Stream, e.NonTextUnchecked, e.Content != nil, r.details}
}

// insertBatch пишет события и содержимое двумя пакетами запросов.
func (s *PGStore) insertBatch(ctx context.Context, tx pgx.Tx, in Ingest, rows []eventRow) ([]bool, error) {
	b := &pgx.Batch{}
	for _, r := range rows {
		b.Queue(insertEvent, s.eventArgs(in, r)...)
	}
	inserted := make([]bool, len(rows))
	if err := execBatch(ctx, tx, b, func(i int, tag pgconn.CommandTag) { inserted[i] = tag.RowsAffected() == 1 }); err != nil {
		return nil, dbError("запись событий", err)
	}
	cb := &pgx.Batch{}
	for i, r := range rows {
		if !inserted[i] || r.ev.Content == nil {
			continue
		}
		args, err := s.contentArgs(ctx, r)
		if err != nil {
			return nil, err
		}
		cb.Queue(insertContent, args...)
	}
	if cb.Len() > 0 {
		if err := execBatch(ctx, tx, cb, nil); err != nil {
			return nil, dbError("запись содержимого", err)
		}
	}
	return inserted, nil
}

// insertEach пишет события по одному, каждое — в своей точке сохранения.
// Событие, которое СУБД отвергла (ErrRejectedByDB), откатывается и попадает
// в rejected; любая другая ошибка прерывает весь пакет.
func (s *PGStore) insertEach(ctx context.Context, tx pgx.Tx, in Ingest, rows []eventRow) (inserted []bool, rejected []int, err error) {
	inserted = make([]bool, len(rows))
	for i, r := range rows {
		ok, err := s.insertOne(ctx, tx, in, r)
		switch {
		case errors.Is(err, ErrRejectedByDB):
			rejected = append(rejected, i)
		case err != nil:
			return nil, nil, err
		default:
			inserted[i] = ok
		}
	}
	return inserted, rejected, nil
}

func (s *PGStore) insertOne(ctx context.Context, tx pgx.Tx, in Ingest, r eventRow) (bool, error) {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("хранилище событий: точка сохранения: %w", err)
	}
	ok, err := func() (bool, error) {
		tag, err := sp.Exec(ctx, insertEvent, s.eventArgs(in, r)...)
		if err != nil {
			return false, dbError("запись события", err)
		}
		if tag.RowsAffected() != 1 || r.ev.Content == nil {
			return tag.RowsAffected() == 1, nil
		}
		args, err := s.contentArgs(ctx, r)
		if err != nil {
			return false, err
		}
		if _, err := sp.Exec(ctx, insertContent, args...); err != nil {
			return false, dbError("запись содержимого", err)
		}
		return true, nil
	}()
	if err != nil {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		if rerr := sp.Rollback(rctx); rerr != nil {
			return false, errors.Join(err, fmt.Errorf("хранилище событий: откат точки сохранения: %w", rerr))
		}
		return false, err
	}
	if err := sp.Commit(ctx); err != nil {
		return false, fmt.Errorf("хранилище событий: точка сохранения: %w", err)
	}
	return ok, nil
}

// insertStats обновляет счётчики отправителя шлюза.
func (s *PGStore) insertStats(ctx context.Context, tx pgx.Tx, in Ingest) error {
	st := in.Stats
	if st == nil {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gateway_event_stats (gateway_id, started_at, dropped, rejected, reported_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (gateway_id) DO UPDATE SET
			dropped = CASE WHEN gateway_event_stats.started_at = EXCLUDED.started_at
				THEN GREATEST(gateway_event_stats.dropped, EXCLUDED.dropped) ELSE EXCLUDED.dropped END,
			rejected = CASE WHEN gateway_event_stats.started_at = EXCLUDED.started_at
				THEN GREATEST(gateway_event_stats.rejected, EXCLUDED.rejected) ELSE EXCLUDED.rejected END,
			started_at = EXCLUDED.started_at, reported_at = EXCLUDED.reported_at`,
		in.GatewayID, st.StartedAt.UTC(), clampInt64(st.Dropped), clampInt64(st.Rejected), in.ReceivedAt.UTC()); err != nil {
		return dbError("счётчики шлюза", err)
	}
	return nil
}

// execBatch выполняет пакет запросов и передаёт итог каждого в fn.
func execBatch(ctx context.Context, tx pgx.Tx, b *pgx.Batch, fn func(int, pgconn.CommandTag)) (err error) {
	br := tx.SendBatch(ctx, b)
	defer func() { err = errors.Join(err, br.Close()) }()
	for i := range b.Len() {
		tag, err := br.Exec()
		if err != nil {
			return err
		}
		if fn != nil {
			fn(i, tag)
		}
	}
	return nil
}

// contentArgs — аргументы insertContent: masked — открытым текстом (маска
// уже наложена шлюзом), full — шифротекст производным ключом суток.
func (s *PGStore) contentArgs(ctx context.Context, r eventRow) ([]any, error) {
	e := r.ev
	if e.Storage != StorageFull {
		return []any{e.ID, r.ts, s.orgID, StorageMasked, null(e.Content.Request), null(e.Content.Response),
			nil, nil, nil, nil}, nil
	}
	d, err := s.box.Derive(ContentKeyPurpose, r.ts)
	if err != nil {
		return nil, fmt.Errorf("хранилище событий: ключ содержимого: %w", err)
	}
	sealed, err := d.Seal(ctx, r.plain, contentTable, contentColumn, e.ID)
	if err != nil {
		return nil, fmt.Errorf("хранилище событий: шифрование содержимого: %w", err)
	}
	day := r.ts.UTC().Format(time.DateOnly)
	return []any{e.ID, r.ts, s.orgID, StorageFull, nil, nil, d.KeyID(), day, d.Alg(), sealed}, nil
}

// StoredContent — содержимое события после чтения.
type StoredContent struct {
	Storage string
	Content Content
}

// Content читает и при необходимости расшифровывает содержимое события
// (для задачи 2.16: доступ — с разрешением events.content.read и записью в
// аудит, которые проверяет вызывающий).
func (s *PGStore) Content(ctx context.Context, id string) (StoredContent, error) {
	ts, err := PartitionTime(id)
	if err != nil {
		return StoredContent{}, ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var (
		out        StoredContent
		req, resp  *string
		keyID, alg *string
		keyDay     *time.Time
		sealed     []byte
	)
	err = s.rdb.QueryRow(ctx, `SELECT storage, request, response, key_id::text, key_day, alg, sealed
		FROM event_content WHERE event_id = $1 AND ts = $2 AND org_id = $3`, id, ts, s.orgID).
		Scan(&out.Storage, &req, &resp, &keyID, &keyDay, &alg, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredContent{}, ErrNotFound
	}
	if err != nil {
		return StoredContent{}, fmt.Errorf("хранилище событий: чтение содержимого: %w", err)
	}
	if out.Storage != StorageFull {
		out.Content = Content{Request: deref(req), Response: deref(resp)}
		return out, nil
	}
	if keyID == nil || keyDay == nil {
		return StoredContent{}, errors.New("хранилище событий: у шифротекста нет ключа")
	}
	plain, err := s.box.OpenDerived(*keyID, ContentKeyPurpose, *keyDay, sealed, contentTable, contentColumn, id)
	if err != nil {
		return StoredContent{}, fmt.Errorf("хранилище событий: расшифрование содержимого: %w", err)
	}
	defer clear(plain)
	if err := json.Unmarshal(plain, &out.Content); err != nil {
		return StoredContent{}, errors.New("хранилище событий: расшифрованное содержимое — не JSON")
	}
	return out, nil
}

// EnsurePartitions создаёт недостающие секции на PartitionsBack суток назад
// и PartitionsAhead вперёд. Возвращает число созданных секций.
func (s *PGStore) EnsurePartitions(ctx context.Context) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var n int
	if err := s.db.QueryRow(ctx, "SELECT events_ensure_partitions($1, $2)", PartitionsBack, PartitionsAhead).Scan(&n); err != nil {
		return 0, fmt.Errorf("хранилище событий: создание секций: %w", err)
	}
	return n, nil
}

// DropExpired удаляет секции старше сроков хранения из event_settings и
// той же транзакцией пишет запись events.retention в аудит (РСБ).
func (s *PGStore) DropExpired(ctx context.Context) ([]string, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var dropped []string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT events_drop_expired()")
		if err != nil {
			return err
		}
		dropped, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		if len(dropped) == 0 {
			return nil
		}
		return s.audit.RecordTx(ctx, tx, audit.Entry{
			OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorSystem, ID: "aisec-server", Name: "Сервер управления"},
			Action: "events.retention", Object: audit.Object{Type: "events"}, Result: audit.ResultSuccess,
			Details: map[string]any{"partitions": dropped},
		})
	})
	if err != nil {
		return nil, fmt.Errorf("хранилище событий: удаление по сроку хранения: %w", err)
	}
	return dropped, nil
}

// eventRow — событие, подготовленное к записи.
type eventRow struct {
	ev                     *Event
	ts                     time.Time
	action, rule, severity string
	details                []byte
	// plain — открытый текст содержимого full (MarshalContent), truncated —
	// содержимое обрезано под предел хранения.
	plain     []byte
	truncated bool
}

func newEventRow(e *Event) (eventRow, error) {
	ts, err := PartitionTime(e.ID)
	if err != nil {
		return eventRow{}, fmt.Errorf("хранилище событий: ID: %w", err)
	}
	r := eventRow{ev: e, ts: ts}
	if e.Storage == StorageFull && e.Content != nil {
		c, truncated := FitContent(*e.Content, MaxSealedPlain)
		if r.plain, err = MarshalContent(c); err != nil {
			return eventRow{}, err
		}
		r.truncated = truncated
	}
	det := e.Details()
	det.ContentTruncated = r.truncated
	if r.details, err = json.Marshal(det); err != nil {
		return eventRow{}, err
	}
	if dd := e.Decision; dd != nil {
		r.action, r.rule, r.severity = dd.Action, dd.Rule, dd.Severity
	}
	return r, nil
}

func storageOf(e *Event) string {
	if e.Storage == "" {
		return StorageNone
	}
	return e.Storage
}

func threatsOf(e *Event) []string {
	if e.Threats == nil {
		return []string{}
	}
	return e.Threats
}

// null — пустая строка как NULL.
func null(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func clampInt64(v uint64) int64 {
	if v > 1<<62 {
		return 1 << 62
	}
	return int64(v)
}
